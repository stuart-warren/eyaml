package eyaml

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"

	"go.mozilla.org/pkcs7"
)

type EyamlPkcs7 struct {
	PrivateKey crypto.PrivateKey
	PublicCert *x509.Certificate
}

func NewEyamlPkcs7(pemPrivateKey []byte, pemPublicCert []byte) (EyamlPkcs7, error) {
	e := EyamlPkcs7{}
	block, _ := pem.Decode(pemPublicCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return e, fmt.Errorf("failed to parse certificate: %w", err)
	}
	e.PublicCert = cert
	block2, _ := pem.Decode(pemPrivateKey)
	key, err := x509.ParsePKCS1PrivateKey(block2.Bytes)
	if err != nil {
		return e, fmt.Errorf("failed to parse key: %w", err)
	}
	e.PrivateKey = key
	return e, nil
}

func (e EyamlPkcs7) DecryptBytes(data []byte) ([]byte, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return []byte{}, fmt.Errorf("could not parse data %w", err)
	}
	out, err := p7.Decrypt(e.PublicCert, e.PrivateKey)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decrypt: %w", err)
	}
	return out, nil
}

func (e EyamlPkcs7) Decrypt(r io.Reader) ([]byte, error) {
	reader := e.newDecryptReader(r)
	data, err := io.ReadAll(reader)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}

type eyamlPkcs7DecryptReader struct {
	source            io.Reader
	err               error
	pointer           int
	pkcs7             EyamlPkcs7
	payloadBuf        *bytes.Buffer
	markerStartIndex  int
	payloadStartIndex int
}

func (e EyamlPkcs7) newDecryptReader(source io.Reader) io.Reader {
	return &eyamlPkcs7DecryptReader{
		source:            source,
		err:               nil,
		pkcs7:             e,
		payloadBuf:        bytes.NewBuffer(nil),
		markerStartIndex:  -1,
		payloadStartIndex: -1,
	}
}

func (r *eyamlPkcs7DecryptReader) Read(buf []byte) (int, error) {

	count := 0
	data := []byte{}
	source := make([]byte, len(buf))
	_, err := r.source.Read(source)
	if err != nil {
		return 0, err
	}

	for _, b := range source {
		switch true {
		case b == 'E' && r.markerStartIndex == -1:
			r.markerStartIndex = r.pointer
		case b == 'N' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-1:
		case b == 'C' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-2:
		case b == '[' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-3:
		case b == 'P' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-4:
		case b == 'K' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-5:
		case b == 'C' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-6:
		case b == 'S' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-7:
		case b == '7' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-8:
		case b == ',' && r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-9: // payload marker complete, next char is payload itself
		case b == ']' && r.markerStartIndex >= 0 && r.payloadStartIndex >= 0: // end of payload marker. must be checked for, before encrypted payload
			r.markerStartIndex = -1
			r.payloadStartIndex = -1
			decoded, err := base64.StdEncoding.DecodeString(r.payloadBuf.String())
			if err != nil {
				return 0, fmt.Errorf("could not base64 decode string: %w", err)
			}
			r.payloadBuf.Reset()
			decrypted, err := r.pkcs7.DecryptBytes(decoded)
			if err != nil {
				return 0, fmt.Errorf("could not decrypt string: %w", err)
			}
			// TODO: handle whitespace indents here
			data = append(data, decrypted...)
		case r.markerStartIndex >= 0 && r.markerStartIndex == r.pointer-10: // first char of encrypted payload
			r.payloadStartIndex = r.pointer
			r.payloadBuf.WriteByte(b)
		case r.markerStartIndex >= 0 && r.payloadStartIndex < 0 && (r.pointer)-(r.markerStartIndex) <= 10: // any unexpected char after beginning of payload marker, but before complete
			r.payloadStartIndex = -1
			data = append(data, b)
		case b == '\n' && r.payloadStartIndex >= 0: // newline within encrypted payload
			fmt.Print("nl") //FIXME
		case b == '\t' && r.payloadStartIndex >= 0: // tab char within encrypted payload
			fmt.Print("tb") //FIXME
		case b == ' ' && r.payloadStartIndex >= 0: // space char within encrypted payload
			fmt.Print("sp") //FIXME
		case r.payloadStartIndex >= 0: // any other char within encrypted payload
			r.payloadBuf.WriteByte(b)
		default: // any other char
			data = append(data, b)
		}
		r.pointer++
	}

	count = copy(buf, bytes.Trim(data, "\x00"))
	r.pointer += count
	return count, nil
}
