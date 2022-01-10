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

const (
	PKCS7ENCPattern = `ENC\[PKCS7,([0-9A-z/=\+\s]+)\]`
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
	data := make([]byte, 1024)
	for {
		_, err := reader.Read(data)
		if err == io.EOF {
			break
		}
		if err != nil {
			return []byte{}, err
		}
	}
	return bytes.Trim(data, "\x00"), nil
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
	_, err := r.source.Read(buf)
	if err != nil {
		return 0, err
	}

	for i, b := range buf {
		switch true {
		case b == 'E' && r.markerStartIndex == -1:
			r.markerStartIndex = i
		case b == 'N' && r.markerStartIndex >= 0 && r.markerStartIndex == i-1:
		case b == 'C' && r.markerStartIndex >= 0 && r.markerStartIndex == i-2:
		case b == '[' && r.markerStartIndex >= 0 && r.markerStartIndex == i-3:
		case b == 'P' && r.markerStartIndex >= 0 && r.markerStartIndex == i-4:
		case b == 'K' && r.markerStartIndex >= 0 && r.markerStartIndex == i-5:
		case b == 'C' && r.markerStartIndex >= 0 && r.markerStartIndex == i-6:
		case b == 'S' && r.markerStartIndex >= 0 && r.markerStartIndex == i-7:
		case b == '7' && r.markerStartIndex >= 0 && r.markerStartIndex == i-8:
		case b == ',' && r.markerStartIndex >= 0 && r.markerStartIndex == i-9:
		case b == ']' && r.markerStartIndex >= 0: // must be checked for, before encrypted payload
			r.markerStartIndex = -1
			r.payloadStartIndex = -1
			decoded, err := base64.StdEncoding.DecodeString(r.payloadBuf.String())
			if err != nil {
				return 0, fmt.Errorf("could not base64 decode string: %w", err)
			}
			decrypted, err := r.pkcs7.DecryptBytes(decoded)
			if err != nil {
				return 0, fmt.Errorf("could not decrypt string: %w", err)
			}
			// TODO: handle whitespace indents here
			data = append(data, decrypted...)
			r.payloadBuf.Reset()
		case r.markerStartIndex >= 0 && r.markerStartIndex == i-10:
			r.payloadStartIndex = i
			r.payloadBuf.WriteByte(b)
		case r.payloadStartIndex >= 0:
			r.payloadBuf.WriteByte(b)
		default:
			data = append(data, b)
		}
	}

	count = copy(buf, data[:len(buf)])
	r.pointer += count
	return count, nil
}
