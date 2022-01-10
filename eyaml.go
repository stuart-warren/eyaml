package eyaml

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"regexp"

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
	var data []byte
	_, err := reader.Read(data)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}

func (e EyamlPkcs7) newDecryptReader(source io.Reader) io.Reader {
	return &eyamlPkcs7DecryptReader{
		source: source,
		err:    nil,
		pkcs7:  e,
	}
}

type eyamlPkcs7DecryptReader struct {
	source io.Reader
	err    error
	count  int
	pkcs7  EyamlPkcs7
}

func (r *eyamlPkcs7DecryptReader) Read(data []byte) (int, error) {

	n, err := r.source.Read(data)
	if err != nil {
		return n, err
	}
	//buf := make([]byte, n)

	re := regexp.MustCompile(PKCS7ENCPattern)
	foundList := re.FindAllSubmatch(data, -1)
	fmt.Printf("len: %d\n", len(foundList))
	for _, found := range foundList {
		decoded, err := base64.StdEncoding.DecodeString(string(found[1]))
		if err != nil {
			return 0, fmt.Errorf("could not base64 decode string: %w", err)
		}
		decrypted, err := r.pkcs7.DecryptBytes(decoded)
		if err != nil {
			return 0, fmt.Errorf("failed to decrypt: %w", err)
		}
		data = bytes.Replace(data, found[0], decrypted, -1)
	}
	return r.count, nil
}
