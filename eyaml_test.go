package eyaml_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stuart-warren/eyaml"
)

const (
	testData = "MIIBeQYJKoZIhvcNAQcDoIIBajCCAWYCAQAxggEhMIIBHQIBADAFMAACAQEwDQYJKoZIhvcNAQEBBQAEggEAR9V0CrIHHnAMSBZm9/jBhjFLpqEyntR4z92ClSjC63uldYeFm5v3zdom3NisE7kTNTUff3TV0UmTNFsgwMHNvW0YWN8zGYBLkmeSj3C47WLCwAp1AyQeS7UFbvNLZFY5uM9UNgDhWP6OTQT1RTefwzSZ5cLTtk68jrnVJCSbSF725S6DdzA5uwC1OvNRf8YvOeNUcsSQQMrcn1JLfQzsrz3X3HIfFK0FQUf6n//mKrtG4KLLm1r04Ds8vkvWDS6YZ5WmKDz6nU1zedGuJymWEmhqJsNJd3GuoZk/3MfINcECplSmPOEavoR7nvKSQ1R2HPmdqe9t80tgvDSCi5VeTzA8BgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBC8ZdN8KqWvPGs2SmCw5miCgBB3dTNhWREgeg5bh8fk3Pa/"
	testFile = `
---
hello-world: ENC[PKCS7,MIIBeQYJKoZIhvcNAQcDoIIBajCCAWYCAQAxggEhMIIBHQIBADAFMAACAQEwDQYJKoZIhvcNAQEBBQAEggEAR9V0CrIHHnAMSBZm9/jBhjFLpqEyntR4z92ClSjC63uldYeFm5v3zdom3NisE7kTNTUff3TV0UmTNFsgwMHNvW0YWN8zGYBLkmeSj3C47WLCwAp1AyQeS7UFbvNLZFY5uM9UNgDhWP6OTQT1RTefwzSZ5cLTtk68jrnVJCSbSF725S6DdzA5uwC1OvNRf8YvOeNUcsSQQMrcn1JLfQzsrz3X3HIfFK0FQUf6n//mKrtG4KLLm1r04Ds8vkvWDS6YZ5WmKDz6nU1zedGuJymWEmhqJsNJd3GuoZk/3MfINcECplSmPOEavoR7nvKSQ1R2HPmdqe9t80tgvDSCi5VeTzA8BgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBC8ZdN8KqWvPGs2SmCw5miCgBB3dTNhWREgeg5bh8fk3Pa/]
`
	pubCert = `
-----BEGIN CERTIFICATE-----
MIIC2TCCAcGgAwIBAgIBATANBgkqhkiG9w0BAQsFADAAMCAXDTIyMDEwOTA0MDM0
MloYDzIwNzExMjI4MDQwMzQyWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA1/TbECQzT4OSFr45jSXLs8zTJqW6ngASghiLmULo8eaVmxII8+h2lZgx
X95y1GjGmAe9Q9DuLL+XbytbNZL/astfspJy/osXPDZRX4ou6W8hvCRl3+Sii+07
DRR+7Y6KgCl4E8PE7cYAqL2sqA90urAdYaTpw/JhfizfkCU24mGqUabli4Fu/e2q
KPR315+FRfDz5EROORToUNtWIqIZy4Z081UsUmM4QBEdhjWfETpqt0/kz99fkl+C
/768P77rQV+Uor+QygE47UIqsHu9+q2L+P5MQ3+Xv4cv+XrgCezSumF3v4kJZzOo
9W53bNfkyNVhf4xRcUQ98fnya/lQqQIDAQABo1wwWjAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSGKyMPWYYFBYzkUGSTzbXJZgvRWDAoBgNVHSMEITAfgBSGKyMP
WYYFBYzkUGSTzbXJZgvRWKEEpAIwAIIBATANBgkqhkiG9w0BAQsFAAOCAQEAWY3a
aWQSWvuhy2AkhhH3meGLorgyGa7YCYfxVeLtpDqE6tsMpkt4HKjAIU2vy8j67CLR
Y0HC7QlrSEY5Y6cRX+lixm9AuTjMueWhLBxOLm2+1oozhSMCzcFM3DvfHHMGaNC5
H8bnsRgnSOwXSJi+2nH9l8QUk61s8dCQ23NMtzsvdxjiq3xKECtrn1CjQIA9Pdsr
zep9vDx/8VP4yW0aNOpsNYEVupiWi3DTEgg9UJ095a4e+BxDpZuxEJYQydDze5M2
LmCWAibQjHU7lUTgUeO4vd5Vc6VvTXa06Gun+wgopd+N661TtmTcEexseBVV2bPP
7WLKnJH5XW7L57JJLg==
-----END CERTIFICATE-----`
	privKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1/TbECQzT4OSFr45jSXLs8zTJqW6ngASghiLmULo8eaVmxII
8+h2lZgxX95y1GjGmAe9Q9DuLL+XbytbNZL/astfspJy/osXPDZRX4ou6W8hvCRl
3+Sii+07DRR+7Y6KgCl4E8PE7cYAqL2sqA90urAdYaTpw/JhfizfkCU24mGqUabl
i4Fu/e2qKPR315+FRfDz5EROORToUNtWIqIZy4Z081UsUmM4QBEdhjWfETpqt0/k
z99fkl+C/768P77rQV+Uor+QygE47UIqsHu9+q2L+P5MQ3+Xv4cv+XrgCezSumF3
v4kJZzOo9W53bNfkyNVhf4xRcUQ98fnya/lQqQIDAQABAoIBAQCuxfRQUOvRyyp9
C4BqMg90uSyd13x7iJVyAklgRN1fgHzNXkAunZDzKpOzAcWvEAjBW2oaK0nGn1wA
VXdgmVHq7SLK02kLhifMzCz5BE1JEG6d5FsqYtAGLH0g7dh3i2edp3INlN+YiylX
ZwIHlVKkEAoHTz79HPk38zsPXn7XoDOMbaSCp2YWGJThSEqsDeueleNrenjq7HdE
oUZ7OlrmazMkjocQis14rKN863iHgTS0qYsbjUdVQbUUr+9Oc0w1zgQ4nJ6IqA9N
2axlss1rM3l2n8gl+R9dmTunCVz5oRK4gqqNeDod4xJwr++MBUcEHaVVRvo6q7QX
obNwbdztAoGBAPvLx2onoBP+3MJHlBAslKH0C/lNa7Z7ap3SdbqhDABmfhr2h6+e
qNUWwz+ZXK0ZkLDp4NoPUKeRxgQUhIRI7OqeszbvOCjI38VuzWCYmJquGXmqJwyj
J068NIYoRYzU57lOI1uajoX6qGx7ciQbUPDQHOrGXEm9UmzoIDNpPcOHAoGBANuP
5GQXLj66q1u4ZwXCFQBYSE+fh5rMjvAA5F5urSVRSovPKeFj5C0ibjWbpi0ry/l+
03EmGTIORfRoLefoXc//NpxFUXpAqmg73jdqMyOKWuRX6yUhGVMt4ZzWS6XuTfwS
9SZy23/Yzyylc9iqB3s5/Owwi0U4WCqiO7s52LZPAoGAKwEFwOqdm2ym1YOWFSEY
DYT52o1PfS4c6nF8a/B/dT4MAZzjVao6WZJ2rFEMFABOxvhaz8NX2ha6hA3hCBrQ
Y83Q++vlYonUNgsThpDpV1muvinCW5Ut7HOWYOdV4ZSnMu3Wehmuh9FknIqE1wfX
ThmtJqfUMT/laPZIMZ+izdcCgYACl9J0tClhqEa50JW25bHlzSUde57YXy4Y+4m2
68uzsyAUQqAV/14EgnGWxH3T7r579dl9bpvBkZWV610PbhkdicAVXGQ382ePz5Uy
RljQRKQKKlemmpt39gTCG23NSeE15utqRtT8z4yy1Eln96oa9HZeO7yJVr8D0eKu
tWIv1QKBgB+YQLZwKNcMyJT9vAB2Po083lmKr91NXsi52SfF1QjiYp8j9+22ERI0
AZ1xSNCP9jxmqsxqkXXH1DKSDhq4ELwyFcIJG5GTCOsFHCLqElx6KhzfiBLSivkY
CqsnwKfefJCZ5HRvnixl4UKGwe71rMudZdZmjnsCmXefM4qb4kbx
-----END RSA PRIVATE KEY-----`
)

var (
	testPkcs7, _ = eyaml.NewEyamlPkcs7([]byte(privKey), []byte(pubCert))
)

func TestPKCS7SimpleDecrypt(t *testing.T) {

	data, err := base64.StdEncoding.DecodeString(testData)
	if err != nil {
		t.Errorf("could not b64 decode %v", err)
	}
	out, err := testPkcs7.DecryptBytes(data)
	if err != nil {
		t.Errorf("failed to decrypt: %v", err.Error())
	}
	fmt.Printf("out = %q\n", out)
}

func TestPKCS7RegexDecrypt(t *testing.T) {

	re := regexp.MustCompile(eyaml.PKCS7ENCPattern)
	foundList := re.FindAllSubmatch([]byte(testFile), -1)
	for _, found := range foundList {
		fmt.Printf("%s -> %s\n", found[0], found[1])
		d := string(found[1])
		data, err := base64.StdEncoding.DecodeString(d)
		if err != nil {
			t.Errorf("could not b64 decode %v", err)
		}
		out, err := testPkcs7.DecryptBytes(data)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err.Error())
		}
		fmt.Printf("out = %q\n", out)
	}
}

// func TestPKCS7ReaderDecrypt(t *testing.T) {
// 	r := strings.NewReader(testFile)
// 	data, err := testPkcs7.Decrypt(r)
// 	if err != nil {
// 		t.Errorf("faild to decrypt: %v", err)
// 	}
// 	fmt.Printf("out = %s", data)
// }

func TestReader(t *testing.T) {
	r := strings.NewReader(testFile)
	var data []byte
	_, err := r.Read(data)
	if err != nil {
		fmt.Print(err)
	}
}

func TestStream(t *testing.T) {
	data := []byte("nteuhnt oheuo eunhtu ENC[PKCS7,MIIBeQYEKoZIhv] uoeeuon etuhu")

	var buf bytes.Buffer
	var markerStartIndex = -1
	var dataStartIndex = -1
	for i, b := range data {
		switch true {
		case b == 'E' && markerStartIndex == -1:
			markerStartIndex = i
		case b == 'N' && markerStartIndex >= 0 && markerStartIndex == i-1:
		case b == 'C' && markerStartIndex >= 0 && markerStartIndex == i-2:
		case b == '[' && markerStartIndex >= 0 && markerStartIndex == i-3:
		case b == 'P' && markerStartIndex >= 0 && markerStartIndex == i-4:
		case b == 'K' && markerStartIndex >= 0 && markerStartIndex == i-5:
		case b == 'C' && markerStartIndex >= 0 && markerStartIndex == i-6:
		case b == 'S' && markerStartIndex >= 0 && markerStartIndex == i-7:
		case b == '7' && markerStartIndex >= 0 && markerStartIndex == i-8:
		case b == ',' && markerStartIndex >= 0 && markerStartIndex == i-9:
		case b == ']' && markerStartIndex >= 0: // must be checked for before data
			markerStartIndex = -1
			dataStartIndex = -1
			fmt.Print(buf.Len()) // print out decryption instead
			buf.Reset()
		case markerStartIndex >= 0 && markerStartIndex == i-10:
			dataStartIndex = i
			buf.WriteByte(b)
			fmt.Print(string('X')) // remove
		case dataStartIndex >= 0:
			buf.WriteByte(b)
			fmt.Print(string('X')) // remove
		default:
			fmt.Print(string(b))
		}
	}
	fmt.Print("\n")
}
