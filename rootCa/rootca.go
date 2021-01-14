package rootCa

import (
	"crypto/x509"
	"io/ioutil"

	"github.com/signal-golang/textsecure/utils"

	log "github.com/sirupsen/logrus"
)

// rootPEM is the PEM formatted signing certificate of the Open Whisper Systems
// server to be used by the TLS client to verify its authenticity instead of
// relying on the system-wide set of root certificates.
var rootPEM = `
-----BEGIN CERTIFICATE-----
MIID4zCCAsugAwIBAgICEBgwDQYJKoZIhvcNAQELBQAwgY0xCzAJBgNVBAYTAlVT
MRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0w
GwYDVQQKDBRPcGVuIFdoaXNwZXIgU3lzdGVtczEdMBsGA1UECwwUT3BlbiBXaGlz
cGVyIFN5c3RlbXMxEzARBgNVBAMMClRleHRTZWN1cmUwHhcNMTkwMjE1MTczODE3
WhcNMjkwMzEyMTgyMDIwWjCBkDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExHTAbBgNVBAoMFE9wZW4gV2hpc3BlciBTeXN0ZW1zMR0wGwYDVQQLDBRP
cGVuIFdoaXNwZXIgU3lzdGVtczEuMCwGA1UEAwwldGV4dHNlY3VyZS1zZXJ2aWNl
LndoaXNwZXJzeXN0ZW1zLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKzIEbXRRbfAosvPk4magHWzsHhwOzu7On7EA4xxqViHbN4ox4jl5Lh9mu6n
VW0eBvxc9zQKPG0ijgQJN/SV53jFwjqqtr4JYTsHzKs6bgHlYH6sW3XHxePj5JFK
SSXWY7lKNASVl5KkSmhaiYItEPExvSoPB9bNwupixZ5Ae0iIE/NYQA6yZXpQTY0d
BU0l1q0pQeXzLXqgJetThzSXr6j5soNO2KyRoMBNbI42fPUYvWRCOUfyUNI2fb3q
suZD+QQ7YKxl5hgDBU8oNCNN80sNWjhh5nFEOWGj5lxl1qYTkp3sWJJGYD6cuQDJ
1DrSKNbDUWnslIe+wvZfTx9+km0CAwEAAaNIMEYwRAYDVR0RBD0wO4IldGV4dHNl
Y3VyZS1zZXJ2aWNlLndoaXNwZXJzeXN0ZW1zLm9yZ4ISc2VydmljZS5zaWduYWwu
b3JnMA0GCSqGSIb3DQEBCwUAA4IBAQApay5HvPcMP+HE2vS3WOxL/ygG1o/q4zcO
/VYOfA7q2yiFN2FDF8lEcwEqcDMAz2+hGK/fXi2gaIYq6fp3fL9OtzIrXmUNCB2I
9PpuI4jj6xUtERecOXSaHE2C3TI3t7CIcvhbGU1OrJiDLbVFHE8RAetsJJyd2YWu
zBwd9U3oWS4ZNzjlwQLTOiJpoApSKmMlQ6OVfgdr6rRTI1ocw+q4/wDxcYEhiLoM
ljy42A/WrwXzyUMDkcAtZHTjkUAuSLivn434nLcYXalMUIW8sQNLksKTqVH26MKS
2t2HRVs4cwDfmtGzmWSLbgRBl/8Oquq5XLLNEUIM31NVcBUFpKhJ
-----END CERTIFICATE-----
`
var directoryPEM = `
-----BEGIN CERTIFICATE-----
MIIEMDCCAxigAwIBAgICEDowDQYJKoZIhvcNAQELBQAwgY0xCzAJBgNVBAYTAlVT
MRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0w
GwYDVQQKDBRPcGVuIFdoaXNwZXIgU3lzdGVtczEdMBsGA1UECwwUT3BlbiBXaGlz
cGVyIFN5c3RlbXMxEzARBgNVBAMMClRleHRTZWN1cmUwHhcNMTkwNjAxMDAwMDAw
WhcNMzEwMTA5MDMzNzEwWjCBgzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExHTAbBgNVBAoMFE9wZW4gV2hpc3BlciBTeXN0ZW1zMR0wGwYDVQQLDBRP
cGVuIFdoaXNwZXIgU3lzdGVtczEhMB8GA1UEAwwYYXBpLmRpcmVjdG9yeS5zaWdu
YWwub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5QXsh6QPygd
gwIY86CbopBAng5zHHknvD3pX3vOBkt7Gd6IlZ+Jle/QFblaqTFPTuU/VX1oT4OI
c5ZTNb5g/LvKMTBRzEset9CeTjx5STRcmWRlPeu3AJPZZEOvCH3AN55GOOiF8FQp
qoFVIhSUFS17iuRr3iGLA0Khn0Ink0qJouQuBqfrx8AL+r5dfTfEqs4sxpS34rxy
5M8z7HrccxbdcBHkNfn/QRLVikmzpFIBhlMcd9C8orobx+9Zv1cTsyl7m95Ma6zm
/aAVT1nPfKi9t666kYvuTezkehbOCsPqTuGZipQ8620vWs4o0u6X+t9JJfYaTHHF
lAU+GuYzCQIDAQABo4GhMIGeMAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9w
ZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQWBBSvJRKESl+1u6wi
Vs7ju08VUdaFLzAfBgNVHSMEGDAWgBQBixjxP/s5GURuhYa+lGUypzI8kDAjBgNV
HREEHDAaghhhcGkuZGlyZWN0b3J5LnNpZ25hbC5vcmcwDQYJKoZIhvcNAQELBQAD
ggEBAFganu/WuRTlcn2NYQPBGjVLtFUmvxZ8Y0U9u3Vg+fj8hXkpC3IN0MlWslmK
EIFJTYUJKpUqvmCPuhjvsaUKCsF1ECaydzl6Tt6nQZmc74epLxDCprbClM8iLDZS
+0ojUZdF/fGjT16NnoUy1aT2BhpFsIQOZCqM40jf1sHWRSsvnojPu8/NzHWBuRjt
HKMJ/I9knakOywrd3htDQdySadU+7uwKRnX/adRpvr3sYi/4cR5sHuf6bAmL6eCB
iZ4yTkYTQ0sPjAEYCrC2HsQPfYMdAPPMWuMlxgRDJkYT9y18jb9FXF6xVf7HhPWQ
ZUmeym0sPsdNE2uKBEuo2YZXxrE=
-----END CERTIFICATE-----
`
var RootCA *x509.CertPool
var DirectoryCA *x509.CertPool

func SetupCA(rootca string) {
	pem := []byte(rootPEM)
	if rootca != "" && utils.Exists(rootca) {
		b, err := ioutil.ReadFile(rootca)
		if err != nil {
			log.Error(err)
			return
		}
		pem = b
	}

	RootCA = x509.NewCertPool()
	if !RootCA.AppendCertsFromPEM(pem) {
		log.Error("[textsecure] Cannot load PEM")
	}
	directoryPem := []byte(directoryPEM)
	DirectoryCA = x509.NewCertPool()
	if !DirectoryCA.AppendCertsFromPEM(directoryPem) {
		log.Error("[textsecure] Cannot load directory PEM")
	}

}
