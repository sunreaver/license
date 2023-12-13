package license

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"

	"github.com/buf1024/golib/crypt"
	"github.com/pkg/errors"
)

func privateEncrypt(privt *rsa.PrivateKey, data []byte) ([]byte, error) {
	return crypt.PrivateEncrypt(privt, data)
}

func publicDecrypt(pubt *rsa.PublicKey, data []byte) ([]byte, error) {
	return crypt.PublicDecrypt(pubt, data)
}

func parsePKCS8PrivateKey(rsaPrivateKey io.Reader) (*rsa.PrivateKey, error) {
	privateBytes, err := io.ReadAll(rsaPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "read rsa private key error")
	}
	block, _ := pem.Decode(privateBytes)
	if block == nil {
		return nil, errors.New("decode private key failed")
	}

	privt, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse pkcs1 private key")
	}
	privtkey, ok := privt.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not rsa private key")
	}
	return privtkey, nil
}

func parseRSAPublicKey(rsaPublicKey io.Reader) (*rsa.PublicKey, error) {
	publicBytes, err := io.ReadAll(rsaPublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "read rsa public key error")
	}
	block, _ := pem.Decode(publicBytes)
	if block == nil {
		return nil, errors.New("decode public key failed")
	}
	cert, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not rsa public key")
	}
	return pub, nil
}
