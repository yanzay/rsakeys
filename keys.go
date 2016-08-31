package rsakeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
)

const bits = 4096

// GenerateKeys generates RSA keypair,
// private key encoded with passphrase,
// keys are PEM encoded
func GenerateKeys(password string, public io.Writer, private io.Writer) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	passphrase := sha512.Sum512([]byte(password))
	err = serializePrivateKey(privateKey, passphrase[:], private)
	if err != nil {
		return err
	}
	return serializePublicKey(&privateKey.PublicKey, public)
}

// ReadKey reads RSA private key from io.Reader and decodes it using password
func ReadKey(password string, private io.Reader) (*rsa.PrivateKey, error) {
	// decoding private key
	privkey, err := ioutil.ReadAll(private)
	block, _ := pem.Decode(privkey)
	if block == nil {
		return nil, errors.New("Invalid private key")
	}
	passphrase := sha512.Sum512([]byte(password))
	decryptedKey, err := x509.DecryptPEMBlock(block, passphrase[:])
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS1PrivateKey(decryptedKey)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func serializePublicKey(key *rsa.PublicKey, writer io.Writer) error {
	public, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: public,
	}
	return pem.Encode(writer, block)
}

func serializePrivateKey(key *rsa.PrivateKey, passphrase []byte, writer io.Writer) error {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	block, err := encryptPrivateKey(block, passphrase)
	if err != nil {
		return err
	}
	return pem.Encode(writer, block)
}

func encryptPrivateKey(block *pem.Block, passphrase []byte) (*pem.Block, error) {
	return x509.EncryptPEMBlock(rand.Reader,
		block.Type,
		block.Bytes,
		passphrase,
		x509.PEMCipherAES256,
	)
}
