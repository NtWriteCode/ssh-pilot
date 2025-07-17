package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/skip2/go-qrcode"
)

// QR generation for public key only
func (c *AppConfig) generatePublicKeyQR(keyName string) (string, error) {
	keyPair, exists := c.KeyPairs[keyName]
	if !exists {
		return "", fmt.Errorf("key pair %s does not exist", keyName)
	}

	qrCode, err := qrcode.Encode(keyPair.PublicKey, qrcode.Medium, 256)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code for public key: %v", err)
	}

	return base64.StdEncoding.EncodeToString(qrCode), nil
}

// QR generation for private key only
func (c *AppConfig) generatePrivateKeyQR(keyName string) (string, error) {
	keyPair, exists := c.KeyPairs[keyName]
	if !exists {
		return "", fmt.Errorf("key pair %s does not exist", keyName)
	}

	// Read private key content from file
	privateKeyContent, err := ioutil.ReadFile(keyPair.PrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file: %v", err)
	}

	qrCode, err := qrcode.Encode(string(privateKeyContent), qrcode.Medium, 256)
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code for private key: %v", err)
	}

	return base64.StdEncoding.EncodeToString(qrCode), nil
}

// Legacy function for backward compatibility
func (c *AppConfig) generateKeyQR(keyName string) (string, error) {
	return c.generatePublicKeyQR(keyName)
}
