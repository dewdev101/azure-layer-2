package main

import (
	"encoding/base64"
	"fmt"
)

func convertBase64ToByteArray(base64String string) ([]byte, error) {
	// Decode the base64 string
	decoded, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base64 string: %v", err)
	}
	return decoded, nil
}

func convertByteArrayToBase64(byteArray []byte) (string, error) {
	base64Str := base64.StdEncoding.EncodeToString(byteArray) // Base64 encode
	return base64Str, nil
}
