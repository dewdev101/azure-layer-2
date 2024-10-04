package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	EncryptionKeyName := os.Getenv("AZURE_KEY_ENCRYPTION_KEY_NAME")
	EncryptionVersion := os.Getenv("AZURE_KEY_ENCRYPTION_KEY_VERSION")
	client := NewClientAzureKey()

	http.HandleFunc("/generate-nonce", generateNonceHandler)
	http.HandleFunc("/generate-dek", generateDEKHandler)
	http.HandleFunc("/encrypt", encryptEDEKHandler(client, EncryptionKeyName, EncryptionVersion))
	http.HandleFunc("/decrypt", decryptEDEKHandler(client, EncryptionKeyName, EncryptionVersion))

	fmt.Println("API is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))

	// Generate an encryption key. 16 bytes = AES-128, 32 bytes = AES-256.

}
func NewClientAzureKey() *azkeys.Client {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
		return nil
	}

	vaultUrl := os.Getenv("AZURE_KEY_VAULT_URL")
	credential, err := azidentity.NewClientSecretCredential(os.Getenv("AZURE_TENANT_ID"), os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_CLIENT_SECRET"), nil)
	if err != nil {
		log.Fatal("error: ", err.Error())
	}
	clientKey, err := azkeys.NewClient(vaultUrl, credential, nil)
	if err != nil {
		log.Fatal(err)
	}
	return clientKey

}

func generateDEK() []byte {
	// Generate random DEK
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}

func generateNonce() []byte {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	return nonce
}

func generateNonceHandler(w http.ResponseWriter, r *http.Request) {

	nonce := generateNonce()
	nonceHex := fmt.Sprintf("%x", nonce)
	response := NonceResponse{
		Nonce: nonceHex,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func generateDEKHandler(w http.ResponseWriter, r *http.Request) {

	dek := generateDEK()
	dekHex := fmt.Sprintf("%x", dek)
	response := DEKResponse{
		DEK: dekHex,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func encryptEDEKHandler(client *azkeys.Client, EncryptionKeyName, EncryptionVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var req DEKRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Check if DEK is provided in the request
		if req.DEK == "" {
			http.Error(w, "DEK is required", http.StatusBadRequest)
			return
		}

		dek32byte, _ := convertBase64ToByteArray(req.DEK)

		// =========== Encrypt DEK to get EDEK ===========
		// RSA-OAEP-256
		parameter := azkeys.KeyOperationsParameters{
			Algorithm: &azkeys.PossibleJSONWebKeyEncryptionAlgorithmValues()[14],
			Value:     dek32byte,
		}

		res, err := client.Encrypt(context.Background(), EncryptionKeyName, EncryptionVersion, parameter, nil)
		if err != nil {
			fmt.Printf("failed to encrypt %v", err)
			log.Fatal(err)
		}

		dekBase64Str, err := convertByteArrayToBase64(res.Result)
		if err != nil {
			log.Fatalf("failed to encode Byte 32 : %v", err)
		}

		// Respond with encrypted data in JSON.
		response := map[string]string{
			"EDEK": dekBase64Str,
		}

		// Return JSON response.
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}
}

func decryptEDEKHandler(client *azkeys.Client, EncryptionKeyName string, EncryptionVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var req EDEKRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Check if DEK is provided in the request
		if req.EDEK == "" {
			http.Error(w, "DEK is required", http.StatusBadRequest)
			return
		}

		edek32byte, _ := convertBase64ToByteArray(req.EDEK)

		// =========== Decrypt ===========
		parameter := azkeys.KeyOperationsParameters{
			Algorithm: &azkeys.PossibleJSONWebKeyEncryptionAlgorithmValues()[14],
			Value:     edek32byte,
		}

		res2, err := client.Decrypt(context.Background(), EncryptionKeyName, EncryptionVersion, parameter, nil)
		if err != nil {
			fmt.Printf("failed to decrypt %v", err)
			log.Fatal(err)
		}
		// fmt.Printf("res2:%v\n", res2.Result)
		dek, err := convertByteArrayToBase64(res2.Result)
		if err != nil {
			fmt.Printf("failed to convertBase64ToByteArray  %v", err)
			log.Fatal(err)
		}

		// Respond with encrypted data in JSON.
		response := map[string]string{
			"DEK": dek,
		}

		// Return JSON response.
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}
}
