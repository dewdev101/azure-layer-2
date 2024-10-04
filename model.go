package main

type DEKResponse struct {
	DEK string `json:"dek"`
}

type DEKRequest struct {
	DEK string `json:"dek"`
}
type EDEKRequest struct {
	EDEK string `json:"edek"`
}

type NonceResponse struct {
	Nonce string `json:"nonce"`
}
