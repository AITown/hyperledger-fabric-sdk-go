package utils

import (
	"crypto/rand"
)

const (
	// NonceSize is the default NonceSize
	NonceSize = 24
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	// TODO: rand could fill less bytes then len
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GetRandomNonce returns a random byte array of length NonceSize
func GetRandomNonce() ([]byte, error) {
	return GetRandomBytes(NonceSize)
}

// func ComputeSHA256(data []byte) (hash []byte) {
// 	hash, err := factory.GetDefault().Hash(data, &bccsp.SHA256Opts{})
// 	if err != nil {
// 		panic(fmt.Errorf("Failed computing SHA256 on [% x]", data))
// 	}
// 	return
// }
