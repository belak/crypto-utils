package cryptoUtils

import "crypto/rand"

func RandomSalt(saltLength int) ([]byte, error) {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func ReadRandom(data []byte) error {
	_, err := rand.Read(data)
	return err
}
