package cryptoUtils

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
)

type Secretbox struct {
	Settings Pbkdf2Settings
	PassSalt []byte
	Nonce    [24]byte
	Data     []byte
}

func SecretboxEncrypt(pass, payload string) (*Secretbox, error) {
	passSalt, err := RandomSalt(DefaultPbdkf2Hasher.SaltLen)
	if err != nil {
		return nil, err
	}
	hash := DefaultPbdkf2Hasher.Hash([]byte(pass), passSalt)

	var nonce [24]byte
	if err := ReadRandom(nonce[:]); err != nil {
		return nil, err
	}

	var secretKey [32]byte
	copy(secretKey[:], hash.Hash)

	var out []byte
	copy(out, nonce[:])

	data := secretbox.Seal(out, []byte(payload), &nonce, &secretKey)

	return &Secretbox{
		Settings: hash.Settings,
		PassSalt: passSalt[:],
		Nonce:    nonce,
		Data:     data[:],
	}, nil
}

func ParseSecretbox(input string) (*Secretbox, error) {
	split := strings.SplitN(input, "$", 6)
	if len(split) != 6 {
		return nil, fmt.Errorf("Unexpected number of parts: %d", len(split))
	}

	alg := split[0]
	kdfAlg := split[1]
	rawIterCount := split[2]
	rawPassSalt := split[3]
	rawNonce := split[4]
	rawData := split[5]

	if alg != "secretbox" {
		return nil, fmt.Errorf("Unknown algorithm %q", alg)
	}

	if kdfAlg != "pbkdf2_sha256" {
		return nil, fmt.Errorf("Unknown kdf algorithm %q", kdfAlg)
	}

	iterCount, err := strconv.Atoi(rawIterCount)
	if err != nil {
		return nil, err
	}

	passSalt, err := Base64Decode(rawPassSalt)
	if err != nil {
		return nil, err
	}

	decodedNonce, err := Base64Decode(rawNonce)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], decodedNonce)

	data, err := Base64Decode(rawData)
	if err != nil {
		return nil, err
	}

	return &Secretbox{
		Settings: Pbkdf2Settings{
			Hasher:         kdfAlg,
			IterationCount: iterCount,
			KeyLength:      32,
		},
		PassSalt: passSalt,
		Nonce:    nonce,
		Data:     data,
	}, nil
}

func (s *Secretbox) Decrypt(pass string) (string, error) {
	hash := s.Settings.Hash([]byte(pass), s.PassSalt)

	var secretKey [32]byte
	copy(secretKey[:], hash.Hash)

	var out []byte
	copy(out, s.Nonce[:])

	data, ok := secretbox.Open(out, s.Data, &s.Nonce, &secretKey)
	if !ok {
		return "", errors.New("failed to decrypt")
	}

	return string(data), nil
}

func (s *Secretbox) String() string {
	return fmt.Sprintf(
		"secretbox$%s$%s$%s$%s",
		s.Settings.String(),
		Base64Encode(s.PassSalt),
		Base64Encode(s.Nonce[:]),
		Base64Encode(s.Data))
}
