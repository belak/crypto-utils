package cryptoUtils

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

type Secretbox struct {
	Settings Pbkdf2Settings
	PassSalt []byte
	Nonce    [24]byte
	Data     []byte
}

func SecretboxEncrypt(pass, payload string) (*Secretbox, error) {
	passSalt, err := RandomBytes(DefaultPbdkf2Settings.SaltLen)
	if err != nil {
		return nil, err
	}
	hash := DefaultPbdkf2Settings.Hash([]byte(pass), passSalt)

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
	alg, rest := SplitOne(input)
	if alg != "secretbox" {
		return nil, fmt.Errorf("Unknown algorithm %q", alg)
	}

	settings, rest, err := ParsePbkdf2Settings(rest)
	if err != nil {
		return nil, err
	}

	rawPassSalt, rest := SplitOne(rest)
	rawNonce, rest := SplitOne(rest)
	rawData, rest := SplitOne(rest)

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
		Settings: *settings,
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
