package cryptoUtil

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

var pbkdfHashers map[string]func() hash.Hash = map[string]func() hash.Hash{
	"pbkdf2_sha1":   sha1.New,
	"pbkdf2_sha256": sha256.New,
	"pbkdf2_sha384": sha3.New384,
	"pbkdf2_sha512": sha3.New512,
}

type Pbkdf2Settings struct {
	Hasher         string
	IterationCount int
	Salt           []byte
	KeyLength      int
}

type Pbkdf2Hash struct {
	Settings Pbkdf2Settings
	Hash     []byte
}

func ParsePbkdf2Hash(data string) (*Pbkdf2Hash, error) {
	hashedParts := strings.Split(data, "$")
	if len(hashedParts) != 4 {
		return nil, fmt.Errorf("Unexpected number of hashed parts: %d", len(hashedParts))
	}

	rawAlg := hashedParts[0]
	rawIter := hashedParts[1]
	rawSalt := hashedParts[2]
	rawHash := hashedParts[3]

	_, ok := pbkdfHashers[rawAlg]
	if !ok {
		return nil, fmt.Errorf("Unexpected algorithm %q", rawAlg)
	}

	iter, err := strconv.Atoi(rawIter)
	if err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(rawSalt)
	if err != nil {
		return nil, err
	}

	hash, err := base64.StdEncoding.DecodeString(rawHash)
	if err != nil {
		return nil, err
	}

	return &Pbkdf2Hash{
		Settings: Pbkdf2Settings{
			Hasher:         rawAlg,
			IterationCount: iter,
			Salt:           salt,
			KeyLength:      len(hash),
		},
		Hash: hash,
	}, nil
}

func (p Pbkdf2Settings) Hash(pass []byte) *Pbkdf2Hash {
	hash := pbkdf2.Key(pass, p.Salt, p.IterationCount, p.KeyLength, pbkdfHashers[p.Hasher])

	return &Pbkdf2Hash{
		Settings: p,
		Hash:     hash,
	}
}

func (p *Pbkdf2Hash) Verify(pass []byte) bool {
	hashedPass := p.Settings.Hash(pass)
	return subtle.ConstantTimeCompare(p.Hash, hashedPass.Hash) == 1
}

func (p *Pbkdf2Hash) String() string {
	return fmt.Sprintf("%s$%d$%s$%s",
		p.Settings.Hasher,
		p.Settings.IterationCount,
		base64.StdEncoding.EncodeToString(p.Settings.Salt),
		base64.StdEncoding.EncodeToString(p.Hash))
}
