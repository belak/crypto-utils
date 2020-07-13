package cryptoUtils

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

// These are roughly based off the django password hashers, though there only
// sha1 (officially from the pbkdf2 RFC) and sha256 are supported. sha384 and
// sha512 have been added as they're called out as working by the Go
// documentation.
var pbkdfHashers map[string]func() hash.Hash = map[string]func() hash.Hash{
	"pbkdf2_sha1":   sha1.New,
	"pbkdf2_sha256": sha256.New,
	"pbkdf2_sha384": sha3.New384,
	"pbkdf2_sha512": sha3.New512,
}

var DefaultPbdkf2Hasher = Pbkdf2Settings{
	Hasher:         "pbkdf2_sha256",
	IterationCount: 260000,
	SaltLen:        8,
	KeyLength:      32,
}

type Pbkdf2Settings struct {
	Hasher         string
	IterationCount int
	SaltLen        int
	KeyLength      int
}

type Pbkdf2Hash struct {
	Settings Pbkdf2Settings
	Salt     []byte
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

	salt, err := Base64Decode(rawSalt)
	if err != nil {
		return nil, err
	}

	hash, err := Base64Decode(rawHash)
	if err != nil {
		return nil, err
	}

	return &Pbkdf2Hash{
		Settings: Pbkdf2Settings{
			Hasher:         rawAlg,
			IterationCount: iter,
			SaltLen:        len(salt),
			KeyLength:      len(hash),
		},
		Salt: salt,
		Hash: hash,
	}, nil
}

func (p Pbkdf2Settings) Hash(pass []byte, salt []byte) *Pbkdf2Hash {
	hash := pbkdf2.Key(pass, salt, p.IterationCount, p.KeyLength, pbkdfHashers[p.Hasher])

	return &Pbkdf2Hash{
		Settings: p,
		Salt:     salt,
		Hash:     hash,
	}
}

func (p Pbkdf2Settings) String() string {
	return fmt.Sprintf("%s$%d",
		p.Hasher,
		p.IterationCount)
}

func (p *Pbkdf2Hash) Verify(pass []byte) bool {
	hashedPass := p.Settings.Hash(pass, p.Salt)
	return subtle.ConstantTimeCompare(p.Hash, hashedPass.Hash) == 1
}

func (p *Pbkdf2Hash) String() string {
	return fmt.Sprintf("%s$%s$%s",
		p.Settings,
		Base64Encode(p.Salt),
		Base64Encode(p.Hash))
}
