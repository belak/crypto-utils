package cryptoUtils

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// These are roughly based off the django password hashers, though there only
// sha1 (officially from the pbkdf2 RFC) and sha256 are supported. sha384 and
// sha512 have been added as they're called out as working by the Go
// documentation.
var pbkdfHashers map[string]func() hash.Hash = map[string]func() hash.Hash{
	"pbkdf2_sha1":   sha1.New,
	"pbkdf2_sha256": sha256.New,
	"pbkdf2_sha384": sha512.New384,
	"pbkdf2_sha512": sha512.New,
}

var DefaultPbdkf2Settings = Pbkdf2Settings{
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

func ParsePbkdf2Settings(data string) (*Pbkdf2Settings, string, error) {
	rawAlg, data := SplitOne(data)
	_, ok := pbkdfHashers[rawAlg]
	if !ok {
		return nil, "", fmt.Errorf("Unexpected algorithm %q", rawAlg)
	}

	rawIter, data := SplitOne(data)
	iter, err := strconv.Atoi(rawIter)
	if err != nil {
		return nil, "", err
	}

	rawKeyLen, data := SplitOne(data)
	keyLen, err := strconv.Atoi(rawKeyLen)
	if err != nil {
		return nil, "", err
	}

	return &Pbkdf2Settings{
		Hasher:         rawAlg,
		IterationCount: iter,
		KeyLength:      keyLen,
	}, data, nil
}

func ParsePbkdf2Hash(data string) (*Pbkdf2Hash, string, error) {
	settings, data, err := ParsePbkdf2Settings(data)

	rawSalt, data := SplitOne(data)
	rawHash, data := SplitOne(data)

	salt, err := Base64Decode(rawSalt)
	if err != nil {
		return nil, "", err
	}

	hash, err := Base64Decode(rawHash)
	if err != nil {
		return nil, "", err
	}

	settings.SaltLen = len(salt)
	settings.KeyLength = len(hash)

	return &Pbkdf2Hash{
		Settings: *settings,
		Salt:     salt,
		Hash:     hash,
	}, data, nil
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
	return fmt.Sprintf("%s$%d$%d",
		p.Hasher,
		p.IterationCount,
		p.KeyLength)
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
