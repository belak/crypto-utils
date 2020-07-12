package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	cli "github.com/urfave/cli/v2"
	"golang.org/x/crypto/pbkdf2"
)

// TODO: support other hashing algorithms

func main() {
	app := &cli.App{
		Name:  "pbkdf2",
		Usage: "key derivation",
		Commands: []*cli.Command{
			{
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "salt-length",
						Value: 8,
					},
					&cli.IntFlag{
						Name:  "iteration-count",
						Value: 260000,
					},
					&cli.IntFlag{
						Name:  "key-length",
						Value: 64,
					},
				},
				Name: "derive",
				Action: func(c *cli.Context) error {
					for _, pass := range c.Args().Slice() {
						saltLength := c.Int("salt-length")
						iterationCount := c.Int("iteration-count")
						keyLength := c.Int("key-length")

						salt := make([]byte, saltLength)
						_, err := rand.Read(salt)
						if err != nil {
							return err
						}

						fmt.Printf(
							"Generating hash for %q using a salt length of %d, an iteration count of %d and a key-length of %d\n",
							pass, saltLength, iterationCount, keyLength)

						hash := pbkdf2.Key([]byte(pass), salt, iterationCount, keyLength, sha256.New)

						fmt.Printf("salt: %x\n", salt)
						fmt.Printf("hash: %x\n", hash)

						fmt.Printf("out: %s$%d$%s$%s\n",
							"pbkdf2_sha256",
							iterationCount,
							base64.StdEncoding.EncodeToString(salt),
							base64.StdEncoding.EncodeToString(hash))
					}

					return nil
				},
			},
			{
				Name: "verify",
				Action: func(c *cli.Context) error {
					for i := 1; i < c.Args().Len(); i += 2 {
						pass := c.Args().Get(i - 1)
						hashed := c.Args().Get(i)

						hashedParts := strings.Split(hashed, "$")
						if len(hashedParts) != 4 {
							return fmt.Errorf("Unexpected number of hashed parts: %d", len(hashedParts))
						}

						alg := hashedParts[0]
						rawIter := hashedParts[1]
						rawSalt := hashedParts[2]
						rawHash := hashedParts[3]

						if alg != "pbkdf2_sha256" {
							return fmt.Errorf("Unexpected algorithm %q", hashedParts[0])
						}

						iter, err := strconv.Atoi(rawIter)
						if err != nil {
							return err
						}

						salt, err := base64.StdEncoding.DecodeString(rawSalt)
						if err != nil {
							return err
						}

						hash, err := base64.StdEncoding.DecodeString(rawHash)
						if err != nil {
							return err
						}

						data := pbkdf2.Key([]byte(pass), salt, iter, len(hash), sha256.New)

						if subtle.ConstantTimeCompare(data, hash) == 1 {
							fmt.Printf("Password %q matched hash %s\n", pass, hashed)
						} else {
							fmt.Printf("Password %q did not match hash %s\n", pass, hashed)
						}
					}

					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
