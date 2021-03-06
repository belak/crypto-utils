package main

import (
	"fmt"
	"log"
	"os"

	cryptoUtils "github.com/belak/crypto-utils"
	cli "github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "pbkdf2",
		Usage: "key derivation",
		Commands: []*cli.Command{
			{
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "hasher",
						Value: cryptoUtils.DefaultPbdkf2Settings.Hasher,
					},
					&cli.IntFlag{
						Name:  "salt-length",
						Value: cryptoUtils.DefaultPbdkf2Settings.SaltLen,
					},
					&cli.IntFlag{
						Name:  "iteration-count",
						Value: cryptoUtils.DefaultPbdkf2Settings.IterationCount,
					},
					&cli.IntFlag{
						Name:  "key-length",
						Value: cryptoUtils.DefaultPbdkf2Settings.KeyLength,
					},
				},
				Name: "derive",
				Action: func(c *cli.Context) error {
					for _, pass := range c.Args().Slice() {
						hasher := c.String("hasher")
						saltLength := c.Int("salt-length")
						iterationCount := c.Int("iteration-count")
						keyLength := c.Int("key-length")

						salt, err := cryptoUtils.RandomBytes(saltLength)
						if err != nil {
							return err
						}

						fmt.Printf(
							"Generating hash for %q using a salt length of %d, an iteration count of %d and a key-length of %d\n",
							pass, saltLength, iterationCount, keyLength)

						hashed := cryptoUtils.Pbkdf2Settings{
							Hasher:         hasher,
							IterationCount: iterationCount,
							SaltLen:        saltLength,
							KeyLength:      keyLength,
						}.Hash([]byte(pass), salt)

						fmt.Printf("salt: %s\n", cryptoUtils.Base64Encode(hashed.Salt))
						fmt.Printf("hash: %s\n", cryptoUtils.Base64Encode(hashed.Hash))
						fmt.Printf("out: %s\n", hashed)
					}

					return nil
				},
			},
			{
				Name: "verify",
				Action: func(c *cli.Context) error {
					for i := 1; i < c.Args().Len(); i += 2 {
						pass := c.Args().Get(i - 1)
						rawHashed := c.Args().Get(i)

						hashed, _, err := cryptoUtils.ParsePbkdf2Hash(rawHashed)
						if err != nil {
							return err
						}

						if hashed.Verify([]byte(pass)) {
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
