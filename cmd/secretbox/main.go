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
		Name:  "secretbox",
		Usage: "basic encryption",
		Commands: []*cli.Command{
			{
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "base64",
						Value: true,
					},
				},
				Name: "encrypt",
				Action: func(c *cli.Context) error {
					pass := c.String("password")
					payload := c.Args().First()

					box, err := cryptoUtils.SecretboxEncrypt(pass, payload)
					if err != nil {
						return err
					}

					fmt.Println(box)
					return nil
				},
			},
			{
				Name: "decrypt",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "password",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					pass := c.String("password")
					payload := c.Args().First()

					box, err := cryptoUtils.ParseSecretbox(payload)
					if err != nil {
						return err
					}

					data, err := box.Decrypt(pass)
					if err != nil {
						return err
					}

					fmt.Println(data)
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
