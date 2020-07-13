package cryptoUtils

import (
	"bytes"
	"strings"
)

func SplitOne(data string) (string, string) {
	split := strings.SplitN(data, "$", 2)
	if len(split) != 2 {
		return split[0], ""
	}

	return split[0], split[1]
}

func SplitOneBytes(data []byte) ([]byte, []byte) {
	split := bytes.SplitN(data, []byte{'$'}, 2)
	if len(split) != 2 {
		return split[0], nil
	}

	return split[0], split[1]
}
