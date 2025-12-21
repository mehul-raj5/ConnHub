package main

import (
	"fmt"
	"mime"
	"net/http"
	"strings"
)

func getFileDetails(data []byte) (kind, extension string) {

	fullMime := http.DetectContentType(data)

	pureMime := strings.Split(fullMime, ";")[0]

	kindPart, _, found := strings.Cut(pureMime, "/")
	if found {
		kind = kindPart
	} else {
		kind = "application"
	}

	exts, _ := mime.ExtensionsByType(pureMime)
	if len(exts) > 0 {
		extension = exts[0]
	} else {
		extension = ".bin"
	}

	return kind, extension
}

func IntTo3Bytes(n int) ([]byte, error) {
	if n < 0 || n > (1<<24)-1 {
		return nil, fmt.Errorf("number out of 3-byte range")
	}
	b := make([]byte, 3)
	b[0] = byte((n >> 16) & 0xFF)
	b[1] = byte((n >> 8) & 0xFF)
	b[2] = byte(n & 0xFF)
	return b, nil
}

func ThreeBytesToInt(b []byte) (int, error) {
	if len(b) != 3 {
		return 0, fmt.Errorf("expected exactly 3 bytes")
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2]), nil
}
