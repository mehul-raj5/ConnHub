package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

// TCP header and payload reader
// return (msgType, payload, sender, error)
func readPacket(conn net.Conn) (byte, []byte, string, error) {
	header := make([]byte, 4)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return 0, nil, "", err
	}

	msgType := header[0]
	length, err := ThreeBytesToInt(header[1:4])
	if err != nil {
		return 0, nil, "", err
	}

	payload := make([]byte, length)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		return 0, nil, "", err
	}

	senderLenBuf := make([]byte, 3)
	if _, err := io.ReadFull(conn, senderLenBuf); err != nil {
		return 0, nil, "", err
	}
	senderLen, _ := ThreeBytesToInt(senderLenBuf)

	senderNameBuf := make([]byte, senderLen)
	if _, err := io.ReadFull(conn, senderNameBuf); err != nil {
		return 0, nil, "", err
	}
	sender := string(senderNameBuf)

	return msgType, payload, sender, nil
}

func ReadMsg(conn net.Conn, file *os.File) {
	saveDir := "data_received"
	if err := os.MkdirAll(saveDir, 0755); err != nil {
		log.Println("Error creating directory:", err)
	}
	for {
		msgType, payload, sender, err := readPacket(conn)
		if err != nil {
			log.Println("Disconnected from server.")
			return
		}
		if msgType == 1 {
			// text
			finalMsg := fmt.Sprintf("From %s: %s", sender, string(payload))
			fmt.Println(finalMsg) // Print to console so you see it live
			fmt.Fprintln(file, finalMsg)

		} else if msgType == 2 {
			// data other than text
			kind, ext := getFileDetails(payload)
			timestamp := time.Now().Format("2006-01-02_15-04-05")
			// Example: file_Alice_2025-12-21_image.png
			filename := fmt.Sprintf("file_%s_%s_%s%s", sender, timestamp, kind, ext)

			path := filepath.Join(saveDir, filename)
			err := os.WriteFile(path, payload, 0644)
			if err != nil {
				log.Println("Error saving file:", err)
				continue
			}
			fmt.Printf("Successfully saved %s from %s as %s\n", kind, sender, path)
		}
	}
}
