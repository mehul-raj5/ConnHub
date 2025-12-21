package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
)

func WriteMsg(conn net.Conn, userName string) {

	reader := bufio.NewReader(os.Stdin)
	nameBytes := []byte(userName)
	nameLenBytes, _ := IntTo3Bytes(len(nameBytes))

	for {
		fmt.Print("Enter type (1=text, 2=image): ")
		line, _, _ := reader.ReadLine()
		TypeOfMsg := string(line)

		var data []byte

		if TypeOfMsg == "1" {
			fmt.Print("Enter message: ")
			msg, _, _ := reader.ReadLine()

			lenBytes, _ := IntTo3Bytes(len(msg))
			data = append(data, byte(1))     // Type
			data = append(data, lenBytes...) // length of payload
			data = append(data, msg...)      // payload

		} else if TypeOfMsg == "2" {
			fmt.Print("Enter image filename: ")
			filename, _, _ := reader.ReadLine()

			path := "/Users/mehulraj/Desktop/PROJECTS /MSR(GO)/data" + string(filename)

			file, err := os.ReadFile(path)

			if err != nil {

				fmt.Println("file not found")

				continue

			}

			lenBytes, _ := IntTo3Bytes(len(file))
			data = append(data, byte(2))     // Type
			data = append(data, lenBytes...) // length of payload
			data = append(data, file...)     // payload
		} else {
			fmt.Println("Invalid type")
			continue
		}

		data = append(data, nameLenBytes...)
		data = append(data, nameBytes...)

		_, err := conn.Write(data)
		if err != nil {
			log.Println("Write error:", err)
			return
		}
	}
}
