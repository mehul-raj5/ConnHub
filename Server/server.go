package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

var (
	connections = make(map[net.Conn]string)
	ConnMutex   sync.Mutex
)

func ThreeBytesToInt(b []byte) (int, error) {
	if len(b) != 3 {
		return 0, fmt.Errorf("invalid length")
	}
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2]), nil
}

func readFullPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	payloadLen, _ := ThreeBytesToInt(header[1:4])

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	senderLenBuf := make([]byte, 3)
	if _, err := io.ReadFull(conn, senderLenBuf); err != nil {
		return nil, err
	}
	senderLen, _ := ThreeBytesToInt(senderLenBuf)

	senderNameBuf := make([]byte, senderLen)
	if _, err := io.ReadFull(conn, senderNameBuf); err != nil {
		return nil, err
	}

	fullPacket := append(header, payload...)
	fullPacket = append(fullPacket, senderLenBuf...)
	fullPacket = append(fullPacket, senderNameBuf...)

	return fullPacket, nil
}

func handleNewClient(conn net.Conn) {
	lenBuf := make([]byte, 3)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		conn.Close()
		return
	}
	nameLen, _ := ThreeBytesToInt(lenBuf)
	nameBuf := make([]byte, nameLen)
	if _, err := io.ReadFull(conn, nameBuf); err != nil {
		conn.Close()
		return
	}
	name := string(nameBuf)

	ConnMutex.Lock()
	connections[conn] = name
	ConnMutex.Unlock()

	fmt.Printf("User %s connected\n", name)

	defer func() {
		ConnMutex.Lock()
		delete(connections, conn)
		ConnMutex.Unlock()
		conn.Close()
		fmt.Printf("User %s disconnected\n", name)
	}()

	for {
		fullPacket, err := readFullPacket(conn)
		if err != nil {
			break
		}
		broadcastRaw(fullPacket)
	}
}

func broadcastRaw(fullPacket []byte) {
	var clientsToNotify []net.Conn

	ConnMutex.Lock()
	for conn := range connections {
		clientsToNotify = append(clientsToNotify, conn)
	}
	ConnMutex.Unlock()

	for _, conn := range clientsToNotify {
		_, err := conn.Write(fullPacket)
		if err != nil {
			conn.Close()

			ConnMutex.Lock()
			delete(connections, conn)
			ConnMutex.Unlock()
		}
	}
}

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Server started on :8080")
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleNewClient(conn)
	}
}
