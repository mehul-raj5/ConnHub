package main

import (
	"fmt"
	"log"
	"net"
	"sync"
)

var (
	connections = make(map[net.Conn]string)
	ConnMutex   sync.Mutex
)

func accept() {

	fmt.Println("------------------------------------------------------------------------------------------------")
	port := ":8080"
	listen, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalln("Error while listening on Port : ", 8080)
	}

	fmt.Println("Server listening on Port ", port)
	fmt.Println("------------------------------------------------------------------------------------------------")

	for {
		//listen
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		buff := make([]byte, 1024)

		n, err := conn.Read(buff)
		temp := string(buff[:n])

		go HandleConnection(conn, temp)

	}
}

func addConn(conn net.Conn, name string) {
	ConnMutex.Lock()
	connections[conn] = name
	ConnMutex.Unlock()

	fmt.Println("Connection established with client :", name)
}

func removeConn(conn net.Conn) {
	ConnMutex.Lock()
	delete(connections, conn)
	ConnMutex.Unlock()

	fmt.Println("Connection demolished with client :", connections[conn])
}

func HandleConnection(conn net.Conn, name string) {

	addConn(conn, name)
	defer removeConn(conn)
	defer conn.Close()

	buff := make([]byte, 1024)

	for {
		n, err := conn.Read(buff)
		if err != nil {
			fmt.Println("Could not read the message", err)
			break
		}
		fmt.Println("Recieved message from : ", name)
		go broadcast(string(buff[:n]), name)
	}

}

func broadcast(Message string, name string) {
	ConnMutex.Lock()

	Copyconnections := make(map[net.Conn]string)
	for conn := range connections {
		Copyconnections[conn] = string("i")
	}

	ConnMutex.Unlock()

	for conn := range Copyconnections {
		temp := "From " + name + " : " + Message
		_, err := conn.Write([]byte(temp))
		if err != nil {
			conn.Close()
			ConnMutex.Lock()
			delete(connections, conn)
			ConnMutex.Unlock()
		}
	}

}

func main() {

	accept()
	select {}

}
