package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
)

func WriteMsg(conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)
	for {
		Input, _, err := reader.ReadLine()
		if err != nil {
			fmt.Println(err)
			continue
		}

		_, err = conn.Write([]byte(Input))
		if err != nil {
			log.Fatalln("The message could not be delivered", err)
			break
		}
	}
	defer conn.Close()

}

func ReadMsg(conn net.Conn) {
	buff := make([]byte, 1024)
	for {
		n, err := conn.Read(buff)
		if err != nil {
			log.Fatalln("Error while recieving data", err)
		}
		fmt.Println(string(buff[:n]))
	}
	defer conn.Close()
}

func main() {
	fmt.Println("------------------------------------------------------------------------------------------------")
	var serverAddr string
	var userName string
	fmt.Print("Enter user name :")
	fmt.Scan(&userName)
	fmt.Print("Enter server address :")
	fmt.Scan(&serverAddr)
	fmt.Println("------------------------------------------------------------------------------------------------")

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalln("Connection Error", err)
	}

	_, err1 := conn.Write([]byte(userName))
	if err1 != nil {
		log.Printf("Error while rendering username : %v", err)
		conn.Close()
		return
	}

	go WriteMsg(conn)
	go ReadMsg(conn)

	select {}

}
