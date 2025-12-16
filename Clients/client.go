package main

import (
	"bufio"
	"fmt"
	"io"
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

func ReadMsg(conn net.Conn, file *os.File) {
	buff := make([]byte, 1024)
	defer conn.Close()
	for {
		n, err := conn.Read(buff)
		if err != nil {
			if err == io.EOF {
				fmt.Println("🔴 Connection closed")
				return
			}
			log.Println("Read error:", err)
			return
		}
		fmt.Fprintln(file, string(buff[:n]))
		fmt.Println(string(buff[:n]))
	}
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

	//create log file
	file, err := os.OpenFile("example.txt",
		os.O_APPEND|os.O_CREATE|os.O_RDWR,
		0644,
	)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	fmt.Fprintln(file, "This line is appended")

	go WriteMsg(conn)
	go ReadMsg(conn, file)

	select {}

}
