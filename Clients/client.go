package main

import (
	"fmt"
	"log"
	"net"
	"os"
)

//to add groups
//create 2 lists
//one in which only member group is stored/
// one in which you are the owner(done at every client)
//create a grup using permanent names
//add this group and members list to edit access groups and members group

//to send message using group name fetch the member list and send message to those members using (list, message)(sent to the server and server forwards these messages)

//add timestamp+name+random_id to each recieved image
//think about header in a better format
//only add from to the message at the reciever side
//no access given to the server to view the messages

func main() {
	var serverAddr, userName string
	fmt.Print("Enter user name: ")
	fmt.Scan(&userName)
	fmt.Print("Enter server address: ")
	fmt.Scan(&serverAddr)

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalln("Connection error:", err)
	}
	defer conn.Close()

	//convert name into same header and payload format for easy understanding
	nameBytes := []byte(userName)
	lenHeader, _ := IntTo3Bytes(len(nameBytes))
	conn.Write(lenHeader)
	conn.Write(nameBytes)

	f, _ := os.OpenFile("messages.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()

	go WriteMsg(conn, userName)
	ReadMsg(conn, f) // Run in main thread to keep app alive
}
