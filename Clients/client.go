package main

import (
	"fmt"
	"log"
	"net"
)

func buildAuthBody() ([]byte, error) {
	userName, err := readLine("Enter your username: ", FixedUsernameSize)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 1+len(userName))
	buf = append(buf, byte(len(userName)))
	buf = append(buf, []byte(userName)...)

	return buf, nil
}

func sendAuthPacket(conn net.Conn) error {
	body, err := buildAuthBody()
	if err != nil {
		return err
	}

	p := Packet{
		Type:   TypeCreational,
		Action: ActionAuth,
		Flags:  0,
		Body:   body,
	}

	buf, err := encode(p)
	if err != nil {
		return err
	}

	_, err = conn.Write(buf)
	if err != nil {
		return err
	}

	fmt.Println("Authenticated successfully")
	return nil
}

func main() {
	var serverAddr string
	fmt.Print("Enter server address: ")
	fmt.Scan(&serverAddr)

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalln("Connection error:", err)
	}
	defer conn.Close()

	err = sendAuthPacket(conn)
	if err != nil {
		log.Fatalln("Authentication error:", err)
	}

	go WriteMsg(conn)
	readmsg(conn)
}

// byte1 (creational or just sending and updating message)|
// byte2 if creational (create user or create group), if sending message (updating group users or sending message to broadcast, if to group or private -> access payload)

//part 3 if create user -> username, if create group -> group name
//part 4 list of users or payload

//update ke liye body me changes aayenge
//flags for future use just like tcp header hehe

//send message -> broadcast or to a specific group

//create group -> enter group name and members
//view groups -> view groups in which you are a member or owner DONT DO THIS , JUST FOR REFERENCE
//exit
