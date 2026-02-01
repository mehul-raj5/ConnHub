package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	TypeCreational uint8 = 1
	TypeMessaging  uint8 = 2
)

const (
	ActionAuth         uint8 = 0
	ActionCreateGroup  uint8 = 1
	ActionUpdateGroup  uint8 = 2
	ActionBroadcastMsg uint8 = 3
	ActionSendGroupMsg uint8 = 4
	ActionPrivateMsg   uint8 = 5
)

const (
	MaxGroupNameLen = 64
	MaxUsers        = 50
	MaxMessageLen   = 4096
	MaxBodyLen      = 1024 * 1024 * 100
	MaxFileSize     = 1024 * 1024 * 100 // 100MB
)

const (
	UpdateAddUsers    uint8 = 1
	UpdateRemoveUsers uint8 = 2
)

type Packet struct {
	Type   uint8
	Action uint8
	Flags  uint8
	Body   []byte
}

var reader = bufio.NewReader(os.Stdin)

func readLine(prompt string, maxLen int) ([]byte, error) {
	fmt.Print(prompt)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)

	if len(line) == 0 || len(line) > maxLen {
		return nil, fmt.Errorf("invalid input length")
	}
	return []byte(line), nil
}
func readFile(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	path, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	path = strings.TrimSpace(path)
	if len(path) == 0 {
		return nil, fmt.Errorf("invalid file path")
	}
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(file) > MaxFileSize {
		return nil, fmt.Errorf("file too large")
	}
	return file, nil
}
func readInt(prompt string) (int, error) {
	fmt.Print(prompt)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)

	var v int
	_, err = fmt.Sscanf(line, "%d", &v)
	return v, err
}

func buildBroadcastMessageBody() ([]byte, error) {
	fmt.Println("Enter the type of broadcast message (1 = Text, 2 = File): ")
	var messagetype int
	fmt.Scan(&messagetype)
	if messagetype != 1 && messagetype != 2 {
		return nil, fmt.Errorf("invalid message type")
	}
	var message []byte

	if messagetype == 1 {
		temp, err := readLine("Enter message: ", MaxMessageLen)
		if err != nil {
			return nil, err
		}
		message = []byte(temp)
	} else if messagetype == 2 {
		temp, err := readFile("Enter file path: ")
		if err != nil {
			return nil, err
		}
		message = temp
	}

	buf := make([]byte, 0)
	buf = append(buf, byte(messagetype))
	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(message)))
	buf = append(buf, msgLen...)
	buf = append(buf, message...)
	return buf, nil
}

func buildCreateGroupBody() ([]byte, error) {
	groupName, err := readLine("Enter group name: ", MaxGroupNameLen)
	if err != nil {
		return nil, err
	}

	userCount, err := readInt("Enter number of users to add: ")
	if err != nil || userCount <= 0 || userCount > MaxUsers {
		return nil, fmt.Errorf("invalid user count")
	}

	buf := make([]byte, 0)
	buf = append(buf, byte(len(groupName)))
	buf = append(buf, []byte(groupName)...)
	buf = append(buf, byte(userCount))

	for i := 0; i < userCount; i++ {
		username, err := readLine(
			fmt.Sprintf("Enter username %d: ", i+1),
			FixedUsernameSize,
		)
		if err != nil {
			return nil, err
		}

		nameBytes := make([]byte, FixedUsernameSize)
		copy(nameBytes, username)
		buf = append(buf, nameBytes...)
	}

	return buf, nil
}

func buildUpdateGroupBody() ([]byte, error) {
	groupName, err := readLine("Enter group name: ", MaxGroupNameLen)
	if err != nil {
		return nil, err
	}

	fmt.Println("1 = Add users")
	fmt.Println("2 = Remove users")

	op, err := readInt("Choose operation: ")
	if err != nil || (op != int(UpdateAddUsers) && op != int(UpdateRemoveUsers)) {
		return nil, fmt.Errorf("invalid operation")
	}

	userCount, err := readInt("Enter number of users: ")
	if err != nil || userCount <= 0 || userCount > MaxUsers {
		return nil, fmt.Errorf("invalid user count")
	}

	buf := make([]byte, 0)
	buf = append(buf, byte(len(groupName)))
	buf = append(buf, []byte(groupName)...)
	buf = append(buf, byte(op))
	buf = append(buf, byte(userCount))

	for i := 0; i < userCount; i++ {
		username, err := readLine(
			fmt.Sprintf("Enter username %d: ", i+1),
			FixedUsernameSize,
		)
		if err != nil {
			return nil, err
		}

		nameBytes := make([]byte, FixedUsernameSize)
		copy(nameBytes, username)
		buf = append(buf, nameBytes...)
	}

	return buf, nil
}

func buildSendGroupMessageBody() ([]byte, error) {
	groupName, err := readLine("Enter group name: ", MaxGroupNameLen)
	if err != nil {
		return nil, err
	}

	fmt.Println("Enter the type of message (1 = Text, 2 = File): ")
	var messagetype int
	fmt.Scan(&messagetype)
	if messagetype != 1 && messagetype != 2 {
		return nil, fmt.Errorf("invalid message type")
	}
	var message []byte

	if messagetype == 1 {
		temp, err := readLine("Enter message: ", MaxMessageLen)
		if err != nil {
			return nil, err
		}
		message = []byte(temp)
	} else if messagetype == 2 {
		temp, err := readFile("Enter file path: ")
		if err != nil {
			return nil, err
		}
		message = temp
	}

	buf := make([]byte, 0)
	buf = append(buf, byte(len(groupName)))
	buf = append(buf, []byte(groupName)...)
	buf = append(buf, byte(messagetype))

	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(message)))
	buf = append(buf, msgLen...)
	buf = append(buf, message...)

	return buf, nil
}

func buildPrivateMessageBody() ([]byte, error) {
	targetUsername, err := readLine("Enter recipient username: ", FixedUsernameSize)
	if err != nil {
		return nil, err
	}

	fmt.Println("Enter the type of message (1 = Text, 2 = File): ")
	var messagetype int
	fmt.Scan(&messagetype)
	if messagetype != 1 && messagetype != 2 {
		return nil, fmt.Errorf("invalid message type")
	}
	var message []byte

	if messagetype == 1 {
		temp, err := readLine("Enter message: ", MaxMessageLen)
		if err != nil {
			return nil, err
		}
		message = []byte(temp)
	} else if messagetype == 2 {
		temp, err := readFile("Enter file path: ")
		if err != nil {
			return nil, err
		}
		message = temp
	}

	buf := make([]byte, 0)
	buf = append(buf, byte(len(targetUsername)))
	buf = append(buf, []byte(targetUsername)...)
	buf = append(buf, byte(messagetype))

	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(message)))
	buf = append(buf, msgLen...)
	buf = append(buf, message...)

	return buf, nil
}

func encode(p Packet) ([]byte, error) {
	if len(p.Body) > MaxBodyLen {
		return nil, fmt.Errorf("body too large")
	}

	buf := make([]byte, 7)
	buf[0] = p.Type
	buf[1] = p.Action
	buf[2] = p.Flags
	binary.BigEndian.PutUint32(buf[3:], uint32(len(p.Body)))
	buf = append(buf, p.Body...)

	return buf, nil
}

func WriteMsg(conn net.Conn) {
	for {
		var p Packet
		p.Flags = 0

		t, err := readInt("Type (1=Creational, 2=Messaging): ")
		if err != nil {
			fmt.Println(err)
			continue
		}
		p.Type = uint8(t)

		switch p.Type {
		case TypeCreational:
			a, _ := readInt("Action (1=Create, 2=Update): ")
			p.Action = uint8(a)

			if p.Action == ActionCreateGroup {
				p.Body, err = buildCreateGroupBody()
			} else if p.Action == ActionUpdateGroup {
				p.Body, err = buildUpdateGroupBody()
			} else {
				fmt.Println("Invalid action")
				continue
			}

		case TypeMessaging:
			a, _ := readInt("Action (3=Broadcast, 4=Group Msg, 5=Private Msg): ")
			p.Action = uint8(a)

			if p.Action == ActionBroadcastMsg {
				p.Body, err = buildBroadcastMessageBody()
			} else if p.Action == ActionSendGroupMsg {
				p.Body, err = buildSendGroupMessageBody()
			} else if p.Action == ActionPrivateMsg {
				p.Body, err = buildPrivateMessageBody()
			} else {
				fmt.Println("Invalid action")
				continue
			}

		default:
			fmt.Println("Invalid type")
			continue
		}

		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		data, err := encode(p)
		if err != nil {
			fmt.Println("Encode error:", err)
			continue
		}

		_, err = conn.Write(data)
		if err != nil {
			fmt.Println("Write error:", err)
			return
		}
	}
}
