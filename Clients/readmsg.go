package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const FixedUsernameSize = 32

var (
	Groups   = make(map[string]map[string]struct{})
	GrpMutex sync.Mutex
)

func decode(conn net.Conn) (Packet, error) {

	var p Packet
	header := make([]byte, 7)
	_, err := io.ReadFull(conn, header)
	if err != nil {
		return p, err
	}

	p.Type = header[0]
	p.Action = header[1]
	p.Flags = header[2]
	bodyLen := int(binary.BigEndian.Uint32(header[3:]))

	if bodyLen < 0 || bodyLen > MaxBodyLen {
		return p, fmt.Errorf("invalid body length")
	}

	if bodyLen > 0 {
		p.Body = make([]byte, bodyLen)
		_, err = io.ReadFull(conn, p.Body)
		if err != nil {
			return p, err
		}

	} else {
		p.Body = []byte{}
	}
	return p, nil
}

func handleCreateGroup(p Packet) {
	if len(p.Body) < 1 {
		return
	}
	CreatorLen := int(p.Body[0])
	if len(p.Body) < 1+CreatorLen+1 {
		return
	}
	CreatorName := string(p.Body[1 : 1+CreatorLen])
	groupNameLen := int(p.Body[1+CreatorLen])
	groupName := string(p.Body[1+CreatorLen+1 : 1+CreatorLen+1+groupNameLen])

	idx := 1 + CreatorLen + 1 + groupNameLen
	if len(p.Body) <= idx {
		return
	}
	userCount := int(p.Body[idx])

	offset := 1 + CreatorLen + 1 + groupNameLen + 1

	GrpMutex.Lock()
	_, exists := Groups[groupName]
	if exists {
		GrpMutex.Unlock()
		return
	}
	Groups[groupName] = make(map[string]struct{})
	Groups[groupName][CreatorName] = struct{}{}
	GrpMutex.Unlock()

	for i := 0; i < userCount; i++ {
		if offset+FixedUsernameSize > len(p.Body) {
			return
		}
		raw := p.Body[offset : offset+FixedUsernameSize]
		offset += FixedUsernameSize

		username := string(bytes.TrimRight(raw, "\x00"))
		if username == "" {
			continue
		}

		GrpMutex.Lock()
		Groups[groupName][username] = struct{}{}
		GrpMutex.Unlock()
	}
	fmt.Printf("%s created a group %s\n", CreatorName, groupName)
}

func handleUpdateGroup(p Packet) {
	if len(p.Body) < 1 {
		return
	}
	CreatorLen := int(p.Body[0])
	if len(p.Body) < 1+CreatorLen+1 {
		return
	}
	CreatorName := string(p.Body[1 : 1+CreatorLen])
	groupNameLen := int(p.Body[1+CreatorLen])
	groupName := string(p.Body[1+CreatorLen+1 : 1+CreatorLen+1+groupNameLen])

	idx := 1 + CreatorLen + 1 + groupNameLen
	if len(p.Body) <= idx {
		return
	}
	op := p.Body[idx]
	if op != UpdateAddUsers && op != UpdateRemoveUsers {
		return
	}
	if len(p.Body) <= idx+1 {
		return
	}
	userCount := int(p.Body[idx+1])

	offset := 1 + CreatorLen + 1 + groupNameLen + 1 + 1

	GrpMutex.Lock()
	group, exists := Groups[groupName]
	if !exists {
		GrpMutex.Unlock()
		return
	}
	GrpMutex.Unlock()

	for i := 0; i < userCount; i++ {
		if offset+FixedUsernameSize > len(p.Body) {
			return
		}
		raw := p.Body[offset : offset+FixedUsernameSize]
		offset += FixedUsernameSize

		username := string(bytes.TrimRight(raw, "\x00"))
		if username == "" {
			continue
		}

		GrpMutex.Lock()
		if op == UpdateAddUsers {
			group[username] = struct{}{}
		} else if op == UpdateRemoveUsers {
			delete(group, username)
		}
		GrpMutex.Unlock()
	}
	fmt.Printf("%s updated group %s\n", CreatorName, groupName)
}

const saveDir = "data_received"

// saveReceivedFile saves payload to saveDir (creating it if needed) with a unique name
// using getFileDetails. Returns the saved file path and any error.
func saveReceivedFile(payload []byte, sender, dir string) (path string, err error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	kind, ext := getFileDetails(payload)
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	safeSender := strings.ReplaceAll(sender, "@", "_")
	safeSender = strings.ReplaceAll(safeSender, " ", "_")
	filename := fmt.Sprintf("file_%s_%s_%s%s", safeSender, timestamp, kind, ext)
	path = filepath.Join(dir, filename)
	if err := os.WriteFile(path, payload, 0644); err != nil {
		return "", err
	}
	return path, nil
}

func handleBroadcast(p Packet) {
	if len(p.Body) < 1 {
		return
	}

	CreatorLen := int(p.Body[0])
	if CreatorLen > FixedUsernameSize {
		return
	}

	if len(p.Body) < 1+CreatorLen+1+4 {
		return
	}
	CreatorName := string(p.Body[1 : 1+CreatorLen])
	messagetype := p.Body[1+CreatorLen]

	msgLen := int(binary.BigEndian.Uint32(p.Body[1+CreatorLen+1 : 1+CreatorLen+1+4]))
	if len(p.Body) < 1+CreatorLen+1+4+msgLen {
		return
	}
	message := p.Body[1+CreatorLen+1+4 : 1+CreatorLen+1+4+msgLen]

	if messagetype == 1 {
		fmt.Printf("Broadcast from %s: %s\n", CreatorName, string(message))
	} else if messagetype == 2 {
		path, err := saveReceivedFile(message, CreatorName, saveDir)
		if err != nil {
			log.Println("Error saving file:", err)
			return
		}
		fmt.Printf("Broadcast message from %s, saved as %s\n", CreatorName, path)
	}
}

func handleSendGroupMessage(p Packet) {
	if len(p.Body) < 1 {
		return
	}
	creatorLen := int(p.Body[0])
	if len(p.Body) < 1+creatorLen+1 {
		return
	}
	creator := string(p.Body[1 : 1+creatorLen])

	groupNameLen := int(p.Body[1+creatorLen])
	if len(p.Body) < 1+creatorLen+1+groupNameLen+1+4 {
		return
	}
	groupName := string(p.Body[1+creatorLen+1 : 1+creatorLen+1+groupNameLen])
	messagetype := p.Body[1+creatorLen+1+groupNameLen]

	msgLen := int(binary.BigEndian.Uint32(p.Body[1+creatorLen+1+groupNameLen+1 : 1+creatorLen+1+groupNameLen+1+4]))
	if len(p.Body) < 1+creatorLen+1+groupNameLen+1+4+msgLen {
		return
	}
	message := p.Body[1+creatorLen+1+groupNameLen+1+4 : 1+creatorLen+1+groupNameLen+1+4+msgLen]

	if messagetype == 1 {
		fmt.Printf("%s : %s sent %s\n", groupName, creator, string(message))
	} else if messagetype == 2 {
		path, err := saveReceivedFile(message, creator, saveDir)
		if err != nil {
			log.Println("Error saving file:", err)
			return
		}
		fmt.Printf("Group message from %s, saved as %s\n", creator, path)
	}
}

func handlePrivateMessage(p Packet) {
	if len(p.Body) < 1 {
		return
	}
	senderLen := int(p.Body[0])
	if senderLen > FixedUsernameSize {
		return
	}
	if len(p.Body) < 1+senderLen+1+4 {
		return
	}
	sender := string(p.Body[1 : 1+senderLen])
	messagetype := p.Body[1+senderLen]
	msgLen := int(binary.BigEndian.Uint32(p.Body[1+senderLen+1 : 1+senderLen+1+4]))
	if len(p.Body) < 1+senderLen+1+4+msgLen {
		return
	}
	message := p.Body[1+senderLen+1+4 : 1+senderLen+1+4+msgLen]

	if messagetype == 1 {
		fmt.Printf("Private from %s: %s\n", sender, string(message))
	} else if messagetype == 2 {
		path, err := saveReceivedFile(message, sender, saveDir)
		if err != nil {
			log.Println("Error saving file:", err)
			return
		}
		fmt.Printf("Private message from %s, saved as %s\n", sender, path)
	}
}

func readmsg(conn net.Conn) {
	defer conn.Close()
	for {
		p, err := decode(conn)
		if err != nil {
			fmt.Println("Decode error:", err)
			return
		}

		switch p.Type {
		case TypeCreational:
			switch p.Action {
			case ActionCreateGroup:
				handleCreateGroup(p)
			case ActionUpdateGroup:
				handleUpdateGroup(p)
			default:
				fmt.Println("Invalid Creational Action")
			}

		case TypeMessaging:
			switch p.Action {
			case ActionBroadcastMsg:
				handleBroadcast(p)
			case ActionSendGroupMsg:
				handleSendGroupMessage(p)
			case ActionPrivateMsg:
				handlePrivateMessage(p)
			default:
				fmt.Println("Invalid Messaging Action")
			}

		}
	}
}
