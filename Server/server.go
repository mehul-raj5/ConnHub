package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// packet types
const (
	TypeCreational uint8 = 1
	TypeMessaging  uint8 = 2
)

// limits
const (
	MaxGroupNameLen = 64
	MaxUsers        = 50
	MaxMessageLen   = 4096
	MaxBodyLen      = 8192
)

// actions
const (
	ActionAuth         uint8 = 0
	ActionCreateGroup  uint8 = 1
	ActionUpdateGroup  uint8 = 2
	ActionBroadcastMsg uint8 = 3
	ActionSendGroupMsg uint8 = 4
)

// update ops
const (
	UpdateAddUsers    uint8 = 1
	UpdateRemoveUsers uint8 = 2
)

const FixedUsernameSize = 32

var (
	stateMu     sync.RWMutex
	connections = make(map[net.Conn]string)
	UserConns   = make(map[string]net.Conn)
	ConnMutex   sync.Mutex
	GrpMutex    sync.Mutex
	ListGroups  = make(map[string]map[string]struct{})
)

type Packet struct {
	Type   uint8
	Action uint8
	Flags  uint8
	Body   []byte
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

func handleCreateGroup(conn net.Conn, pkt Packet) {
	ConnMutex.Lock()
	creator, ok := connections[conn]
	ConnMutex.Unlock()

	if !ok {
		return
	}
	if len(pkt.Body) < 2 {
		return
	}

	groupNameLen := int(pkt.Body[0])
	if len(pkt.Body) < 1+groupNameLen+1 {
		return
	}

	groupName := string(pkt.Body[1 : 1+groupNameLen])
	userCount := int(pkt.Body[1+groupNameLen])
	offset := 1 + groupNameLen + 1
	expected := offset + userCount*FixedUsernameSize

	if expected > len(pkt.Body) {
		return
	}

	log.Printf("User %s created group %s\n", creator, groupName)

	GrpMutex.Lock()
	if _, exists := ListGroups[groupName]; exists {
		GrpMutex.Unlock()
		return
	}
	ListGroups[groupName] = make(map[string]struct{})
	ListGroups[groupName][creator] = struct{}{}
	GrpMutex.Unlock()

	body := make([]byte, 0)
	body = append(body, byte(len(creator)))
	body = append(body, []byte(creator)...)
	body = append(body, pkt.Body...)

	for i := 0; i < userCount; i++ {
		if offset+FixedUsernameSize > len(pkt.Body) {
			break
		}
		raw := pkt.Body[offset : offset+FixedUsernameSize]
		offset += FixedUsernameSize
		username := string(bytes.TrimRight(raw, "\x00"))

		if username == "" {
			continue
		}

		GrpMutex.Lock()
		ListGroups[groupName][username] = struct{}{}
		GrpMutex.Unlock()
	}

	resp := Packet{
		Type:   TypeCreational,
		Action: ActionCreateGroup,
		Flags:  0,
		Body:   body,
	}

	encoded, err := encode(resp)
	if err != nil {
		return
	}

	GrpMutex.Lock()
	groupMembers := make([]string, 0, len(ListGroups[groupName]))
	for member := range ListGroups[groupName] {
		groupMembers = append(groupMembers, member)
	}
	GrpMutex.Unlock()

	for _, member := range groupMembers {
		ConnMutex.Lock()
		c := UserConns[member]
		ConnMutex.Unlock()
		if c != nil {
			c.Write(encoded)
		}
	}
}

func handleUpdateGroup(conn net.Conn, p Packet) {
	ConnMutex.Lock()
	creator, ok := connections[conn]
	ConnMutex.Unlock()

	if !ok {
		return
	}
	if len(p.Body) < 2 {
		return
	}

	groupNameLen := int(p.Body[0])
	if len(p.Body) < 1+groupNameLen+1 {
		return
	}

	GroupName := string(p.Body[1 : 1+groupNameLen])
	op := uint8(p.Body[1+groupNameLen])
	userCount := int(p.Body[1+groupNameLen+1])
	offset := 1 + groupNameLen + 1 + 1

	for i := 0; i < userCount; i++ {
		if offset+FixedUsernameSize > len(p.Body) {
			break
		}
		raw := p.Body[offset : offset+FixedUsernameSize]
		offset += FixedUsernameSize
		username := string(bytes.TrimRight(raw, "\x00"))

		if username == "" {
			continue
		}

		GrpMutex.Lock()
		group, exists := ListGroups[GroupName]
		if !exists {
			GrpMutex.Unlock()
			return
		}

		if op == UpdateAddUsers {
			group[username] = struct{}{}
		} else {
			delete(ListGroups[GroupName], username)
		}
		GrpMutex.Unlock()
	}

	buff := make([]byte, 0)
	buff = append(buff, byte(len(creator)))
	buff = append(buff, []byte(creator)...)
	buff = append(buff, p.Body...)

	resp := Packet{
		Type:   TypeCreational,
		Action: ActionUpdateGroup,
		Flags:  0,
		Body:   buff,
	}

	encoded, err := encode(resp)
	if err != nil {
		return
	}

	GrpMutex.Lock()
	groupMembers := make([]string, 0, len(ListGroups[GroupName]))
	for member := range ListGroups[GroupName] {
		groupMembers = append(groupMembers, member)
	}
	GrpMutex.Unlock()

	for _, member := range groupMembers {
		ConnMutex.Lock()
		c := UserConns[member]
		ConnMutex.Unlock()
		if c != nil {
			c.Write(encoded)
		}
	}
	log.Printf("User %s just updated the group %s", creator, GroupName)
}

func handleBroadcastMessage(conn net.Conn, p Packet) {
	ConnMutex.Lock()
	creator, ok := connections[conn]
	ConnMutex.Unlock()

	if !ok {
		return
	}
	log.Printf("User %s broadcasted a message\n", creator)

	if len(p.Body) < 2 {
		return
	}

	messageLen := int(binary.BigEndian.Uint16(p.Body[0:2]))
	if len(p.Body) < 2+messageLen {
		return
	}
	message := string(p.Body[2 : 2+messageLen])

	body := make([]byte, 0)
	body = append(body, byte(len(creator)))
	body = append(body, []byte(creator)...)
	msgLen := make([]byte, 2)
	binary.BigEndian.PutUint16(msgLen, uint16(len(message)))
	body = append(body, msgLen...)
	body = append(body, []byte(message)...)

	resp := Packet{
		Type:   TypeMessaging,
		Action: ActionBroadcastMsg,
		Flags:  0,
		Body:   body,
	}

	encoded, err := encode(resp)
	if err != nil {
		return
	}

	ConnMutex.Lock()
	conns := make([]net.Conn, 0, len(connections))
	for c := range connections {
		conns = append(conns, c)
	}
	ConnMutex.Unlock()

	for _, c := range conns {
		if c != conn {
			c.Write(encoded)
		}
	}
}

func handleSendGroupMessage(conn net.Conn, p Packet) {
	ConnMutex.Lock()
	creator, ok := connections[conn]
	ConnMutex.Unlock()

	if !ok {
		return
	}
	if len(p.Body) < 1 {
		return
	}

	groupNameLen := int(p.Body[0])
	if len(p.Body) < 1+groupNameLen+2 {
		return
	}

	groupName := string(p.Body[1 : 1+groupNameLen])
	messageLen := int(binary.BigEndian.Uint16(p.Body[1+groupNameLen : 1+groupNameLen+2]))

	if len(p.Body) < 1+groupNameLen+2+messageLen {
		return
	}

	GrpMutex.Lock()
	members, exists := ListGroups[groupName]
	GrpMutex.Unlock()

	if !exists {
		return
	}

	body := make([]byte, 0)
	body = append(body, byte(len(creator)))
	body = append(body, []byte(creator)...)
	body = append(body, p.Body...)
	resp := Packet{
		Type:   TypeMessaging,
		Action: ActionSendGroupMsg,
		Flags:  0,
		Body:   body,
	}

	encoded, err := encode(resp)
	if err != nil {
		return
	}

	GrpMutex.Lock()
	groupMembers := make([]string, 0, len(members))
	for member := range members {
		groupMembers = append(groupMembers, member)
	}
	GrpMutex.Unlock()

	for _, member := range groupMembers {
		ConnMutex.Lock()
		c := UserConns[member]
		ConnMutex.Unlock()
		if c != nil && c != conn {
			c.Write(encoded)
		}
	}
	log.Printf("User %s sent message to group %s\n", creator, groupName)
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	p, err := decode(conn)
	if err != nil {
		log.Println("Decode error:", err)
		return
	}

	if p.Type != TypeCreational || p.Action != ActionAuth {
		return
	}

	if len(p.Body) < 1 {
		return
	}

	usernameLen := int(p.Body[0])
	if len(p.Body) < 1+usernameLen {
		return
	}

	username := string(p.Body[1 : 1+usernameLen])

	ConnMutex.Lock()
	connections[conn] = username
	UserConns[username] = conn
	ConnMutex.Unlock()

	log.Printf("User %s connected\n", username)
	for {
		packet, err := decode(conn)
		if err != nil {
			if err == io.EOF {
				log.Printf("Client %s disconnected\n", connections[conn])
			} else {
				log.Println("Decode error:", err)
			}
			ConnMutex.Lock()
			username := connections[conn]
			delete(connections, conn)
			delete(UserConns, username)
			ConnMutex.Unlock()
			return
		}

		switch packet.Type {
		case TypeCreational:
			switch packet.Action {
			case ActionCreateGroup:
				handleCreateGroup(conn, packet)
			case ActionUpdateGroup:
				handleUpdateGroup(conn, packet)
			default:
				log.Println("Invalid Creational Action")
			}
		case TypeMessaging:
			switch packet.Action {
			case ActionBroadcastMsg:
				handleBroadcastMessage(conn, packet)
			case ActionSendGroupMsg:
				handleSendGroupMessage(conn, packet)
			default:
				log.Println("Invalid Messaging Action")
			}
		default:
			log.Println("Invalid Packet Type")
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
		go handleClient(conn)
	}
}
