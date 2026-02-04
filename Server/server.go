package main

import (
	"common"
	"crypto/rand"
	"io"
	"log"
	"net"
	"sync"
)

type User struct {
	ID           [common.IDSize]byte
	Username     string
	OfflineQueue []common.Packet
}

type Client struct {
	Conn     net.Conn
	UserID   [common.IDSize]byte
	Username string
}

type Conversation struct {
	ID      [common.IDSize]byte
	Name    string
	Members map[[common.IDSize]byte]struct{}
	IsGroup bool
}

type Server struct {
	mu        sync.RWMutex
	users     map[[common.IDSize]byte]*User
	usernames map[string][common.IDSize]byte
	clients   map[[common.IDSize]byte]*Client
	conns     map[net.Conn]*Client
	convs     map[[common.IDSize]byte]*Conversation
}

func NewServer() *Server {
	return &Server{
		users:     make(map[[common.IDSize]byte]*User),
		usernames: make(map[string][common.IDSize]byte),
		clients:   make(map[[common.IDSize]byte]*Client),
		conns:     make(map[net.Conn]*Client),
		convs:     make(map[[common.IDSize]byte]*Conversation),
	}
}

func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("Server listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer s.removeConnection(conn)

	p, err := common.Decode(conn)
	if err != nil {
		log.Printf("Handshake decode error: %v", err)
		return
	}

	if p.Header.MsgType != common.CtrlLogin {
		log.Printf("Expected CtrlLogin, got %d", p.Header.MsgType)
		return
	}

	username := string(p.Body)
	log.Printf("Login request from: %s", username)

	userID := s.getOrCreateUser(username)
	client := &Client{
		Conn:     conn,
		UserID:   userID,
		Username: username,
	}

	s.addConnection(conn, client)

	ack := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlLoginAck,
			BodyLen: common.IDSize,
		},
		Body: userID[:],
	}
	if err := ack.Encode(conn); err != nil {
		return
	}

	s.flushOfflineQueue(userID, conn)

	for {
		p, err := common.Decode(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error for %s: %v", username, err)
			}
			break
		}
		p.Header.SenderID = userID
		s.handlePacket(client, p)
	}
}

func (s *Server) handlePacket(sender *Client, p common.Packet) {
	switch p.Header.MsgType {
	case common.CtrlGroupCreate:
		s.handleGroupCreate(sender, p)
	case common.CtrlDirectInit:
		s.handleDirectInit(sender, p)
	case common.MsgText, common.MsgFileMeta, common.MsgFileChunk:
		s.handleData(sender, p)
	default:
		log.Printf("Unknown MsgType: %d", p.Header.MsgType)
	}
}

func (s *Server) handleData(sender *Client, p common.Packet) {
	convID := p.Header.ConversationID

	s.mu.RLock()
	conv, ok := s.convs[convID]
	s.mu.RUnlock()

	if !ok {
		return
	}

	for memberID := range conv.Members {
		if memberID == sender.UserID {
			continue
		}
		go s.sendPacket(memberID, p)
	}
}

func (s *Server) handleGroupCreate(sender *Client, p common.Packet) {
	if len(p.Body) < 2 {
		return
	}
	nameLen := int(p.Body[0])
	if len(p.Body) < 1+nameLen+1 {
		return
	}
	groupName := string(p.Body[1 : 1+nameLen])
	memberCount := int(p.Body[1+nameLen])
	offset := 1 + nameLen + 1

	members := make([][common.IDSize]byte, 0, memberCount+1)
	members = append(members, sender.UserID)

	for i := 0; i < memberCount; i++ {
		if offset >= len(p.Body) {
			break
		}
		if offset+1 > len(p.Body) {
			break
		}
		mLen := int(p.Body[offset])
		offset++
		if offset+mLen > len(p.Body) {
			break
		}
		mName := string(p.Body[offset : offset+mLen])
		offset += mLen

		mID := s.getOrCreateUser(mName)
		members = append(members, mID)
	}

	convID := genID()
	conv := &Conversation{
		ID:      convID,
		Name:    groupName,
		Members: make(map[[common.IDSize]byte]struct{}),
		IsGroup: true,
	}
	for _, m := range members {
		conv.Members[m] = struct{}{}
	}

	s.mu.Lock()
	s.convs[convID] = conv
	s.mu.Unlock()

	log.Printf("Created Group %s (%x) with %d members", groupName, convID, len(members))

	respBody := make([]byte, 0)
	respBody = append(respBody, convID[:]...)
	respBody = append(respBody, byte(len(groupName)))
	respBody = append(respBody, []byte(groupName)...)

	respBody = append(respBody, byte(len(members)))
	for _, mID := range members {
		var mName string
		s.mu.RLock()
		if u, ok := s.users[mID]; ok {
			mName = u.Username
		} else if c, ok := s.clients[mID]; ok {
			mName = c.Username
		}
		s.mu.RUnlock()

		respBody = append(respBody, mID[:]...)
		respBody = append(respBody, byte(len(mName)))
		respBody = append(respBody, []byte(mName)...)
	}

	respHeader := common.Header{
		MsgType:        common.CtrlGroupCreate,
		ConversationID: convID,
		BodyLen:        uint32(len(respBody)),
		SenderID:       sender.UserID,
	}

	pkt := common.Packet{Header: respHeader, Body: respBody}

	for _, m := range members {
		go s.sendPacket(m, pkt)
	}
}

func (s *Server) handleDirectInit(sender *Client, p common.Packet) {
	targetName := string(p.Body)
	targetID := s.getOrCreateUser(targetName)

	s.mu.Lock()
	var foundID [16]byte
	found := false

	for id, c := range s.convs {
		if !c.IsGroup && len(c.Members) == 2 {
			_, hasSender := c.Members[sender.UserID]
			_, hasTarget := c.Members[targetID]
			if hasSender && hasTarget {
				foundID = id
				found = true
				break
			}
		}
	}

	if !found {
		foundID = genID()
		conv := &Conversation{
			ID:      foundID,
			Members: make(map[[common.IDSize]byte]struct{}),
			IsGroup: false,
		}
		conv.Members[sender.UserID] = struct{}{}
		conv.Members[targetID] = struct{}{}
		s.convs[foundID] = conv
	}
	s.mu.Unlock()

	ack := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlDirectAck,
			ConversationID: foundID,
			BodyLen:        16,
		},
		Body: foundID[:],
	}
	s.sendPacket(sender.UserID, ack)

	notifyBody := []byte(sender.Username)
	notify := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlDirectInit,
			ConversationID: foundID,
			BodyLen:        uint32(len(notifyBody)),
			SenderID:       sender.UserID,
		},
		Body: notifyBody,
	}
	s.sendPacket(targetID, notify)
}

func (s *Server) sendPacket(userID [common.IDSize]byte, p common.Packet) {
	s.mu.Lock()
	client, ok := s.clients[userID]
	if ok {
		s.mu.Unlock()
		if err := p.Encode(client.Conn); err != nil {
			log.Printf("Send error to %x: %v", userID, err)
		}
	} else {
		user, exists := s.users[userID]
		if exists {
			user.OfflineQueue = append(user.OfflineQueue, p)
		}
		s.mu.Unlock()
	}
}

func (s *Server) flushOfflineQueue(userID [common.IDSize]byte, conn net.Conn) {
	s.mu.Lock()
	user, ok := s.users[userID]
	if !ok || len(user.OfflineQueue) == 0 {
		s.mu.Unlock()
		return
	}
	queue := user.OfflineQueue
	user.OfflineQueue = nil
	s.mu.Unlock()

	for _, p := range queue {
		p.Encode(conn)
	}
}

func (s *Server) getOrCreateUser(username string) [common.IDSize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id, ok := s.usernames[username]; ok {
		return id
	}

	id := genID()
	s.usernames[username] = id
	s.users[id] = &User{
		ID:           id,
		Username:     username,
		OfflineQueue: make([]common.Packet, 0),
	}
	return id
}

func (s *Server) addConnection(conn net.Conn, client *Client) {
	s.mu.Lock()
	s.clients[client.UserID] = client
	s.conns[conn] = client
	s.mu.Unlock()
}

func (s *Server) removeConnection(conn net.Conn) {
	s.mu.Lock()
	if client, ok := s.conns[conn]; ok {
		delete(s.conns, conn)
		delete(s.clients, client.UserID)
	}
	s.mu.Unlock()
}

func genID() [16]byte {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		panic(err)
	}
	return id
}

func main() {
	srv := NewServer()
	if err := srv.Start(":8080"); err != nil {
		log.Fatal(err)
	}
}
