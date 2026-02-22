package main

import (
	common "common"
	"crypto/rand"
	"io"
	"log"
	"net"
	"sync"
)

type User struct {
	ID          [common.IDSize]byte
	Username    string
	IdentityKey [32]byte
	// OfflineQueue stores packets destined for this user while they were offline.
	OfflineQueue []common.Packet
}

type Client struct {
	Conn     net.Conn
	UserID   [common.IDSize]byte
	Username string
	// mu protects concurrent writes to Conn
	mu sync.Mutex
}

type Conversation struct {
	ID      [common.IDSize]byte
	Name    string
	Admins  map[[common.IDSize]byte]struct{}
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

	if len(p.Body) < 32 {
		log.Printf("Login payload too short")
		return
	}

	var pubKey [32]byte
	copy(pubKey[:], p.Body[:32])
	username := string(p.Body[32:])
	log.Printf("Login: %s", username)

	userID := s.getOrCreateUser(username, pubKey)
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
	// Initial ACK doesn't need client mutex because we just created client
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
	case common.CtrlGroupAdd:
		s.handleGroupAdd(sender, p)
	case common.CtrlGroupRemove:
		s.handleGroupRemove(sender, p)
	case common.CtrlGroupMakeAdmin:
		s.handleGroupMakeAdmin(sender, p)
	case common.CtrlGroupRemoveAdmin:
		s.handleGroupRemoveAdmin(sender, p)
	case common.CtrlDirectInit:
		s.handleDirectInit(sender, p)
	case common.CtrlPubRq:
		s.handlePubRq(sender, p)
	case common.MsgText, common.MsgFileMeta, common.MsgFileChunk, common.MsgControl, common.CtrlGroupKeyUpdate, common.CtrlGroupKeyUpdateAck:
		s.handleData(sender, p)
	default:
		log.Printf("Unknown MsgType: %d", p.Header.MsgType)
	}
}

func (s *Server) handleGroupAdd(sender *Client, p common.Packet) {
	if len(p.Body) < 17 {
		return
	}
	var convID [16]byte
	copy(convID[:], p.Body[:16])

	s.mu.Lock()
	conv, ok := s.convs[convID]
	s.mu.Unlock()

	if !ok {
		return
	}

	s.mu.RLock()
	_, isAdmin := conv.Admins[sender.UserID]
	s.mu.RUnlock()

	if !isAdmin {
		log.Printf("[WARNING] Unauthorized CtrlGroupAdd from %x for group %x", sender.UserID[:4], convID[:4])
		return
	}

	offset := 16
	uLen := int(p.Body[offset])
	offset++
	if len(p.Body) < offset+uLen {
		return
	}
	targetName := string(p.Body[offset : offset+uLen])

	s.mu.RLock()
	targetID, idExists := s.usernames[targetName]
	var targetUser *User
	if idExists {
		targetUser = s.users[targetID]
	}
	s.mu.RUnlock()

	if !idExists || targetUser.IdentityKey == [32]byte{} {
		log.Printf("[WARNING] Cannot add unregistered user %s to group", targetName)
		return
	}

	s.mu.Lock()
	if _, exists := conv.Members[targetID]; exists {
		s.mu.Unlock()
		return
	}
	conv.Members[targetID] = struct{}{}
	s.mu.Unlock()

	respBody := make([]byte, 0)
	respBody = append(respBody, convID[:]...)
	respBody = append(respBody, byte(len(conv.Name)))
	respBody = append(respBody, []byte(conv.Name)...)
	respBody = append(respBody, targetID[:]...)
	respBody = append(respBody, byte(len(targetName)))
	respBody = append(respBody, []byte(targetName)...)

	resp := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlGroupAdd,
			ConversationID: convID,
			SenderID:       sender.UserID,
			BodyLen:        uint32(len(respBody)),
		},
		Body: respBody,
	}

	s.mu.RLock()
	members := make([][16]byte, 0, len(conv.Members))
	for m := range conv.Members {
		members = append(members, m)
	}
	s.mu.RUnlock()

	for _, m := range members {
		s.sendPacket(m, resp)
	}
}

func (s *Server) handleGroupRemove(sender *Client, p common.Packet) {
	if len(p.Body) < 17 {
		return
	}
	var convID [16]byte
	copy(convID[:], p.Body[:16])

	s.mu.RLock()
	conv, ok := s.convs[convID]
	if !ok {
		s.mu.RUnlock()
		return
	}
	_, isAdmin := conv.Admins[sender.UserID]
	s.mu.RUnlock()

	if !isAdmin {
		log.Printf("[WARNING] Unauthorized CtrlGroupRemove from %x for group %x", sender.UserID[:4], convID[:4])
		return
	}

	offset := 16
	uLen := int(p.Body[offset])
	offset++
	if len(p.Body) < offset+uLen {
		return
	}
	targetName := string(p.Body[offset : offset+uLen])
	targetID := s.getOrCreateUser(targetName, [32]byte{})

	s.mu.Lock()
	if c, ok := s.convs[convID]; ok {
		delete(c.Members, targetID)
	}
	s.mu.Unlock()

	respBody := make([]byte, 0)
	respBody = append(respBody, convID[:]...)
	respBody = append(respBody, targetID[:]...)

	resp := common.Packet{
		Header: common.Header{
			MsgType:  common.CtrlGroupRemove,
			SenderID: sender.UserID,
			BodyLen:  uint32(len(respBody)),
		},
		Body: respBody,
	}

	s.mu.RLock()
	members := make([][16]byte, 0, len(conv.Members))
	for m := range conv.Members {
		members = append(members, m)
	}
	s.mu.RUnlock()

	for _, m := range members {
		s.sendPacket(m, resp)
	}
	s.sendPacket(targetID, resp)
}

func (s *Server) handleGroupMakeAdmin(sender *Client, p common.Packet) {
	if len(p.Body) < 17 {
		return
	}
	var convID [16]byte
	copy(convID[:], p.Body[:16])

	s.mu.RLock()
	conv, ok := s.convs[convID]
	if !ok {
		s.mu.RUnlock()
		return
	}
	_, isAdmin := conv.Admins[sender.UserID]
	s.mu.RUnlock()

	if !isAdmin {
		log.Printf("[WARNING] Unauthorized MakeAdmin from %x for group %x", sender.UserID[:4], convID[:4])
		return
	}

	offset := 16
	uLen := int(p.Body[offset])
	offset++
	if len(p.Body) < offset+uLen {
		return
	}
	targetName := string(p.Body[offset : offset+uLen])
	targetID := s.getOrCreateUser(targetName, [32]byte{})

	s.mu.Lock()
	if _, exists := conv.Members[targetID]; !exists {
		s.mu.Unlock()
		return
	}
	conv.Admins[targetID] = struct{}{}
	s.mu.Unlock()

	respBody := make([]byte, 16+16)
	copy(respBody[0:16], convID[:])
	copy(respBody[16:32], targetID[:])

	resp := common.Packet{
		Header: common.Header{
			MsgType:  common.CtrlGroupMakeAdmin,
			SenderID: sender.UserID,
			BodyLen:  uint32(len(respBody)),
		},
		Body: respBody,
	}

	s.mu.RLock()
	members := make([][16]byte, 0, len(conv.Members))
	for m := range conv.Members {
		members = append(members, m)
	}
	s.mu.RUnlock()

	for _, m := range members {
		s.sendPacket(m, resp)
	}
}

func (s *Server) handleGroupRemoveAdmin(sender *Client, p common.Packet) {
	if len(p.Body) < 17 {
		return
	}
	var convID [16]byte
	copy(convID[:], p.Body[:16])

	s.mu.RLock()
	conv, ok := s.convs[convID]
	if !ok {
		s.mu.RUnlock()
		return
	}
	_, isAdmin := conv.Admins[sender.UserID]
	s.mu.RUnlock()

	if !isAdmin {
		log.Printf("[WARNING] Unauthorized RemoveAdmin from %x for group %x", sender.UserID[:4], convID[:4])
		return
	}

	offset := 16
	uLen := int(p.Body[offset])
	offset++
	if len(p.Body) < offset+uLen {
		return
	}
	targetName := string(p.Body[offset : offset+uLen])
	targetID := s.getOrCreateUser(targetName, [32]byte{})

	s.mu.Lock()
	delete(conv.Admins, targetID)
	s.mu.Unlock()

	respBody := make([]byte, 16+16)
	copy(respBody[0:16], convID[:])
	copy(respBody[16:32], targetID[:])

	resp := common.Packet{
		Header: common.Header{
			MsgType:  common.CtrlGroupRemoveAdmin,
			SenderID: sender.UserID,
			BodyLen:  uint32(len(respBody)),
		},
		Body: respBody,
	}

	s.mu.RLock()
	members := make([][16]byte, 0, len(conv.Members))
	for m := range conv.Members {
		members = append(members, m)
	}
	s.mu.RUnlock()

	for _, m := range members {
		s.sendPacket(m, resp)
	}
}

func (s *Server) handleData(sender *Client, p common.Packet) {
	s.mu.RLock()
	conv, ok := s.convs[p.Header.ConversationID]
	s.mu.RUnlock()

	if !ok {
		log.Printf("[DEBUG] handleData: Dropped packet type %d for unknown conv %x", p.Header.MsgType, p.Header.ConversationID)
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
	if len(p.Body) < 1 {
		return
	}
	offset := 0
	nameLen := int(p.Body[offset])
	offset++
	if len(p.Body) < offset+nameLen+1 {
		return
	}
	groupName := string(p.Body[offset : offset+nameLen])
	offset += nameLen

	count := int(p.Body[offset])
	offset++

	memberIDs := make([][16]byte, 0)
	memberIDs = append(memberIDs, sender.UserID)

	for i := 0; i < count; i++ {
		if len(p.Body) < offset+1 {
			break
		}
		uLen := int(p.Body[offset])
		offset++
		if len(p.Body) < offset+uLen {
			break
		}
		uName := string(p.Body[offset : offset+uLen])
		offset += uLen

		s.mu.RLock()
		uid, idExists := s.usernames[uName]
		var user *User
		if idExists {
			user = s.users[uid]
		}
		s.mu.RUnlock()

		if !idExists || user.IdentityKey == [32]byte{} {
			log.Printf("[WARNING] Skipping unregistered user %s during group create", uName)
			continue
		}

		memberIDs = append(memberIDs, uid)
	}

	convID := genID()
	conv := &Conversation{
		ID:      convID,
		Name:    groupName,
		IsGroup: true,
		Admins:  make(map[[common.IDSize]byte]struct{}),
		Members: make(map[[common.IDSize]byte]struct{}),
	}
	for _, mid := range memberIDs {
		conv.Members[mid] = struct{}{}
	}
	conv.Admins[sender.UserID] = struct{}{}

	s.mu.Lock()
	s.convs[convID] = conv
	s.mu.Unlock()

	respBody := make([]byte, 0)
	respBody = append(respBody, convID[:]...)
	respBody = append(respBody, byte(len(groupName)))
	respBody = append(respBody, []byte(groupName)...)
	respBody = append(respBody, byte(len(conv.Members)))

	s.mu.RLock()
	for mID := range conv.Members {
		user := s.users[mID]
		name := "Unknown"
		if user != nil {
			name = user.Username
		}
		respBody = append(respBody, mID[:]...)
		respBody = append(respBody, byte(len(name)))
		respBody = append(respBody, []byte(name)...)
	}
	s.mu.RUnlock()

	resp := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlGroupCreate,
			ConversationID: convID,
			SenderID:       sender.UserID,
			BodyLen:        uint32(len(respBody)),
		},
		Body: respBody,
	}

	for mID := range conv.Members {
		s.sendPacket(mID, resp)
	}
}

func (s *Server) handleDirectInit(sender *Client, p common.Packet) {
	targetName := string(p.Body)

	s.mu.RLock()
	targetID, idExists := s.usernames[targetName]
	var targetUser *User
	if idExists {
		targetUser = s.users[targetID]
	}
	s.mu.RUnlock()

	if !idExists || targetUser.IdentityKey == [32]byte{} {
		log.Printf("[WARNING] Cannot init direct with unregistered user %s", targetName)
		return
	}
	convID := common.HashIDs(sender.UserID, targetID)

	log.Printf("[DEBUG] handleDirectInit: %s (%x) -> %s (%x). ConvID: %x", sender.Username, sender.UserID, targetName, targetID, convID)

	s.mu.Lock()
	_, exists := s.convs[convID]
	if !exists {
		conv := &Conversation{
			ID:      convID,
			Members: make(map[[common.IDSize]byte]struct{}),
			Admins:  make(map[[common.IDSize]byte]struct{}),
			IsGroup: false,
		}
		conv.Members[sender.UserID] = struct{}{}
		conv.Members[targetID] = struct{}{}
		s.convs[convID] = conv
	}

	var targetPubKey [32]byte
	if u, ok := s.users[targetID]; ok {
		targetPubKey = u.IdentityKey
	}

	var senderPubKey [32]byte
	if u, ok := s.users[sender.UserID]; ok {
		senderPubKey = u.IdentityKey
	}
	s.mu.Unlock()

	ackBody := make([]byte, 0, 16+32)
	ackBody = append(ackBody, convID[:]...)
	ackBody = append(ackBody, targetPubKey[:]...)

	ack := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlDirectAck,
			ConversationID: convID,
			BodyLen:        uint32(len(ackBody)),
		},
		Body: ackBody,
	}
	s.sendPacket(sender.UserID, ack)

	notifyBody := make([]byte, 0, 16+32+len(sender.Username))
	notifyBody = append(notifyBody, convID[:]...)
	notifyBody = append(notifyBody, senderPubKey[:]...)
	notifyBody = append(notifyBody, []byte(sender.Username)...)

	notify := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlDirectInit,
			ConversationID: convID,
			BodyLen:        uint32(len(notifyBody)),
			SenderID:       sender.UserID,
		},
		Body: notifyBody,
	}
	s.sendPacket(targetID, notify)
}

func (s *Server) handlePubRq(sender *Client, p common.Packet) {
	if len(p.Body) < 16 {
		return
	}
	var targetID [16]byte
	copy(targetID[:], p.Body[:16])

	s.mu.RLock()
	user, exists := s.users[targetID]
	s.mu.RUnlock()

	if !exists {
		return
	}

	respBody := make([]byte, 16+32)
	copy(respBody[0:16], targetID[:])
	copy(respBody[16:48], user.IdentityKey[:])

	resp := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlPubAck,
			ConversationID: p.Header.ConversationID,
			SenderID:       [16]byte{},
			BodyLen:        uint32(len(respBody)),
		},
		Body: respBody,
	}
	s.sendPacket(sender.UserID, resp)
}

func (s *Server) sendPacket(userID [common.IDSize]byte, p common.Packet) {
	s.mu.Lock()
	client, ok := s.clients[userID]
	s.mu.Unlock()

	if ok {
		client.mu.Lock()
		defer client.mu.Unlock()

		if err := p.Encode(client.Conn); err != nil {
			log.Printf("Send error to %x: %v", userID, err)
		}
	} else {
		s.mu.Lock()
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

func (s *Server) getOrCreateUser(username string, pubKey [32]byte) [common.IDSize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	zero := [32]byte{}

	if id, ok := s.usernames[username]; ok {
		if u, exists := s.users[id]; exists {
			if pubKey != zero && u.IdentityKey != pubKey {
				u.IdentityKey = pubKey
			}
		}
		return id
	}

	id := genID()
	s.usernames[username] = id
	s.users[id] = &User{
		ID:           id,
		Username:     username,
		IdentityKey:  pubKey,
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
