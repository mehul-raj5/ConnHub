package main

import (
	common "common"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type User struct {
	ID          [common.IDSize]byte
	Username    string
	IdentityKey [32]byte

	OfflineQueue []common.Packet
}

// sendBufferSize bounds how far a recipient may fall behind before the server
// treats it as a stalled consumer. writeTimeout bounds a single socket write so
// a wedged peer cannot park the write loop forever.
const (
	sendBufferSize  = 128
	writeTimeout    = 10 * time.Second
	maxOfflineQueue = 512
)

// Client owns one connection. Exactly one goroutine (writeLoop) ever writes to
// Conn, so packets are framed in order and no write lock is needed. Producers
// hand packets over via enqueue, which never blocks.
type Client struct {
	Conn     net.Conn
	UserID   [common.IDSize]byte
	Username string

	send      chan common.Packet
	done      chan struct{}
	sendMu    sync.Mutex // guards closed; never held across I/O
	closed    bool
	closeOnce sync.Once
}

// enqueue queues p for delivery. It reports false if the connection is closing
// or the peer has fallen sendBufferSize packets behind.
func (c *Client) enqueue(p common.Packet) bool {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.closed {
		return false
	}
	select {
	case c.send <- p:
		return true
	default:
		return false
	}
}

// close tears the connection down. Marking closed under sendMu before closing
// done guarantees no enqueue can land after a spill has drained the channel.
func (c *Client) close() {
	c.closeOnce.Do(func() {
		c.sendMu.Lock()
		c.closed = true
		c.sendMu.Unlock()
		close(c.done)
		c.Conn.Close()
	})
}

type Conversation struct {
	ID      [common.IDSize]byte
	Name    string
	Admins  map[[common.IDSize]byte]struct{}
	Members [][common.IDSize]byte
	IsGroup bool
}

func (c *Conversation) HasMember(id [common.IDSize]byte) bool {
	for _, m := range c.Members {
		if m == id {
			return true
		}
	}
	return false
}

func (c *Conversation) RemoveMember(id [common.IDSize]byte) {
	for i, m := range c.Members {
		if m == id {
			c.Members = append(c.Members[:i], c.Members[i+1:]...)
			return
		}
	}
}

type Server struct {
	mu        sync.RWMutex
	users     map[[common.IDSize]byte]*User
	usernames map[string][common.IDSize]byte
	clients   map[[common.IDSize]byte]*Client
	conns     map[net.Conn]*Client
	convs     map[[common.IDSize]byte]*Conversation
	media     SupabaseConfig
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

	userID, err := s.authenticateUser(username, pubKey)
	if err != nil {
		log.Printf("Login rejected for %s: %v", username, err)
		errPkt := common.Packet{
			Header: common.Header{
				MsgType: common.CtrlError,
				BodyLen: 0,
			},
		}
		errPkt.Encode(conn)
		return
	}

	client := &Client{
		Conn:     conn,
		UserID:   userID,
		Username: username,
		send:     make(chan common.Packet, sendBufferSize),
		done:     make(chan struct{}),
	}
	defer client.close()

	ack := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlLoginAck,
			BodyLen: common.IDSize,
		},
		Body: userID[:],
	}

	// Written inline: the write loop has not started and the client is not yet
	// registered, so nothing else can be writing to this socket.
	if err := ack.Encode(conn); err != nil {
		return
	}

	s.addConnection(conn, client)
	go s.writeLoop(client)

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
	case common.CtrlUploadRq:
		s.handleUploadRq(sender, p)
	case common.CtrlDownloadRq:
		s.handleDownloadRq(sender, p)
	case common.MsgText, common.MsgMediaMeta, common.MsgControl, common.CtrlGroupKeyUpdate, common.CtrlGroupKeyUpdateAck:
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
	if conv.HasMember(targetID) {
		s.mu.Unlock()
		return
	}
	conv.Members = append(conv.Members, targetID)
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

	syncBody := make([]byte, 0)
	syncBody = append(syncBody, convID[:]...)
	syncBody = append(syncBody, byte(len(conv.Name)))
	syncBody = append(syncBody, []byte(conv.Name)...)

	s.mu.RLock()
	syncBody = append(syncBody, byte(len(conv.Members)))
	for _, mID := range conv.Members {
		user := s.users[mID]
		name := "Unknown"
		if user != nil {
			name = user.Username
		}
		syncBody = append(syncBody, mID[:]...)
		syncBody = append(syncBody, byte(len(name)))
		syncBody = append(syncBody, []byte(name)...)
	}
	var adminsList [][16]byte
	for aID := range conv.Admins {
		if aID != sender.UserID {
			adminsList = append(adminsList, aID)
		}
	}
	members := make([][16]byte, 0, len(conv.Members))
	members = append(members, conv.Members...)
	s.mu.RUnlock()

	syncResp := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlGroupCreate,
			ConversationID: convID,
			SenderID:       sender.UserID,
			BodyLen:        uint32(len(syncBody)),
		},
		Body: syncBody,
	}

	for _, m := range members {
		if m == targetID {
			s.sendPacket(m, syncResp)

			for _, aID := range adminsList {
				adminRespBody := make([]byte, 32)
				copy(adminRespBody[0:16], convID[:])
				copy(adminRespBody[16:32], aID[:])

				aResp := common.Packet{
					Header: common.Header{
						MsgType:  common.CtrlGroupMakeAdmin,
						SenderID: sender.UserID,
						BodyLen:  32,
					},
					Body: adminRespBody,
				}
				s.sendPacket(targetID, aResp)
			}
		} else {
			s.sendPacket(m, resp)
		}
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
	isMember := conv.HasMember(sender.UserID)
	s.mu.RUnlock()

	if !isMember {
		log.Printf("[WARNING] CtrlGroupRemove from non-member %x for group %x", sender.UserID[:4], convID[:4])
		return
	}

	offset := 16
	uLen := int(p.Body[offset])
	offset++
	if len(p.Body) < offset+uLen {
		return
	}
	targetName := string(p.Body[offset : offset+uLen])
	targetID, ok := s.getUserIDByName(targetName)
	if !ok {
		return
	}

	// The initiator is sender.UserID, which the server stamps on every packet,
	// so it cannot be spoofed by the client. A member may always remove
	// themselves (leaving the group); removing anyone else requires admin.
	if targetID != sender.UserID && !isAdmin {
		log.Printf("[WARNING] Unauthorized CtrlGroupRemove from %x targeting %x in group %x",
			sender.UserID[:4], targetID[:4], convID[:4])
		return
	}

	s.mu.Lock()
	if c, ok := s.convs[convID]; ok {
		c.RemoveMember(targetID)
		wasAdmin := false
		if _, ok := c.Admins[targetID]; ok {
			delete(c.Admins, targetID)
			wasAdmin = true
		}
		if wasAdmin && len(c.Admins) == 0 && len(c.Members) > 0 {
			newAdmin := c.Members[0]
			c.Admins[newAdmin] = struct{}{}
			go s.broadcastMakeAdmin(convID, newAdmin)
		}
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
	members = append(members, conv.Members...)
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
	targetID, ok := s.getUserIDByName(targetName)
	if !ok {
		return
	}

	s.mu.Lock()
	if !conv.HasMember(targetID) {
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
	members = append(members, conv.Members...)
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
	targetID, ok := s.getUserIDByName(targetName)
	if !ok {
		return
	}

	// Checked and mutated in one critical section so two concurrent demotions
	// cannot both pass the last-admin guard and leave the group unmanageable.
	s.mu.Lock()
	if _, isTargetAdmin := conv.Admins[targetID]; !isTargetAdmin {
		s.mu.Unlock()
		return
	}
	if len(conv.Admins) <= 1 {
		s.mu.Unlock()
		log.Printf("[WARNING] Refusing to demote %x: last admin of group %x", targetID[:4], convID[:4])
		return
	}
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
	members = append(members, conv.Members...)
	s.mu.RUnlock()

	for _, m := range members {
		s.sendPacket(m, resp)
	}
}

func (s *Server) handleData(sender *Client, p common.Packet) {
	s.mu.RLock()
	conv, ok := s.convs[p.Header.ConversationID]
	var isMember bool
	var members [][common.IDSize]byte
	if ok {
		members = append(members, conv.Members...)
		isMember = conv.HasMember(sender.UserID)
	}
	s.mu.RUnlock()

	if !ok {
		log.Printf("[DEBUG] handleData: Dropped packet type %d for unknown conv %x", p.Header.MsgType, p.Header.ConversationID)
		return
	}

	if !isMember {
		log.Printf("[WARNING] handleData: non-member %x sent to conv %x", sender.UserID[:4], p.Header.ConversationID[:4])
		return
	}

	// members is a snapshot taken under the read lock; enqueue never blocks, so
	// the fan-out runs inline rather than spawning a goroutine per recipient.
	for _, memberID := range members {
		if memberID == sender.UserID {
			continue
		}
		s.sendPacket(memberID, p)
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
		Members: make([][common.IDSize]byte, 0),
	}
	for _, mid := range memberIDs {
		if !conv.HasMember(mid) {
			conv.Members = append(conv.Members, mid)
		}
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
	for _, mID := range conv.Members {
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

	for _, mID := range conv.Members {
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
			Members: make([][common.IDSize]byte, 0),
			Admins:  make(map[[common.IDSize]byte]struct{}),
			IsGroup: false,
		}
		conv.Members = append(conv.Members, sender.UserID)
		conv.Members = append(conv.Members, targetID)
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

// isMember reports whether userID belongs to the conversation convID.
func (s *Server) isMember(convID, userID [common.IDSize]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conv, ok := s.convs[convID]
	if !ok {
		return false
	}
	return conv.HasMember(userID)
}

// mediaAck builds a reply that echoes the request's MessageID so the client can
// correlate it. An empty body signals failure to the client.
func mediaAck(msgType uint8, req common.Packet, body []byte) common.Packet {
	return common.Packet{
		Header: common.Header{
			MsgType:        msgType,
			MessageID:      req.Header.MessageID,
			ConversationID: req.Header.ConversationID,
			BodyLen:        uint32(len(body)),
		},
		Body: body,
	}
}

// handleUploadRq mints a signed Supabase upload URL for a conversation member.
func (s *Server) handleUploadRq(sender *Client, p common.Packet) {
	if !s.media.Enabled() {
		log.Printf("[WARNING] CtrlUploadRq but media storage not configured")
		s.sendPacket(sender.UserID, mediaAck(common.CtrlUploadAck, p, nil))
		return
	}
	if !s.isMember(p.Header.ConversationID, sender.UserID) {
		log.Printf("[WARNING] CtrlUploadRq from non-member %x for conv %x", sender.UserID[:4], p.Header.ConversationID[:4])
		s.sendPacket(sender.UserID, mediaAck(common.CtrlUploadAck, p, nil))
		return
	}

	var rnd [16]byte
	rand.Read(rnd[:])
	objectPath := fmt.Sprintf("%x/%x", p.Header.ConversationID[:], rnd[:])

	url, err := s.media.SignUpload(objectPath)
	if err != nil {
		log.Printf("[ERROR] SignUpload: %v", err)
		s.sendPacket(sender.UserID, mediaAck(common.CtrlUploadAck, p, nil))
		return
	}

	body := common.EncodeSignedURLPayload(objectPath, url)
	s.sendPacket(sender.UserID, mediaAck(common.CtrlUploadAck, p, body))
}

// handleDownloadRq mints a signed Supabase download URL, but only for objects
// that belong to a conversation the requester is a member of.
func (s *Server) handleDownloadRq(sender *Client, p common.Packet) {
	if !s.media.Enabled() {
		s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, nil))
		return
	}
	strs, err := common.DecodeSignedURLPayload(p.Body, 1)
	if err != nil {
		s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, nil))
		return
	}
	objectPath := strs[0]

	// The object path is "<convIDhex>/<random>"; require the requester to both
	// name that conversation and be a member of it.
	prefix := fmt.Sprintf("%x/", p.Header.ConversationID[:])
	if !strings.HasPrefix(objectPath, prefix) || !s.isMember(p.Header.ConversationID, sender.UserID) {
		log.Printf("[WARNING] CtrlDownloadRq from %x for foreign object %q", sender.UserID[:4], objectPath)
		s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, nil))
		return
	}

	url, err := s.media.SignDownload(objectPath, 3600)
	if err != nil {
		log.Printf("[ERROR] SignDownload: %v", err)
		s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, nil))
		return
	}

	body := common.EncodeSignedURLPayload(url)
	s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, body))
}

// writeLoop is the sole writer for one connection. It first drains whatever
// accumulated while the user was offline, then serves live traffic. On any
// write failure it tears the connection down and spills the backlog back onto
// the offline queue so nothing is silently dropped.
func (s *Server) writeLoop(c *Client) {
	defer func() {
		c.close()
		s.spill(c)
	}()

	for _, p := range s.takeOfflineQueue(c.UserID) {
		if !s.writePacket(c, p) {
			return
		}
	}

	for {
		select {
		case p := <-c.send:
			if !s.writePacket(c, p) {
				return
			}
		case <-c.done:
			return
		}
	}
}

// writePacket performs one bounded socket write. A false return means the
// connection is finished.
func (s *Server) writePacket(c *Client, p common.Packet) bool {
	c.Conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := p.Encode(c.Conn); err != nil {
		log.Printf("[WARNING] Write to %s (%x) failed: %v", c.Username, c.UserID[:4], err)
		s.queueOffline(c.UserID, p)
		return false
	}
	return true
}

// spill moves anything still queued for a dead connection onto the offline
// queue. Safe because close() marks the client closed before this runs, so no
// further enqueue can succeed.
func (s *Server) spill(c *Client) {
	for {
		select {
		case p := <-c.send:
			s.queueOffline(c.UserID, p)
		default:
			return
		}
	}
}

// queueOffline stores a packet for later delivery, capped at maxOfflineQueue
// packets per user; the oldest are discarded first.
func (s *Server) queueOffline(userID [common.IDSize]byte, p common.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return
	}
	if len(user.OfflineQueue) >= maxOfflineQueue {
		drop := len(user.OfflineQueue) - maxOfflineQueue + 1
		log.Printf("[WARNING] Offline queue full for %x, dropping %d oldest", userID[:4], drop)
		user.OfflineQueue = append(user.OfflineQueue[:0], user.OfflineQueue[drop:]...)
	}
	user.OfflineQueue = append(user.OfflineQueue, p)
}

func (s *Server) sendPacket(userID [common.IDSize]byte, p common.Packet) {
	s.mu.RLock()
	client, ok := s.clients[userID]
	s.mu.RUnlock()

	if !ok {
		s.queueOffline(userID, p)
		return
	}

	if !client.enqueue(p) {
		log.Printf("[WARNING] %s (%x) is not keeping up; disconnecting", client.Username, userID[:4])
		client.close() // its writeLoop spills the rest
		s.queueOffline(userID, p)
	}
}

// takeOfflineQueue atomically removes and returns a user's queued packets.
func (s *Server) takeOfflineQueue(userID [common.IDSize]byte) []common.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok || len(user.OfflineQueue) == 0 {
		return nil
	}
	queue := user.OfflineQueue
	user.OfflineQueue = nil
	return queue
}

func (s *Server) authenticateUser(username string, pubKey [32]byte) ([common.IDSize]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	zero := [32]byte{}

	if id, ok := s.usernames[username]; ok {
		if u, exists := s.users[id]; exists {
			if pubKey == zero {
				return [common.IDSize]byte{}, errors.New("not allowed")
			}
			if pubKey != zero && u.IdentityKey != pubKey {
				return [common.IDSize]byte{}, errors.New("username already taken")
			}
		}
		return id, nil
	}

	id := genID()
	s.usernames[username] = id
	s.users[id] = &User{
		ID:           id,
		Username:     username,
		IdentityKey:  pubKey,
		OfflineQueue: make([]common.Packet, 0),
	}
	return id, nil
}

func (s *Server) getUserIDByName(username string) ([common.IDSize]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usernames[username]
	return id, ok
}

func (s *Server) addConnection(conn net.Conn, client *Client) {
	s.mu.Lock()
	if oldClient, ok := s.clients[client.UserID]; ok {
		// Close the old connection to prevent ghost sessions
		oldClient.close()
		delete(s.conns, oldClient.Conn)
	}
	s.clients[client.UserID] = client
	s.conns[conn] = client
	s.mu.Unlock()
}

func (s *Server) removeConnection(conn net.Conn) {
	s.mu.Lock()
	if client, ok := s.conns[conn]; ok {
		delete(s.conns, conn)
		// Only delete from clients map if this connection is the currently active one
		// otherwise, we might be deleting a newly established connection (if old conn just closed)
		if activeClient, isClientOk := s.clients[client.UserID]; isClientOk && activeClient.Conn == conn {
			delete(s.clients, client.UserID)
		}
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

func (s *Server) broadcastMakeAdmin(convID, targetID [common.IDSize]byte) {
	respBody := make([]byte, 32)
	copy(respBody[0:16], convID[:])
	copy(respBody[16:32], targetID[:])
	resp := common.Packet{
		Header: common.Header{
			MsgType:  common.CtrlGroupMakeAdmin,
			SenderID: [16]byte{},
			BodyLen:  32,
		},
		Body: respBody,
	}
	s.mu.RLock()
	conv, ok := s.convs[convID]
	if !ok {
		s.mu.RUnlock()
		return
	}
	members := make([][16]byte, 0, len(conv.Members))
	members = append(members, conv.Members...)
	s.mu.RUnlock()
	for _, m := range members {
		s.sendPacket(m, resp)
	}
}

func main() {
	srv := NewServer()

	srv.media = SupabaseConfig{
		URL:        strings.TrimRight(os.Getenv("SUPABASE_URL"), "/"),
		ServiceKey: os.Getenv("SUPABASE_SERVICE_KEY"),
		Bucket:     os.Getenv("SUPABASE_BUCKET"),
	}
	if srv.media.Enabled() {
		log.Printf("Media storage enabled (bucket %q at %s)", srv.media.Bucket, srv.media.URL)
	} else {
		log.Printf("Media storage DISABLED: set SUPABASE_URL, SUPABASE_SERVICE_KEY, SUPABASE_BUCKET to enable")
	}

	if err := srv.Start(":8080"); err != nil {
		log.Fatal(err)
	}
}
