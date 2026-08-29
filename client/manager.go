package main

import (
	common "common"
	"fmt"
	"log"
	"sync"
	"time"
)

type ClientManager struct {
	UserID   [common.IDSize]byte
	Username string

	Conversations map[[common.IDSize]byte]ConversationInfo

	Usernames map[[common.IDSize]byte]string

	PublicKeys      map[[common.IDSize]byte][32]byte
	pendingRequests map[[common.IDSize]byte]chan struct{}

	// pendingURLs correlates a CtrlUpload/DownloadRq (keyed by the request's
	// MessageID) with the CtrlUpload/DownloadAck the server replies with.
	pendingURLs map[[common.IDSize]byte]chan []string

	mu sync.Mutex
}

type ConversationInfo struct {
	Name    string
	IsGroup bool
	Admins  map[[common.IDSize]byte]struct{}
	Members [][common.IDSize]byte
}

func NewClientManager(userID [common.IDSize]byte, username string) *ClientManager {
	log.Printf("[DEBUG] NewClientManager called with UserID: %x\n", userID)
	return &ClientManager{
		UserID:          userID,
		Username:        username,
		Conversations:   make(map[[common.IDSize]byte]ConversationInfo),
		Usernames:       make(map[[common.IDSize]byte]string),
		PublicKeys:      make(map[[common.IDSize]byte][32]byte),
		pendingRequests: make(map[[common.IDSize]byte]chan struct{}),
		pendingURLs:     make(map[[common.IDSize]byte]chan []string),
	}
}

// NewURLRequest registers a pending signed-URL request and returns the channel
// that DeliverURL will send the server's reply on.
func (m *ClientManager) NewURLRequest(reqID [common.IDSize]byte) chan []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := make(chan []string, 1)
	m.pendingURLs[reqID] = ch
	return ch
}

// DeliverURL hands the decoded ack strings (possibly nil on failure) to the
// waiting requester and clears the pending entry.
func (m *ClientManager) DeliverURL(reqID [common.IDSize]byte, strs []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, ok := m.pendingURLs[reqID]; ok {
		ch <- strs
		delete(m.pendingURLs, reqID)
	}
}

// CancelURLRequest drops a pending request that timed out.
func (m *ClientManager) CancelURLRequest(reqID [common.IDSize]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pendingURLs, reqID)
}

func (m *ClientManager) RegisterConversation(id [common.IDSize]byte, name string, isGroup bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Conversations[id] = ConversationInfo{
		Name:    name,
		IsGroup: isGroup,
		Admins:  make(map[[common.IDSize]byte]struct{}),
		Members: make([][common.IDSize]byte, 0),
	}
	tuiPrintf("[INFO] Conversation registered: %s", name)
}

func (m *ClientManager) SetGroupAdmin(id [common.IDSize]byte, userID [common.IDSize]byte, isAdmin bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[id]; ok {
		if isAdmin {
			info.Admins[userID] = struct{}{}
		} else {
			delete(info.Admins, userID)
		}
		m.Conversations[id] = info
	}
}

func (m *ClientManager) AddMemberToGroup(groupID, userID [common.IDSize]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[groupID]; ok {
		exists := false
		for _, id := range info.Members {
			if id == userID {
				exists = true
				break
			}
		}
		if !exists {
			info.Members = append(info.Members, userID)
			m.Conversations[groupID] = info
		}
	}
}

func (m *ClientManager) RemoveMemberFromGroup(groupID, userID [common.IDSize]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[groupID]; ok {
		for i, id := range info.Members {
			if id == userID {
				info.Members = append(info.Members[:i], info.Members[i+1:]...)
				m.Conversations[groupID] = info
				break
			}
		}
	}
}

func (m *ClientManager) GetGroupMembers(groupID [common.IDSize]byte) [][common.IDSize]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var members [][common.IDSize]byte
	if info, ok := m.Conversations[groupID]; ok {
		members = append(members, info.Members...)
	}
	return members
}

func (m *ClientManager) AddUser(id [common.IDSize]byte, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Usernames[id] = name
}

func (m *ClientManager) GetUsername(id [common.IDSize]byte) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if name, ok := m.Usernames[id]; ok {
		return name
	}
	return fmt.Sprintf("%x", id[:4])
}

func (m *ClientManager) GetConversationName(id [common.IDSize]byte) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[id]; ok {
		return info.Name
	}
	return fmt.Sprintf("%x", id[:4])
}

func (m *ClientManager) IsGroup(id [common.IDSize]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[id]; ok {
		return info.IsGroup
	}
	return false
}

func (m *ClientManager) IsGroupAdmin(id [common.IDSize]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[id]; ok {
		_, isAdmin := info.Admins[m.UserID]
		return isAdmin
	}
	return false
}

func (m *ClientManager) IsUserAdmin(groupID [common.IDSize]byte, userID [common.IDSize]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[groupID]; ok {
		_, isAdmin := info.Admins[userID]
		return isAdmin
	}
	return false
}

// RemoveConversation forgets a conversation entirely. Used when the local user
// leaves or is removed from a group.
func (m *ClientManager) RemoveConversation(id [common.IDSize]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Conversations, id)
}

func (m *ClientManager) GetPublicKey(userID [common.IDSize]byte, fetchFunc func()) ([32]byte, error) {
	m.mu.Lock()
	if key, ok := m.PublicKeys[userID]; ok {
		m.mu.Unlock()
		return key, nil
	}

	ch, pending := m.pendingRequests[userID]
	if !pending {
		ch = make(chan struct{})
		m.pendingRequests[userID] = ch
		m.mu.Unlock()
		fetchFunc()
		m.mu.Lock()
	}

	m.mu.Unlock()

	select {
	case <-ch:
		m.mu.Lock()
		defer m.mu.Unlock()
		if key, ok := m.PublicKeys[userID]; ok {
			return key, nil
		}
		return [32]byte{}, fmt.Errorf("public key not found after fetch")
	case <-time.After(5 * time.Second):
		m.mu.Lock()
		delete(m.pendingRequests, userID)
		m.mu.Unlock()
		return [32]byte{}, fmt.Errorf("timeout waiting for public key")
	}
}

func (m *ClientManager) UpdatePublicKey(userID [common.IDSize]byte, key [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PublicKeys[userID] = key

	if ch, ok := m.pendingRequests[userID]; ok {
		close(ch)
		delete(m.pendingRequests, userID)
	}
}
