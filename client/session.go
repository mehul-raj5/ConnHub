package main

import (
	common "common"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

type Session struct {
	ConversationID [16]byte
	RootKey        [32]byte

	SendChainKey [32]byte
	RecvChainKey [32]byte

	SendCount uint32
	RecvCount uint32

	// Skipped Keys for out-of-order messages: Map[SeqNum]MessageKey
	SkippedKeys map[uint32][32]byte

	CreatedAt time.Time
	mu        sync.Mutex
}

type GroupSession struct {
	GroupID        [16]byte
	CurrentKey     [32]byte
	CurrentVersion uint32
	MessageCounter uint32
	IsAdmin        bool
	Members        map[[16]byte]struct{}
	OldKeys        map[uint32][32]byte
	mu             sync.Mutex
}

type SessionManager struct {
	// sessions maps ConversationID to Session
	sessions      map[[16]byte]*Session
	groupSessions map[[16]byte]*GroupSession
	mu            sync.RWMutex
	identity      *IdentityManager
}

func NewSessionManager(idMgr *IdentityManager) *SessionManager {
	return &SessionManager{
		sessions:      make(map[[16]byte]*Session),
		groupSessions: make(map[[16]byte]*GroupSession),
		identity:      idMgr,
	}
}

func (sm *SessionManager) GetSession(convID [16]byte) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessions[convID]
	return sess, ok
}

// SaveSession stores a new session with initialized chains.
func (sm *SessionManager) SaveSession(convID [16]byte, sendKey, recvKey [32]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[convID] = &Session{
		ConversationID: convID,
		SendChainKey:   sendKey,
		RecvChainKey:   recvKey,
		SendCount:      0,
		RecvCount:      0,
		SkippedKeys:    make(map[uint32][32]byte),
		CreatedAt:      time.Now(),
	}

}

func (sm *SessionManager) PerformHandshake(convID [16]byte, peerPubKey [32]byte) (*common.Packet, error) {
	if peerPubKey == [32]byte{} {
		return nil, fmt.Errorf("peer public key is empty")
	}

	priv, pub, err := common.GenerateEphemeralKeys()
	if err != nil {
		return nil, err
	}

	secret, err := common.DeriveSharedSecret(priv, peerPubKey)
	if err != nil {
		return nil, err
	}

	rootA, rootB := common.DeriveRatchetRoots(secret)

	sm.SaveSession(convID, rootA, rootB)

	pkt := &common.Packet{
		Header: common.Header{
			MsgType:        common.MsgControl,
			ConversationID: convID,
			Flags:          common.FlagHandshake,
			BodyLen:        32,
		},
		Body: pub[:],
	}

	return pkt, nil
}

func (sm *SessionManager) HandleHandshake(p common.Packet) error {
	if len(p.Body) < 32 {
		return fmt.Errorf("handshake body too short")
	}

	var senderEphemeralPub [32]byte
	copy(senderEphemeralPub[:], p.Body[:32])

	secret, err := common.DeriveSharedSecret(sm.identity.PrivateKey, senderEphemeralPub)
	if err != nil {
		return err
	}

	rootA, rootB := common.DeriveRatchetRoots(secret)

	sm.SaveSession(p.Header.ConversationID, rootB, rootA)
	return nil
}

func (sm *SessionManager) EncryptPacket(pkt *common.Packet) error {
	session, ok := sm.GetSession(pkt.Header.ConversationID)
	if !ok {
		return fmt.Errorf("no secure session for conversation %x", pkt.Header.ConversationID[:4])
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	msgKey, nextChain := common.RatchetStep(session.SendChainKey)
	session.SendChainKey = nextChain

	expectedEncryptedLen := len(pkt.Body) + common.NonceSize + 16
	pkt.Header.BodyLen = uint32(4 + expectedEncryptedLen)
	pkt.Header.Flags |= common.FlagEncrypted

	headerBytes := pkt.Header.Bytes()

	encryptedBody, err := common.Encrypt(msgKey, pkt.Body, headerBytes)
	if err != nil {
		return err
	}

	finalPayload := make([]byte, 4+len(encryptedBody))
	binary.BigEndian.PutUint32(finalPayload[0:], session.SendCount)
	copy(finalPayload[4:], encryptedBody)

	pkt.Body = finalPayload

	session.SendCount++

	return nil
}

func (sm *SessionManager) DecryptPacket(pkt *common.Packet) error {
	if pkt.Header.Flags&common.FlagEncrypted == 0 {
		return nil
	}

	session, ok := sm.GetSession(pkt.Header.ConversationID)
	if !ok {
		return fmt.Errorf("no session found for %x", pkt.Header.ConversationID[:4])
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if len(pkt.Body) < 4+common.NonceSize {
		return fmt.Errorf("packet too short for ratified E2EE")
	}

	seqNum := binary.BigEndian.Uint32(pkt.Body[0:4])
	encryptedPart := pkt.Body[4:]

	var msgKey [32]byte
	found := false

	if key, exists := session.SkippedKeys[seqNum]; exists {
		msgKey = key
		delete(session.SkippedKeys, seqNum)
		found = true
	} else {
		if seqNum == session.RecvCount {
			msgKey, session.RecvChainKey = common.RatchetStep(session.RecvChainKey)
			session.RecvCount++
			found = true
		} else if seqNum > session.RecvCount {
			if seqNum-session.RecvCount > 2000 {
				return fmt.Errorf("message too far in future")
			}
			for i := session.RecvCount; i < seqNum; i++ {
				mk, next := common.RatchetStep(session.RecvChainKey)
				session.RecvChainKey = next
				session.SkippedKeys[i] = mk
			}
			msgKey, session.RecvChainKey = common.RatchetStep(session.RecvChainKey)
			session.RecvCount = seqNum + 1
			found = true
		} else {
			return fmt.Errorf("duplicate or old message skipped")
		}
	}

	if !found {
		return fmt.Errorf("failed to derive key")
	}

	decrypted, err := common.Decrypt(msgKey, encryptedPart, pkt.Header.Bytes())
	if err != nil {
		return fmt.Errorf("decryption failed for seq %d: %v", seqNum, err)
	}

	pkt.Body = decrypted
	pkt.Header.BodyLen = uint32(len(decrypted))
	pkt.Header.Flags &^= common.FlagEncrypted
	return nil
}

func (sm *SessionManager) GetGroupSession(groupID [16]byte) (*GroupSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.groupSessions[groupID]
	return sess, ok
}

func (sm *SessionManager) CreateGroupSession(groupID [16]byte, key [32]byte, version uint32, isAdmin bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var oldVersionToKeep uint32

	if sess, ok := sm.groupSessions[groupID]; ok {
		sess.mu.Lock()
		if sess.CurrentVersion > 0 && sess.CurrentVersion < version {
			sess.OldKeys[sess.CurrentVersion] = sess.CurrentKey
			oldVersionToKeep = sess.CurrentVersion
		}
		sess.CurrentKey = key
		sess.CurrentVersion = version
		sess.MessageCounter = 0
		sess.IsAdmin = isAdmin
		sess.mu.Unlock()

		if oldVersionToKeep > 0 {
			go func(s *GroupSession, v uint32) {
				time.Sleep(5 * time.Second)
				s.mu.Lock()
				delete(s.OldKeys, v)
				s.mu.Unlock()
			}(sess, oldVersionToKeep)
		}
	} else {
		sm.groupSessions[groupID] = &GroupSession{
			GroupID:        groupID,
			CurrentKey:     key,
			CurrentVersion: version,
			MessageCounter: 0,
			IsAdmin:        isAdmin,
			Members:        make(map[[16]byte]struct{}),
			OldKeys:        make(map[uint32][32]byte),
		}
	}
}

func (sm *SessionManager) EncryptGroupPacket(pkt *common.Packet) error {
	session, ok := sm.GetGroupSession(pkt.Header.ConversationID)
	if !ok {
		return fmt.Errorf("no group session for %x", pkt.Header.ConversationID[:4])
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	expectedEncryptedLen := len(pkt.Body) + common.NonceSize + 16
	pkt.Header.BodyLen = uint32(4 + expectedEncryptedLen)
	pkt.Header.Flags |= common.FlagEncrypted

	headerBytes := pkt.Header.Bytes()

	encryptedBody, err := common.Encrypt(session.CurrentKey, pkt.Body, headerBytes)
	if err != nil {
		return err
	}

	finalPayload := make([]byte, 4+len(encryptedBody))
	binary.BigEndian.PutUint32(finalPayload[0:], session.CurrentVersion)
	copy(finalPayload[4:], encryptedBody)

	pkt.Body = finalPayload

	return nil
}

func (sm *SessionManager) DecryptGroupPacket(pkt *common.Packet) error {
	if pkt.Header.Flags&common.FlagEncrypted == 0 {
		return nil
	}

	session, ok := sm.GetGroupSession(pkt.Header.ConversationID)
	if !ok {
		return fmt.Errorf("no group session for %x", pkt.Header.ConversationID[:4])
	}

	if len(pkt.Body) < 4+common.NonceSize {
		return fmt.Errorf("group packet too short")
	}

	version := binary.BigEndian.Uint32(pkt.Body[0:4])
	encryptedPart := pkt.Body[4:]

	session.mu.Lock()
	defer session.mu.Unlock()

	var decryptionKey [32]byte

	if version < session.CurrentVersion {
		oldKey, exists := session.OldKeys[version]
		if !exists {
			return fmt.Errorf("key version %d is too old and its 5-second retention window expired", version)
		}
		decryptionKey = oldKey
	} else if version == session.CurrentVersion {
		decryptionKey = session.CurrentKey
	} else {
		return fmt.Errorf("key version %d is ahead of current %d (awaiting update)", version, session.CurrentVersion)
	}

	decrypted, err := common.Decrypt(decryptionKey, encryptedPart, pkt.Header.Bytes())
	if err != nil {
		return fmt.Errorf("group decryption failed: %v", err)
	}

	pkt.Body = decrypted
	pkt.Header.BodyLen = uint32(len(decrypted))
	pkt.Header.Flags &^= common.FlagEncrypted
	return nil
}

func (gs *GroupSession) IncrementCounter() {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.MessageCounter++
}

func (gs *GroupSession) ShouldRotate() bool {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	return gs.MessageCounter >= 5
}
