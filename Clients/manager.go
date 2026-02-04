package main

import (
	"common"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type FileAssembly struct {
	Meta           common.FileMetadata
	ReceivedChunks map[int32]bool
	Data           []byte
}

type ClientManager struct {
	UserID        [common.IDSize]byte
	Username      string
	Conversations map[[common.IDSize]byte]string
	Usernames     map[[common.IDSize]byte]string
	PendingFiles  map[[common.IDSize]byte]*FileAssembly
	mu            sync.Mutex
}

func NewClientManager(username string) *ClientManager {
	return &ClientManager{
		Username:      username,
		Conversations: make(map[[common.IDSize]byte]string),
		Usernames:     make(map[[common.IDSize]byte]string),
		PendingFiles:  make(map[[common.IDSize]byte]*FileAssembly),
	}
}

func (m *ClientManager) RegisterConversation(id [common.IDSize]byte, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Conversations[id] = name
	fmt.Printf("\n[INFO] Conversation registered: %s\n> ", name)
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
	if name, ok := m.Conversations[id]; ok {
		return name
	}
	return fmt.Sprintf("%x", id[:4])
}

func (m *ClientManager) HandleFileMeta(msgID [common.IDSize]byte, meta common.FileMetadata) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.PendingFiles[msgID] = &FileAssembly{
		Meta:           meta,
		ReceivedChunks: make(map[int32]bool),
		Data:           make([]byte, meta.FileSize),
	}
	fmt.Printf("\n[INFO] Receiving file: %s (%d bytes)\n> ", meta.FileName, meta.FileSize)
}

func (m *ClientManager) HandleFileChunk(msgID [common.IDSize]byte, chunk common.FileChunk) {
	m.mu.Lock()
	defer m.mu.Unlock()

	assembly, ok := m.PendingFiles[msgID]
	if !ok {
		return
	}

	const StandardChunkSize = 32 * 1024
	offset := int64(chunk.ChunkNo) * StandardChunkSize

	if offset+int64(len(chunk.ChunkData)) > int64(len(assembly.Data)) {
	}

	copy(assembly.Data[offset:], chunk.ChunkData)
	assembly.ReceivedChunks[chunk.ChunkNo] = true

	if len(assembly.ReceivedChunks) == int(assembly.Meta.TotalChunks) {
		m.finalizeFile(msgID, assembly)
		delete(m.PendingFiles, msgID)
	}
}

func (m *ClientManager) finalizeFile(msgID [common.IDSize]byte, assembly *FileAssembly) {
	dir := "downloads"
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, assembly.Meta.FileName)

	if _, err := os.Stat(path); err == nil {
		path += fmt.Sprintf(".%x", msgID[:4])
	}

	if err := os.WriteFile(path, assembly.Data, 0644); err != nil {
		fmt.Printf("\n[ERROR] Failed to save file: %v\n> ", err)
	} else {
		fmt.Printf("\n[INFO] File saved: %s\n> ", path)
	}
}
