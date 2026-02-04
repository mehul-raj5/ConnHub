package common

import (
	"encoding/binary"
	"fmt"
	"io"
)

const IDSize = 16

const HeaderSize = 16 + 16 + 16 + 1 + 4

const (
	MsgText      uint8 = 0x01
	MsgFileMeta  uint8 = 0x02
	MsgFileChunk uint8 = 0x03

	CtrlLogin       uint8 = 0x10
	CtrlLoginAck    uint8 = 0x11
	CtrlGroupCreate uint8 = 0x12
	CtrlGroupAdd    uint8 = 0x13
	CtrlGroupRemove uint8 = 0x14
	CtrlDirectInit  uint8 = 0x15
	CtrlDirectAck   uint8 = 0x16
	CtrlError       uint8 = 0xFF
)

type Header struct {
	MessageID      [IDSize]byte
	ConversationID [IDSize]byte
	SenderID       [IDSize]byte
	MsgType        uint8
	BodyLen        uint32
}

type Packet struct {
	Header Header
	Body   []byte
}

func (p *Packet) Encode(w io.Writer) error {
	buf := make([]byte, HeaderSize)
	copy(buf[0:16], p.Header.MessageID[:])
	copy(buf[16:32], p.Header.ConversationID[:])
	copy(buf[32:48], p.Header.SenderID[:])
	buf[48] = p.Header.MsgType
	binary.BigEndian.PutUint32(buf[49:], p.Header.BodyLen)

	if _, err := w.Write(buf); err != nil {
		return err
	}
	if p.Header.BodyLen > 0 {
		if _, err := w.Write(p.Body); err != nil {
			return err
		}
	}
	return nil
}

func Decode(r io.Reader) (Packet, error) {
	var p Packet
	buf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return p, err
	}

	copy(p.Header.MessageID[:], buf[0:16])
	copy(p.Header.ConversationID[:], buf[16:32])
	copy(p.Header.SenderID[:], buf[32:48])
	p.Header.MsgType = buf[48]
	p.Header.BodyLen = binary.BigEndian.Uint32(buf[49:])

	if p.Header.BodyLen > 1024*1024*100 {
		return p, fmt.Errorf("body too large: %d", p.Header.BodyLen)
	}

	if p.Header.BodyLen > 0 {
		p.Body = make([]byte, p.Header.BodyLen)
		if _, err := io.ReadFull(r, p.Body); err != nil {
			return p, err
		}
	}
	return p, nil
}

type FileMetadata struct {
	FileName    string
	FileType    string
	FileSize    int64
	TotalChunks int32
}

func (m *FileMetadata) Encode() []byte {
	nameBytes := []byte(m.FileName)
	typeBytes := []byte(m.FileType)

	size := 2 + len(nameBytes) + 2 + len(typeBytes) + 8 + 4
	buf := make([]byte, size)

	offset := 0
	binary.BigEndian.PutUint16(buf[offset:], uint16(len(nameBytes)))
	offset += 2
	copy(buf[offset:], nameBytes)
	offset += len(nameBytes)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(typeBytes)))
	offset += 2
	copy(buf[offset:], typeBytes)
	offset += len(typeBytes)

	binary.BigEndian.PutUint64(buf[offset:], uint64(m.FileSize))
	offset += 8
	binary.BigEndian.PutUint32(buf[offset:], uint32(m.TotalChunks))

	return buf
}

func DecodeFileMetadata(data []byte) (FileMetadata, error) {
	var m FileMetadata
	offset := 0

	if len(data) < 2 {
		return m, fmt.Errorf("data too short")
	}
	nameLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if len(data) < offset+nameLen+2 {
		return m, fmt.Errorf("data too short for name")
	}
	m.FileName = string(data[offset : offset+nameLen])
	offset += nameLen

	typeLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if len(data) < offset+typeLen+8+4 {
		return m, fmt.Errorf("data too short for remainder")
	}
	m.FileType = string(data[offset : offset+typeLen])
	offset += typeLen

	m.FileSize = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8
	m.TotalChunks = int32(binary.BigEndian.Uint32(data[offset:]))

	return m, nil
}

type FileChunk struct {
	ChunkNo   int32
	ChunkData []byte
}

func (c *FileChunk) Encode() []byte {
	buf := make([]byte, 4+len(c.ChunkData))
	binary.BigEndian.PutUint32(buf[0:], uint32(c.ChunkNo))
	copy(buf[4:], c.ChunkData)
	return buf
}

func DecodeFileChunk(data []byte) (FileChunk, error) {
	var c FileChunk
	if len(data) < 4 {
		return c, fmt.Errorf("chunk data too short")
	}
	c.ChunkNo = int32(binary.BigEndian.Uint32(data[0:]))
	c.ChunkData = data[4:]
	return c, nil
}
