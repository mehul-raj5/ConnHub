package common

import (
	"encoding/binary"
	"fmt"
	"io"
)

const IDSize = 16

const HeaderSize = 16 + 16 + 16 + 1 + 2 + 4

const (
	MsgControl   uint8 = 0x00
	MsgText      uint8 = 0x01
	MsgMediaMeta uint8 = 0x04 // E2E-encrypted media metadata envelope (Supabase direct-upload)

	CtrlLogin             uint8 = 0x10
	CtrlLoginAck          uint8 = 0x11
	CtrlGroupCreate       uint8 = 0x12
	CtrlGroupAdd          uint8 = 0x13
	CtrlGroupRemove       uint8 = 0x14
	CtrlDirectInit        uint8 = 0x15
	CtrlDirectAck         uint8 = 0x16
	CtrlGroupKeyUpdate    uint8 = 0x17
	CtrlGroupMakeAdmin    uint8 = 0x1B
	CtrlGroupRemoveAdmin  uint8 = 0x1C
	CtrlGroupKeyUpdateAck uint8 = 0x1A
	CtrlPubRq             uint8 = 0x18
	CtrlPubAck            uint8 = 0x19

	// Media direct-upload signed-URL exchange (client <-> chat server).
	CtrlUploadRq   uint8 = 0x20 // client -> server: request a signed upload URL
	CtrlUploadAck  uint8 = 0x21 // server -> client: signed upload URL + object path
	CtrlDownloadRq uint8 = 0x22 // client -> server: request a signed download URL
	CtrlDownloadAck uint8 = 0x23 // server -> client: signed download URL

	CtrlError uint8 = 0xFF

	FlagNone      uint16 = 0
	FlagEncrypted uint16 = 1 << 0
	FlagHandshake uint16 = 1 << 1
	FlagAck       uint16 = 1 << 2
	FlagInit      uint16 = 1 << 3
)

type Header struct {
	MessageID      [IDSize]byte
	ConversationID [IDSize]byte
	SenderID       [IDSize]byte
	MsgType        uint8
	Flags          uint16
	BodyLen        uint32
}

type Packet struct {
	Header Header
	Body   []byte
}

func (h *Header) Bytes() []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[0:16], h.MessageID[:])
	copy(buf[16:32], h.ConversationID[:])
	copy(buf[32:48], h.SenderID[:])
	buf[48] = h.MsgType
	binary.BigEndian.PutUint16(buf[49:], h.Flags)
	binary.BigEndian.PutUint32(buf[51:], h.BodyLen)
	return buf
}

func (p *Packet) Encode(w io.Writer) error {
	buf := make([]byte, HeaderSize)
	copy(buf[0:16], p.Header.MessageID[:])
	copy(buf[16:32], p.Header.ConversationID[:])
	copy(buf[32:48], p.Header.SenderID[:])
	buf[48] = p.Header.MsgType
	binary.BigEndian.PutUint16(buf[49:], p.Header.Flags)
	binary.BigEndian.PutUint32(buf[51:], p.Header.BodyLen)

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
	p.Header.Flags = binary.BigEndian.Uint16(buf[49:])
	p.Header.BodyLen = binary.BigEndian.Uint32(buf[51:])

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

// --- Media direct-upload payloads ---

// MediaMetadata is the lightweight envelope sent in a MsgMediaMeta packet after
// the encrypted blob has been uploaded to Supabase Storage. The whole packet body
// is itself E2E-encrypted (EncryptPacket/EncryptGroupPacket), so the DecryptKey
// and Thumbnail travel confidentially.
type MediaMetadata struct {
	FileName   string   // original file name
	FileType   string   // detected MIME type
	FileSize   int64    // plaintext size in bytes
	ObjectPath string   // Supabase Storage object key
	DecryptKey [32]byte // XChaCha20-Poly1305 key for the uploaded blob
	FileHash   [32]byte // SHA-256 of the plaintext, for integrity verification
	Thumbnail  []byte   // small compressed JPEG preview (may be empty)
}

// putString writes a uint16 length prefix followed by the bytes of s.
func putString(buf []byte, s string) int {
	binary.BigEndian.PutUint16(buf, uint16(len(s)))
	copy(buf[2:], s)
	return 2 + len(s)
}

// getString reads a uint16-prefixed string starting at offset. Returns the
// string and the new offset, or an error if the data is truncated.
func getString(data []byte, offset int) (string, int, error) {
	if len(data) < offset+2 {
		return "", offset, fmt.Errorf("data too short for string length")
	}
	n := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+n {
		return "", offset, fmt.Errorf("data too short for string body")
	}
	return string(data[offset : offset+n]), offset + n, nil
}

func (m *MediaMetadata) Encode() []byte {
	size := 2 + len(m.FileName) +
		2 + len(m.FileType) +
		8 + // FileSize
		2 + len(m.ObjectPath) +
		32 + // DecryptKey
		32 + // FileHash
		4 + len(m.Thumbnail) // uint32 length + thumbnail bytes
	buf := make([]byte, size)

	offset := 0
	offset += putString(buf[offset:], m.FileName)
	offset += putString(buf[offset:], m.FileType)

	binary.BigEndian.PutUint64(buf[offset:], uint64(m.FileSize))
	offset += 8

	offset += putString(buf[offset:], m.ObjectPath)

	copy(buf[offset:], m.DecryptKey[:])
	offset += 32
	copy(buf[offset:], m.FileHash[:])
	offset += 32

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(m.Thumbnail)))
	offset += 4
	copy(buf[offset:], m.Thumbnail)

	return buf
}

func DecodeMediaMetadata(data []byte) (MediaMetadata, error) {
	var m MediaMetadata
	var err error
	offset := 0

	if m.FileName, offset, err = getString(data, offset); err != nil {
		return m, err
	}
	if m.FileType, offset, err = getString(data, offset); err != nil {
		return m, err
	}

	if len(data) < offset+8 {
		return m, fmt.Errorf("data too short for file size")
	}
	m.FileSize = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	if m.ObjectPath, offset, err = getString(data, offset); err != nil {
		return m, err
	}

	if len(data) < offset+32+32+4 {
		return m, fmt.Errorf("data too short for keys/hash")
	}
	copy(m.DecryptKey[:], data[offset:offset+32])
	offset += 32
	copy(m.FileHash[:], data[offset:offset+32])
	offset += 32

	thumbLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if len(data) < offset+thumbLen {
		return m, fmt.Errorf("data too short for thumbnail")
	}
	m.Thumbnail = make([]byte, thumbLen)
	copy(m.Thumbnail, data[offset:offset+thumbLen])

	return m, nil
}

// EncodeSignedURLPayload / DecodeSignedURLPayload carry one or two length-prefixed
// strings, used for the CtrlUpload/CtrlDownload ack bodies (objectPath, signedURL).
func EncodeSignedURLPayload(strs ...string) []byte {
	size := 0
	for _, s := range strs {
		size += 2 + len(s)
	}
	buf := make([]byte, size)
	offset := 0
	for _, s := range strs {
		offset += putString(buf[offset:], s)
	}
	return buf
}

func DecodeSignedURLPayload(data []byte, count int) ([]string, error) {
	out := make([]string, 0, count)
	offset := 0
	for i := 0; i < count; i++ {
		s, next, err := getString(data, offset)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		offset = next
	}
	return out, nil
}
