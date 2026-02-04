package main

import (
	"bufio"
	"common"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const StandardChunkSize = 32 * 1024

var (
	mgr    *ClientManager
	conn   net.Conn
	reader *bufio.Reader
)

func main() {
	reader = bufio.NewReader(os.Stdin)

	fmt.Print("Enter server address (default :8080): ")
	addr, _ := reader.ReadString('\n')
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = ":8080"
	}

	fmt.Print("Enter your username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	var err error
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if err := performHandshake(username); err != nil {
		log.Fatal(err)
	}

	mgr = NewClientManager(username)

	go readLoop()

	inputLoop()
}

func performHandshake(username string) error {
	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlLogin,
			BodyLen: uint32(len(username)),
		},
		Body: []byte(username),
	}
	if err := pkt.Encode(conn); err != nil {
		return err
	}

	resp, err := common.Decode(conn)
	if err != nil {
		return err
	}

	if resp.Header.MsgType != common.CtrlLoginAck {
		return fmt.Errorf("unexpected handshake response: %d", resp.Header.MsgType)
	}
	fmt.Printf("Logged in! UserID: %x\n", resp.Body)
	return nil
}

func readLoop() {
	for {
		pkt, err := common.Decode(conn)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("\n[ERROR] Disconnected: %v\n", err)
			}
			os.Exit(1)
		}

		switch pkt.Header.MsgType {
		case common.MsgText:
			name := mgr.GetConversationName(pkt.Header.ConversationID)
			sender := mgr.GetUsername(pkt.Header.SenderID)
			fmt.Printf("\n[%s] %s: %s\n> ", name, sender, string(pkt.Body))

		case common.MsgFileMeta:
			meta, err := common.DecodeFileMetadata(pkt.Body)
			if err != nil {
				log.Printf("Bad file meta: %v", err)
				continue
			}
			sender := mgr.GetUsername(pkt.Header.SenderID)
			fmt.Printf("\n[%s] Receiving file from %s: %s (%d bytes)\n> ",
				mgr.GetConversationName(pkt.Header.ConversationID),
				sender, meta.FileName, meta.FileSize)
			mgr.HandleFileMeta(pkt.Header.MessageID, meta)

		case common.MsgFileChunk:
			chunk, err := common.DecodeFileChunk(pkt.Body)
			if err != nil {
				log.Printf("Bad chunk: %v", err)
				continue
			}
			mgr.HandleFileChunk(pkt.Header.MessageID, chunk)

		case common.CtrlDirectAck:
			var convID [16]byte
			copy(convID[:], pkt.Body)
			mgr.RegisterConversation(convID, "Private Chat")

		case common.CtrlDirectInit:
			senderName := string(pkt.Body)
			mgr.AddUser(pkt.Header.SenderID, senderName)
			mgr.RegisterConversation(pkt.Header.ConversationID, "Private Chat: "+senderName)

		case common.CtrlGroupCreate:
			if len(pkt.Body) < 17 {
				continue
			}

			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			nameLen := int(pkt.Body[16])
			if len(pkt.Body) < 17+nameLen+1 {
				continue
			}

			groupName := string(pkt.Body[17 : 17+nameLen])
			mgr.RegisterConversation(convID, groupName)

			offset := 17 + nameLen
			memberCount := int(pkt.Body[offset])
			offset++

			for i := 0; i < memberCount; i++ {
				if offset+17 > len(pkt.Body) {
					break
				}
				var mID [16]byte
				copy(mID[:], pkt.Body[offset:offset+16])
				offset += 16

				mNameLen := int(pkt.Body[offset])
				offset++

				if offset+mNameLen > len(pkt.Body) {
					break
				}
				mName := string(pkt.Body[offset : offset+mNameLen])
				offset += mNameLen

				mgr.AddUser(mID, mName)
			}
		}
	}
}

func inputLoop() {
	for {
		fmt.Println("\n=== MENU ===")
		fmt.Println("1. Create Group")
		fmt.Println("2. Start Private Chat")
		fmt.Println("3. Send Message")
		fmt.Println("4. Send File")
		fmt.Println("5. List Conversations")
		fmt.Print("> ")

		line, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(line)

		switch choice {
		case "1":
			createGroup()
		case "2":
			startPrivateChat()
		case "3":
			sendMessage(false)
		case "4":
			sendMessage(true)
		case "5":
			listConversations()
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func createGroup() {
	fmt.Print("Group Name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)

	fmt.Print("Enter usernames (comma separated): ")
	users, _ := reader.ReadString('\n')
	parts := strings.Split(users, ",")

	body := make([]byte, 0)
	body = append(body, byte(len(name)))
	body = append(body, []byte(name)...)
	body = append(body, byte(len(parts)))

	for _, u := range parts {
		u = strings.TrimSpace(u)
		body = append(body, byte(len(u)))
		body = append(body, []byte(u)...)
	}

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupCreate,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	pkt.Encode(conn)
}

func startPrivateChat() {
	fmt.Print("Target Username: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlDirectInit,
			BodyLen: uint32(len(name)),
		},
		Body: []byte(name),
	}
	pkt.Encode(conn)
}

func listConversations() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	i := 0
	for id, name := range mgr.Conversations {
		fmt.Printf("%d. %s (%x)\n", i, name, id[:4])
		i++
	}
}

func sendMessage(isFile bool) {
	mgr.mu.Lock()
	convs := make([][16]byte, 0, len(mgr.Conversations))
	names := make([]string, 0, len(mgr.Conversations))
	for id, name := range mgr.Conversations {
		convs = append(convs, id)
		names = append(names, name)
	}
	mgr.mu.Unlock()

	if len(convs) == 0 {
		fmt.Println("No active conversations. Create one first.")
		return
	}

	for i, n := range names {
		fmt.Printf("%d. %s\n", i, n)
	}
	fmt.Print("Select conversation: ")
	idxStr, _ := reader.ReadString('\n')
	idx, _ := strconv.Atoi(strings.TrimSpace(idxStr))

	if idx < 0 || idx >= len(convs) {
		fmt.Println("Invalid selection")
		return
	}
	convID := convs[idx]

	if isFile {
		sendFile(convID)
	} else {
		sendText(convID)
	}
}

func sendText(convID [16]byte) {
	fmt.Print("Message: ")
	msg, _ := reader.ReadString('\n')
	msg = strings.TrimSpace(msg)

	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.MsgText,
			ConversationID: convID,
			MessageID:      genID(),
			BodyLen:        uint32(len(msg)),
		},
		Body: []byte(msg),
	}
	pkt.Encode(conn)
}

func sendFile(convID [16]byte) {
	fmt.Print("File Path: ")
	path, _ := reader.ReadString('\n')
	path = strings.TrimSpace(path)

	f, err := os.Open(path)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	size := info.Size()
	totalChunks := int32((size + StandardChunkSize - 1) / StandardChunkSize)
	msgID := genID()

	meta := common.FileMetadata{
		FileName:    filepath.Base(path),
		FileType:    "application/octet-stream",
		FileSize:    size,
		TotalChunks: totalChunks,
	}
	metaBytes := meta.Encode()

	metaPkt := common.Packet{
		Header: common.Header{
			MsgType:        common.MsgFileMeta,
			ConversationID: convID,
			MessageID:      msgID,
			BodyLen:        uint32(len(metaBytes)),
		},
		Body: metaBytes,
	}
	metaPkt.Encode(conn)

	buf := make([]byte, StandardChunkSize)
	chunkNo := int32(0)
	for {
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			break
		}
		if n == 0 {
			break
		}

		chunkData := make([]byte, n)
		copy(chunkData, buf[:n])

		c := common.FileChunk{
			ChunkNo:   chunkNo,
			ChunkData: chunkData,
		}
		cBytes := c.Encode()

		chkPkt := common.Packet{
			Header: common.Header{
				MsgType:        common.MsgFileChunk,
				ConversationID: convID,
				MessageID:      msgID,
				BodyLen:        uint32(len(cBytes)),
			},
			Body: cBytes,
		}
		chkPkt.Encode(conn)

		chunkNo++
		time.Sleep(1 * time.Millisecond)
	}
	fmt.Println("File sent!")
}

func genID() [16]byte {
	var id [16]byte
	rand.Read(id[:])
	return id
}
