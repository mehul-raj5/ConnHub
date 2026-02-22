package main

import (
	"bufio"
	common "common"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const StandardChunkSize = 32 * 1024

var (
	rotationMu sync.Mutex
	mgr        *ClientManager
	idMgr      *IdentityManager
	sessionMgr *SessionManager
	conn       net.Conn
	reader     *bufio.Reader
	connLock   sync.Mutex
)

func main() {
	reader = bufio.NewReader(os.Stdin)

	var err error
	idMgr, err = NewIdentityManager()
	if err != nil {
		log.Fatalf("Failed to init identity: %v", err)
	}

	fmt.Print("Enter server address (default :8080): ")
	addr, _ := reader.ReadString('\n')
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = ":8080"
	}

	fmt.Print("Enter your username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	conn, err = net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	userID, err := performHandshake(username, idMgr.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	mgr = NewClientManager(userID, username)
	fmt.Printf("[DEBUG] main: mgr.UserID set to %x\n", mgr.UserID)
	sessionMgr = NewSessionManager(idMgr)

	go readLoop()

	inputLoop()
}

func performHandshake(username string, pubKey [32]byte) ([16]byte, error) {
	body := make([]byte, 0, 32+len(username))
	body = append(body, pubKey[:]...)
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlLogin,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	if err := sendPacket(&pkt); err != nil {
		return [16]byte{}, err
	}

	resp, err := common.Decode(conn)
	if err != nil {
		return [16]byte{}, err
	}

	if resp.Header.MsgType != common.CtrlLoginAck {
		return [16]byte{}, fmt.Errorf("unexpected handshake response: %d", resp.Header.MsgType)
	}

	var userID [16]byte
	copy(userID[:], resp.Body)
	fmt.Printf("Logged in! UserID: %x\n", userID)
	return userID, nil
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

		if pkt.Header.Flags&common.FlagEncrypted != 0 {
			if mgr.IsGroup(pkt.Header.ConversationID) {
				if err := sessionMgr.DecryptGroupPacket(&pkt); err != nil {
					log.Printf("[ERROR] Group Decrypt failed: %v", err)
					continue
				}
				if sess, ok := sessionMgr.GetGroupSession(pkt.Header.ConversationID); ok {
					sess.IncrementCounter()
					if sess.ShouldRotate() && mgr.IsGroupAdmin(pkt.Header.ConversationID) {
						go rotateGroupKey(pkt.Header.ConversationID)
					}
				}
			} else {
				if err := sessionMgr.DecryptPacket(&pkt); err != nil {
					log.Printf("[ERROR] Failed to decrypt packet from %x: %v", pkt.Header.SenderID[:4], err)
					continue
				}
			}
		}

		switch pkt.Header.MsgType {
		case common.MsgControl:
			if pkt.Header.Flags&common.FlagHandshake != 0 {
				sender := mgr.GetUsername(pkt.Header.SenderID)
				if err := sessionMgr.HandleHandshake(pkt); err != nil {
					log.Printf("Handshake failed: %v", err)
				} else {
					fmt.Printf("[INFO] Secure Session established with %s\n> ", sender)
				}
			}

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
			if len(pkt.Body) < 48 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[:16])
			var peerKey [32]byte
			copy(peerKey[:], pkt.Body[16:48])

			mgr.RegisterConversation(convID, "Private Chat", false)

			if _, ok := sessionMgr.GetSession(convID); ok {
				fmt.Printf("[INFO] Session already exists for %x, skipping handshake.\n", convID[:4])
				continue
			}

			fmt.Printf("[INFO] Key Exchange Initiating...\n")

			handshakePkt, err := sessionMgr.PerformHandshake(convID, peerKey)
			if err == nil {
				sendPacket(handshakePkt)
			} else {
				fmt.Printf("[ERROR] Handshake init failed: %v\n", err)
			}

		case common.CtrlDirectInit:
			if len(pkt.Body) < 48 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[:16])

			senderName := string(pkt.Body[48:])
			mgr.AddUser(pkt.Header.SenderID, senderName)
			mgr.RegisterConversation(pkt.Header.ConversationID, "Private Chat: "+senderName, false)

			fmt.Printf("[INFO] Private Chat requested by %s. Waiting for Handshake...\n", senderName)

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
			mgr.RegisterConversation(convID, groupName, true)
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
				mgr.AddMemberToGroup(convID, mID)
			}

			mgr.SetGroupAdmin(convID, pkt.Header.SenderID, true)

			fmt.Printf("[DEBUG] CtrlGroupCreate: Packet SenderID=%x, My UserID=%x\n", pkt.Header.SenderID, mgr.UserID)
			if pkt.Header.SenderID == mgr.UserID {
				fmt.Printf("[INFO] You are Admin of group %s. Initializing Key...\n", groupName)
				fmt.Printf("[DEBUG] readLoop: Triggering initial rotation for %x\n", convID)
				go rotateGroupKey(convID)
			}

		case common.CtrlGroupAdd:
			if len(pkt.Body) < 17 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			nameLen := int(pkt.Body[16])
			offset := 17
			var groupName string
			if len(pkt.Body) >= offset+nameLen {
				groupName = string(pkt.Body[offset : offset+nameLen])
				offset += nameLen
			} else {
				continue
			}
			if mgr.GetConversationName(convID) == fmt.Sprintf("%x", convID[:4]) {
				mgr.RegisterConversation(convID, groupName, true)
			}
			if len(pkt.Body) < offset+17 {
				continue
			}
			var userID [16]byte
			copy(userID[:], pkt.Body[offset:offset+16])
			offset += 16
			uNameLen := int(pkt.Body[offset])
			offset++
			if len(pkt.Body) < offset+uNameLen {
				continue
			}
			userName := string(pkt.Body[offset : offset+uNameLen])
			mgr.AddUser(userID, userName)
			mgr.AddMemberToGroup(convID, userID)
			fmt.Printf("\n[INFO] User %s added to group %s\n> ", userName, groupName)

			if mgr.IsGroupAdmin(convID) && pkt.Header.SenderID == mgr.UserID {
				go rotateGroupKey(convID)
			}

		case common.CtrlGroupRemove:
			if len(pkt.Body) < 32 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.RemoveMemberFromGroup(convID, userID)
			fmt.Printf("\n[INFO] User %s removed from group %s\n> ", uName, groupName)

			if mgr.IsGroupAdmin(convID) && pkt.Header.SenderID == mgr.UserID {
				go rotateGroupKey(convID)
			}

		case common.CtrlGroupMakeAdmin:
			if len(pkt.Body) < 32 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.SetGroupAdmin(convID, userID, true)
			fmt.Printf("\n[INFO] User %s is now an Admin of group %s\n> ", uName, groupName)

		case common.CtrlGroupRemoveAdmin:
			if len(pkt.Body) < 32 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.SetGroupAdmin(convID, userID, false)
			fmt.Printf("\n[INFO] User %s is no longer an Admin of group %s\n> ", uName, groupName)

		case common.CtrlPubAck:
			if len(pkt.Body) < 48 {
				continue
			}
			var userID [16]byte
			copy(userID[:], pkt.Body[:16])
			var pubKey [32]byte
			copy(pubKey[:], pkt.Body[16:48])
			mgr.UpdatePublicKey(userID, pubKey)

		case common.CtrlGroupKeyUpdate:

			if len(pkt.Body) < 16+4+32 {
				continue
			}
			var groupID [16]byte
			copy(groupID[:], pkt.Body[:16])
			version := binary.BigEndian.Uint32(pkt.Body[16:20])
			var key [32]byte
			copy(key[:], pkt.Body[20:52])

			if !mgr.IsUserAdmin(groupID, pkt.Header.SenderID) {
				log.Printf("[WARNING] Unauthorized Key Update dropped from %x for group %x", pkt.Header.SenderID[:4], groupID[:4])
				continue
			}

			sessionMgr.CreateGroupSession(groupID, key, version, false)
			fmt.Printf("\n[INFO] Group Key Updated for %s (v%d)\n> ", mgr.GetConversationName(groupID), version)

			ackBody := make([]byte, 20)
			copy(ackBody[:16], groupID[:])
			binary.BigEndian.PutUint32(ackBody[16:], version)

			ackPkt := common.Packet{
				Header: common.Header{
					MsgType:        common.CtrlGroupKeyUpdateAck,
					ConversationID: pkt.Header.ConversationID,
					SenderID:       mgr.UserID,
					BodyLen:        20,
				},
				Body: ackBody,
			}
			if err := sessionMgr.EncryptPacket(&ackPkt); err == nil {
				sendPacket(&ackPkt)
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
		fmt.Println("6. Add Member to Group")
		fmt.Println("7. Remove Member from Group")
		fmt.Println("8. Make Member Admin")
		fmt.Println("9. Remove Admin")
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
		case "6":
			addMember()
		case "7":
			removeMember()
		case "8":
			makeGroupAdmin()
		case "9":
			removeGroupAdmin()
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
	sendPacket(&pkt)
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
	sendPacket(&pkt)
}

func listConversations() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	i := 0
	for id, info := range mgr.Conversations {
		typeStr := "Private"
		if info.IsGroup {
			typeStr = "Group"
		}
		fmt.Printf("%d. %s [%s] (%x)\n", i, info.Name, typeStr, id[:4])
		i++
	}
}

func addMember() {
	convID, ok := selectConversation("Select Group: ")
	if !ok {
		return
	}
	if !mgr.IsGroup(convID) {
		fmt.Println("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		fmt.Println("Error: Only admins can add members.")
		return
	}
	fmt.Print("Enter username to add: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}

	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupAdd,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	fmt.Println("Add member request sent.")
}

func removeMember() {
	convID, ok := selectConversation("Select Group: ")
	if !ok {
		return
	}
	if !mgr.IsGroup(convID) {
		fmt.Println("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		fmt.Println("Error: Only admins can remove members.")
		return
	}
	fmt.Print("Enter username to remove: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}

	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupRemove,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	fmt.Println("Remove member request sent.")
}

func makeGroupAdmin() {
	convID, ok := selectConversation("Select Group: ")
	if !ok {
		return
	}
	if !mgr.IsGroup(convID) {
		fmt.Println("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		fmt.Println("Error: Only admins can promote other members.")
		return
	}
	fmt.Print("Enter username to make Admin: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}

	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupMakeAdmin,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	fmt.Println("Make admin request sent.")
}

func removeGroupAdmin() {
	convID, ok := selectConversation("Select Group: ")
	if !ok {
		return
	}
	if !mgr.IsGroup(convID) {
		fmt.Println("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		fmt.Println("Error: Only admins can demote admins.")
		return
	}
	fmt.Print("Enter username to remove from Admin: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}

	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupRemoveAdmin,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	fmt.Println("Remove admin request sent.")
}

func selectConversation(prompt string) ([16]byte, bool) {
	mgr.mu.Lock()
	convs := make([][16]byte, 0, len(mgr.Conversations))
	names := make([]string, 0, len(mgr.Conversations))
	for id, info := range mgr.Conversations {
		convs = append(convs, id)
		names = append(names, info.Name)
	}
	mgr.mu.Unlock()

	if len(convs) == 0 {
		fmt.Println("No active conversations.")
		return [16]byte{}, false
	}

	for i, n := range names {
		fmt.Printf("%d. %s\n", i, n)
	}
	fmt.Print(prompt)
	idxStr, _ := reader.ReadString('\n')
	idx, _ := strconv.Atoi(strings.TrimSpace(idxStr))

	if idx < 0 || idx >= len(convs) {
		fmt.Println("Invalid selection")
		return [16]byte{}, false
	}
	return convs[idx], true
}

func sendMessage(isFile bool) {
	convID, ok := selectConversation("Select conversation: ")
	if !ok {
		return
	}
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
			SenderID:       mgr.UserID,
			BodyLen:        uint32(len(msg)),
		},
		Body: []byte(msg),
	}

	if mgr.IsGroup(convID) {
		fmt.Printf("[DEBUG] sendText: Encrypting for GroupID %x\n", convID)

		rotationMu.Lock()
		err := sessionMgr.EncryptGroupPacket(&pkt)
		rotationMu.Unlock()

		if err != nil {
			fmt.Printf("[ERROR] Group Encryption failed: %v\n", err)
			return
		}
		if sess, ok := sessionMgr.GetGroupSession(convID); ok {
			sess.IncrementCounter()
			if sess.ShouldRotate() && mgr.IsGroupAdmin(convID) {
				go rotateGroupKey(convID)
			}
		}
	} else {
		if err := sessionMgr.EncryptPacket(&pkt); err != nil {
			fmt.Printf("[ERROR] %v. Please ensure Handshake is complete.\n", err)
			return
		}
	}

	sendPacket(&pkt)
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
			SenderID:       mgr.UserID,
			BodyLen:        uint32(len(metaBytes)),
		},
		Body: metaBytes,
	}

	if mgr.IsGroup(convID) {
		rotationMu.Lock()
		err := sessionMgr.EncryptGroupPacket(&metaPkt)
		rotationMu.Unlock()

		if err != nil {
			fmt.Printf("[ERROR] Group Encryption failed for meta: %v\n", err)
			return
		}
		if sess, ok := sessionMgr.GetGroupSession(convID); ok {
			sess.IncrementCounter()
			if sess.ShouldRotate() && mgr.IsGroupAdmin(convID) {
				go rotateGroupKey(convID)
			}
		}
	} else {
		if err := sessionMgr.EncryptPacket(&metaPkt); err != nil {
			fmt.Printf("[ERROR] Encryption failed for meta: %v\n", err)
			return
		}
	}
	sendPacket(&metaPkt)

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
				SenderID:       mgr.UserID,
				BodyLen:        uint32(len(cBytes)),
			},
			Body: cBytes,
		}
		if mgr.IsGroup(convID) {
			rotationMu.Lock()
			err := sessionMgr.EncryptGroupPacket(&chkPkt)
			rotationMu.Unlock()

			if err != nil {
				fmt.Printf("[ERROR] Group Encryption failed for chunk: %v\n", err)
				return
			}
		} else {
			if err := sessionMgr.EncryptPacket(&chkPkt); err != nil {
				fmt.Printf("[ERROR] Encryption failed for chunk: %v\n", err)
				return
			}
		}
		sendPacket(&chkPkt)
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

func sendPacket(pkt *common.Packet) error {
	connLock.Lock()
	defer connLock.Unlock()
	return pkt.Encode(conn)
}

func sendCtrlPubRq(userID [16]byte) {
	pkt := common.Packet{
		Header: common.Header{
			MsgType:  common.CtrlPubRq,
			SenderID: mgr.UserID,
			BodyLen:  16,
		},
		Body: userID[:],
	}
	sendPacket(&pkt)
}

func rotateGroupKey(groupID [16]byte) {
	rotationMu.Lock()
	defer rotationMu.Unlock()

	fmt.Printf("[DEBUG] rotateGroupKey: Starting rotation for %x\n", groupID)

	if !mgr.IsGroupAdmin(groupID) {
		fmt.Printf("[DEBUG] rotateGroupKey: Not admin for %x, aborting\n", groupID)
		return
	}

	var newKey [32]byte
	if _, err := rand.Read(newKey[:]); err != nil {
		log.Printf("Failed to gen key: %v", err)
		return
	}

	var newVersion uint32 = 1
	if sess, ok := sessionMgr.GetGroupSession(groupID); ok {
		newVersion = sess.CurrentVersion + 1
	}

	members := mgr.GetGroupMembers(groupID)
	fmt.Printf("[DEBUG] rotateGroupKey: Found %d members for group %x\n", len(members), groupID)

	for _, memberID := range members {
		if memberID == mgr.UserID {
			continue
		}
		fmt.Printf("[DEBUG] rotateGroupKey: Processing member %x\n", memberID)

		convID := common.HashIDs(mgr.UserID, memberID)
		if _, ok := sessionMgr.GetSession(convID); !ok {
			memberUName := mgr.GetUsername(memberID)
			initPkt := common.Packet{
				Header: common.Header{
					MsgType: common.CtrlDirectInit,
					BodyLen: uint32(len(memberUName)),
				},
				Body: []byte(memberUName),
			}
			sendPacket(&initPkt)
			fmt.Printf("[DEBUG] rotateGroupKey: Sent CtrlDirectInit for %s\n", memberUName)

			established := false
			for i := 0; i < 50; i++ {
				if _, ok := sessionMgr.GetSession(convID); ok {
					established = true
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			if !established {
				log.Printf("Handshake timeout with %x (no session after 5s)", memberID[:4])
				continue
			}
		}

		payload := make([]byte, 16+4+32)
		copy(payload[0:16], groupID[:])
		binary.BigEndian.PutUint32(payload[16:20], newVersion)
		copy(payload[20:52], newKey[:])

		pkt := common.Packet{
			Header: common.Header{
				MsgType:        common.CtrlGroupKeyUpdate,
				ConversationID: convID,
				SenderID:       mgr.UserID,
				BodyLen:        uint32(len(payload)),
			},
			Body: payload,
		}

		if err := sessionMgr.EncryptPacket(&pkt); err != nil {
			log.Printf("Failed to encrypt key update for %x: %v", memberID[:4], err)
			continue
		}

		sendPacket(&pkt)
		fmt.Printf("[DEBUG] rotateGroupKey: Sent Key Update to %x\n", memberID)
	}

	time.Sleep(500 * time.Millisecond)

	sessionMgr.CreateGroupSession(groupID, newKey, newVersion, true)
	fmt.Printf("\n[INFO] Rotated Group Key to v%d\n> ", newVersion)
	fmt.Printf("[DEBUG] rotateGroupKey: Created session for GroupID %x\n", groupID)
}
