package main

import (
	"bufio"
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

	tea "github.com/charmbracelet/bubbletea"
)

var (
	mgr        *ClientManager
	idMgr      *IdentityManager
	sessionMgr *SessionManager
	conn       net.Conn
	reader     *bufio.Reader
	connLock   sync.Mutex
)

func main() {
	f, err := os.OpenFile("client.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Error opening client.log: %v\n", err)
	} else {
		log.SetOutput(f)
		defer f.Close()
	}

	reader = bufio.NewReader(os.Stdin)

	idMgr, err = NewIdentityManager()
	if err != nil {
		log.Fatalf("Failed to init identity: %v", err)
	}

	tuiPrint("Enter server address (default :8080): ")
	addr, _ := reader.ReadString('\n')
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = ":8080"
	}

	tuiPrint("Enter your username: ")
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
	log.Printf("[DEBUG] main: mgr.UserID set to %x\n", mgr.UserID)
	sessionMgr = NewSessionManager(idMgr, userID)

	go readLoop()

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	program = p
	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
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
	tuiPrintf("Logged in! UserID: %x", userID)
	return userID, nil
}

func readLoop() {
	for {
		pkt, err := common.Decode(conn)
		if err != nil {
			if err != io.EOF {
				tuiPrintf("[ERROR] Disconnected: %v", err)
			}
			os.Exit(1)
		}
		deliver(pkt)
	}
}

// deliver decrypts a packet if it needs it and hands it to dispatch. A packet
// whose key has not arrived yet is held rather than dropped, and comes back
// through here once the missing key lands.
func deliver(pkt common.Packet) {
	if err := tryDecrypt(&pkt); err != nil {
		if !Recoverable(err) {
			log.Printf("[ERROR] Dropping packet from %x: %v", pkt.Header.SenderID[:4], err)
			return
		}

		convID := pkt.Header.ConversationID
		pending.Park(convID, pkt)

		// A missing sender key is already on its way over the direct channel we
		// share with that member, so there is nothing to ask for. Not knowing
		// the conversation at all is different: the roster has to be fetched.
		if !errors.Is(err, ErrNoSenderKey) {
			requestConvInfo(convID)
		}
		return
	}
	dispatch(pkt)
}

// tryDecrypt unwraps an encrypted packet using whichever session applies.
//
// An unknown conversation reads as a direct one, because IsGroup returns false
// for anything unregistered. That resolves itself: the roster reply says which
// it really is, and the replayed packet then takes the right branch.
func tryDecrypt(pkt *common.Packet) error {
	if pkt.Header.Flags&common.FlagEncrypted == 0 {
		return nil
	}
	if mgr.IsGroup(pkt.Header.ConversationID) {
		return sessionMgr.DecryptGroupPacket(pkt)
	}
	return sessionMgr.DecryptPacket(pkt)
}

func dispatch(pkt common.Packet) {
	{
		switch pkt.Header.MsgType {
		case common.MsgText:
			name := mgr.GetConversationName(pkt.Header.ConversationID)
			sender := mgr.GetUsername(pkt.Header.SenderID)
			if program != nil {
				go program.Send(NetworkMsg{
					ConversationID: pkt.Header.ConversationID,
					SenderName:     sender,
					Content:        string(pkt.Body),
					IsSystemMeta:   false,
				})
			} else {
				fmt.Printf("[%s] %s: %s\n", name, sender, string(pkt.Body))
			}

		case common.MsgMediaMeta:
			meta, err := common.DecodeMediaMetadata(pkt.Body)
			if err != nil {
				log.Printf("Bad media meta: %v", err)
				return
			}
			sender := mgr.GetUsername(pkt.Header.SenderID)
			tuiPrintf("[%s] Incoming media from %s: %s (%d bytes)",
				mgr.GetConversationName(pkt.Header.ConversationID),
				sender, meta.FileName, meta.FileSize)
			handleIncomingMedia(pkt.Header.ConversationID, sender, meta)

		case common.CtrlUploadAck:
			strs, err := common.DecodeSignedURLPayload(pkt.Body, 2)
			if err != nil {
				strs = nil
			}
			mgr.DeliverURL(pkt.Header.MessageID, strs)

		case common.CtrlDownloadAck:
			strs, err := common.DecodeSignedURLPayload(pkt.Body, 1)
			if err != nil {
				strs = nil
			}
			mgr.DeliverURL(pkt.Header.MessageID, strs)

		case common.CtrlDirectAck:
			// convID(16) || peerID(16) || peerPubKey(32) || peerName
			if len(pkt.Body) < 64 {
				return
			}
			var convID, peerID [16]byte
			copy(convID[:], pkt.Body[:16])
			copy(peerID[:], pkt.Body[16:32])
			var peerKey [32]byte
			copy(peerKey[:], pkt.Body[32:64])
			peerName := string(pkt.Body[64:])

			mgr.AddUser(peerID, peerName)
			mgr.RegisterConversation(convID, "Private Chat: "+peerName, false)

			// No packet is sent back. The peer derives the mirror of this
			// session on its own when our first message reaches it.
			if err := sessionMgr.DeriveDirectSession(convID, peerID, peerKey); err != nil {
				tuiPrintf("[ERROR] Could not open chat with %s: %v", peerName, err)
				return
			}
			tuiPrintf("[INFO] Secure session ready with %s", peerName)

		case common.CtrlSenderKey:
			sk, err := common.DecodeSenderKey(pkt.Body)
			if err != nil {
				log.Printf("[ERROR] Bad sender key from %x: %v", pkt.Header.SenderID[:4], err)
				return
			}

			// Membership is not checked here. The server refuses to relay group
			// traffic from a non-member, so a chain installed for one is inert,
			// and a key can legitimately arrive before the roster that would
			// confirm it.
			if err := sessionMgr.SetPeerSenderKey(sk.GroupID, pkt.Header.SenderID, sk.ChainKey, sk.Epoch); err != nil {
				log.Printf("[INFO] Ignoring sender key: %v", err)
				return
			}
			replay(pending.ReleaseSender(sk.GroupID, pkt.Header.SenderID))

		case common.CtrlGroupCreate:
			if len(pkt.Body) < 17 {
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			nameLen := int(pkt.Body[16])
			if len(pkt.Body) < 17+nameLen {
				return
			}
			groupName := string(pkt.Body[17 : 17+nameLen])

			members, _, err := parseRoster(pkt.Body, 17+nameLen)
			if err != nil {
				log.Printf("[ERROR] Bad group roster for %x: %v", convID[:4], err)
				return
			}

			mgr.RegisterConversation(convID, groupName, true)
			for _, m := range members {
				mgr.AddUser(m.UserID, m.Name)
				mgr.UpdatePublicKey(m.UserID, m.PubKey)
				mgr.AddMemberToGroup(convID, m.UserID)
			}
			mgr.SetGroupAdmin(convID, pkt.Header.SenderID, true)

			tuiPrintf("[INFO] Group %s created with %d members. Distributing key...", groupName, len(members))
			bootstrapGroupKeys(convID, members)

		case common.CtrlGroupAdd:
			// convID(16) || nameLen(1) || name || userID(16) || pubKey(32) || nameLen(1) || name
			if len(pkt.Body) < 17 {
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			nameLen := int(pkt.Body[16])
			offset := 17
			if len(pkt.Body) < offset+nameLen {
				return
			}
			groupName := string(pkt.Body[offset : offset+nameLen])
			offset += nameLen

			if len(pkt.Body) < offset+16+32+1 {
				return
			}
			var userID [16]byte
			copy(userID[:], pkt.Body[offset:offset+16])
			offset += 16
			var pubKey [32]byte
			copy(pubKey[:], pkt.Body[offset:offset+32])
			offset += 32
			uNameLen := int(pkt.Body[offset])
			offset++
			if len(pkt.Body) < offset+uNameLen {
				return
			}
			userName := string(pkt.Body[offset : offset+uNameLen])

			if mgr.GetConversationName(convID) == fmt.Sprintf("%x", convID[:4]) {
				mgr.RegisterConversation(convID, groupName, true)
			}
			mgr.AddUser(userID, userName)
			mgr.UpdatePublicKey(userID, pubKey)
			mgr.AddMemberToGroup(convID, userID)
			tuiPrintf("[INFO] User %s added to group %s", userName, groupName)

			// The joiner needs a direct channel with us before any key can reach
			// them, and the membership change means everyone rekeys.
			ensureDirectSession(userID, pubKey)
			distributeSenderKey(convID, mgr.GetGroupMembers(convID))

		case common.CtrlGroupRemove:
			if len(pkt.Body) < 32 {
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)

			if userID == mgr.UserID {
				// We left, or were removed: forget the group and its keys.
				mgr.RemoveConversation(convID)
				sessionMgr.DeleteGroupSession(convID)
				tuiPrintf("[INFO] You are no longer a member of %s", groupName)
				return
			}

			mgr.RemoveMemberFromGroup(convID, userID)
			tuiPrintf("[INFO] User %s removed from group %s", uName, groupName)

			// Their chains are worthless to us now, and ours must become
			// worthless to them: a chain ratchets forward on its own, so without
			// a fresh key they would keep reading the group indefinitely.
			sessionMgr.ForgetSender(convID, userID)
			distributeSenderKey(convID, mgr.GetGroupMembers(convID))

		case common.CtrlGroupMakeAdmin:
			if len(pkt.Body) < 32 {
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.SetGroupAdmin(convID, userID, true)
			tuiPrintf("[INFO] User %s is now an Admin of group %s", uName, groupName)

		case common.CtrlGroupRemoveAdmin:
			if len(pkt.Body) < 32 {
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.SetGroupAdmin(convID, userID, false)
			tuiPrintf("[INFO] User %s is no longer an Admin of group %s", uName, groupName)

		case common.CtrlConvInfoAck:
			info, err := common.DecodeConvInfo(pkt.Body)
			if err != nil {
				log.Printf("[ERROR] Bad conversation info: %v", err)
				return
			}
			applyConvInfo(info)

		}
	}
}

func createGroup(name string, users []string) {
	if name == "" {
		tuiPrintln("Group Name cannot be empty")
		return
	}
	body := make([]byte, 0)
	body = append(body, byte(len(name)))
	body = append(body, []byte(name)...)
	body = append(body, byte(len(users)))

	for _, u := range users {
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

func startPrivateChat(name string) {
	if name == "" {
		tuiPrintln("Target username cannot be empty")
		return
	}
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
		tuiPrintf("%d. %s [%s] (%x)", i, info.Name, typeStr, id[:4])
		i++
	}
}

func addMember(convID [16]byte, username string) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		tuiPrintln("Error: Only admins can perform this action.")
		return
	}
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
	tuiPrintln("Add member request sent.")
}

func removeMember(convID [16]byte, username string) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		tuiPrintln("Error: Only admins can perform this action.")
		return
	}
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
	tuiPrintln("Remove member request sent.")
}

func makeGroupAdmin(convID [16]byte, username string) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		tuiPrintln("Error: Only admins can perform this action.")
		return
	}
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
	tuiPrintln("Make admin request sent.")
}

func removeGroupAdmin(convID [16]byte, username string) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		tuiPrintln("Error: Only admins can perform this action.")
		return
	}
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
	tuiPrintln("Remove admin request sent.")
}

func leaveGroup(convID [16]byte) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}

	username := mgr.Username
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
	tuiPrintln("Leave group request sent.")
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

// convInfoRetry throttles roster lookups. The server answers nothing at all
// when the asker is not a member, so without a cooldown a stream of packets for
// a conversation we have no business in would produce a request each.
const convInfoRetry = 5 * time.Second

var (
	convInfoMu    sync.Mutex
	convInfoAsked = map[[16]byte]time.Time{}
)

// requestConvInfo asks the server who is in a conversation, at most once per
// convInfoRetry per conversation.
func requestConvInfo(convID [16]byte) {
	convInfoMu.Lock()
	if last, asked := convInfoAsked[convID]; asked && time.Since(last) < convInfoRetry {
		convInfoMu.Unlock()
		return
	}
	convInfoAsked[convID] = time.Now()
	convInfoMu.Unlock()

	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlConvInfoRq,
			ConversationID: convID,
			SenderID:       mgr.UserID,
			BodyLen:        common.IDSize,
		},
		Body: convID[:],
	}
	if err := sendPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not request roster for %x: %v", convID[:4], err)
	}
}

// applyConvInfo takes the server's answer about a conversation we did not know,
// establishes whatever keys it makes possible, and replays what was held.
func applyConvInfo(info common.ConvInfo) {
	for _, m := range info.Members {
		if m.UserID == mgr.UserID {
			continue
		}
		mgr.AddUser(m.UserID, m.Name)
		mgr.UpdatePublicKey(m.UserID, m.PubKey)
	}

	if info.IsGroup {
		name := info.Name
		if name == "" {
			name = fmt.Sprintf("%x", info.ConvID[:4])
		}
		mgr.RegisterConversation(info.ConvID, name, true)
		sessionMgr.EnsureGroupSession(info.ConvID)

		for _, m := range info.Members {
			mgr.AddMemberToGroup(info.ConvID, m.UserID)
			if m.UserID == mgr.UserID {
				continue
			}
			// Sender keys travel over the direct channel with each member, so
			// those sessions have to exist before any of them can be read.
			ensureDirectSession(m.UserID, m.PubKey)
		}
		tuiPrintf("[INFO] Joined group %s (%d members)", name, len(info.Members))
	} else {
		for _, m := range info.Members {
			if m.UserID == mgr.UserID {
				continue
			}
			mgr.RegisterConversation(info.ConvID, "Private Chat: "+m.Name, false)
			if err := sessionMgr.DeriveDirectSession(info.ConvID, m.UserID, m.PubKey); err != nil {
				tuiPrintf("[ERROR] Could not open chat with %s: %v", m.Name, err)
				return
			}
			tuiPrintf("[INFO] Secure session ready with %s", m.Name)
		}
	}

	replay(pending.Release(info.ConvID))
}

// ensureDirectSession derives the session with a peer if there is not one yet.
func ensureDirectSession(peerID [16]byte, pubKey [32]byte) {
	convID := common.HashIDs(mgr.UserID, peerID)
	if _, ok := sessionMgr.GetSession(convID); ok {
		return
	}
	if err := sessionMgr.DeriveDirectSession(convID, peerID, pubKey); err != nil {
		log.Printf("[ERROR] Could not derive session with %x: %v", peerID[:4], err)
	}
}

// replay feeds held packets back through delivery now that a key has arrived.
// Anything still blocked simply parks again.
func replay(pkts []common.Packet) {
	for _, p := range pkts {
		deliver(p)
	}
}

// parseRoster reads the member list the server appends to group broadcasts:
// count(1) then, per member, id(16) ‖ identityKey(32) ‖ nameLen(1) ‖ name.
func parseRoster(body []byte, offset int) ([]common.ConvMember, int, error) {
	if len(body) < offset+1 {
		return nil, offset, fmt.Errorf("roster truncated before member count")
	}
	count := int(body[offset])
	offset++

	members := make([]common.ConvMember, 0, count)
	for i := 0; i < count; i++ {
		if len(body) < offset+16+32+1 {
			return nil, offset, fmt.Errorf("roster truncated at member %d", i)
		}
		var m common.ConvMember
		copy(m.UserID[:], body[offset:offset+16])
		offset += 16
		copy(m.PubKey[:], body[offset:offset+32])
		offset += 32

		nameLen := int(body[offset])
		offset++
		if len(body) < offset+nameLen {
			return nil, offset, fmt.Errorf("roster truncated in member %d name", i)
		}
		m.Name = string(body[offset : offset+nameLen])
		offset += nameLen

		members = append(members, m)
	}
	return members, offset, nil
}

// bootstrapGroupKeys sets up everything this client needs to take part in a
// group: a direct session with every other member, its own sending chain, and
// that chain delivered to each of them.
//
// No round trip is needed for the sessions. The identity keys arrived with the
// roster, and the server registered the pairwise conversations when it created
// the group, so the key packets have somewhere to go immediately.
func bootstrapGroupKeys(groupID [16]byte, members []common.ConvMember) {
	sessionMgr.EnsureGroupSession(groupID)

	ids := make([][16]byte, 0, len(members))
	for _, m := range members {
		if m.UserID == mgr.UserID {
			continue
		}
		ensureDirectSession(m.UserID, m.PubKey)
		ids = append(ids, m.UserID)
	}
	distributeSenderKey(groupID, ids)
}

// distributeSenderKey generates a fresh sending chain for a group and unicasts
// it to every current member over the direct channel shared with each. Called
// when the group is first keyed and again on every membership change.
func distributeSenderKey(groupID [16]byte, memberIDs [][16]byte) {
	// Only the key RotateSenderKey returns may be sent. The live chain ratchets
	// forward with every message, so reading it back later would hand peers a
	// key that cannot open anything already sent in this epoch.
	key, epoch, err := sessionMgr.RotateSenderKey(groupID)
	if err != nil {
		tuiPrintf("[ERROR] Could not generate a sender key: %v", err)
		return
	}
	payload := (&common.SenderKeyPayload{GroupID: groupID, Epoch: epoch, ChainKey: key}).Encode()

	sent, failed := 0, 0
	for _, id := range memberIDs {
		if id == mgr.UserID {
			continue
		}
		if sendSenderKey(id, payload) {
			sent++
		} else {
			failed++
		}
	}

	if failed > 0 {
		tuiPrintf("[WARN] Sent group key v%d to %d members, %d could not be reached", epoch, sent, failed)
		return
	}
	log.Printf("[DEBUG] distributeSenderKey: group %x epoch %d to %d members", groupID[:4], epoch, sent)
}

// sendSenderKey delivers one chain key to one member, encrypted to them alone
// over the direct conversation the two share.
func sendSenderKey(peerID [16]byte, payload []byte) bool {
	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlSenderKey,
			ConversationID: common.HashIDs(mgr.UserID, peerID),
			MessageID:      genID(),
			SenderID:       mgr.UserID,
			BodyLen:        uint32(len(payload)),
		},
		Body: payload,
	}
	if err := sessionMgr.EncryptPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not seal sender key for %x: %v", peerID[:4], err)
		return false
	}
	if err := sendPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not send sender key to %x: %v", peerID[:4], err)
		return false
	}
	return true
}
