package main

import (
	"fmt"
	common "hello_hello/Common"
	"testing"
)

func TestRatchetLogic(t *testing.T) {
	// 1. Setup Identities (In-Memory)
	alicePriv, alicePub, _ := common.GenerateIdentityKeys()
	aliceID := &IdentityManager{PrivateKey: alicePriv, PublicKey: alicePub}

	bobPriv, bobPub, _ := common.GenerateIdentityKeys()
	bobID := &IdentityManager{PrivateKey: bobPriv, PublicKey: bobPub}

	aliceMgr := NewSessionManager(aliceID)
	bobMgr := NewSessionManager(bobID)

	convID := [16]byte{0xAB, 0xCD}

	// 2. Perform Handshake (Simulated)
	// Alice -> Bob: Ephemeral Key
	pkt, err := aliceMgr.PerformHandshake(convID, bobID.PublicKey)
	if err != nil {
		t.Fatalf("Alice Handshake Init failed: %v", err)
	}

	// Bob receives Handshake
	if err := bobMgr.HandleHandshake(*pkt); err != nil {
		t.Fatalf("Bob Handle Handshake failed: %v", err)
	}

	// Verify Roots match (implicitly, by checking if they can talk)
	// Note: In real Double Ratchet, Alice's Send = Bob's Recv, and vice versa.

	// 3. Test In-Order Communication (Alice -> Bob)
	msgs := []string{"Hello", "World", "This", "Is", "Ratchet"}
	encryptedPkts := make([]*common.Packet, len(msgs))

	for i, msg := range msgs {
		pkt := &common.Packet{
			Header: common.Header{
				ConversationID: convID,
				MsgType:        common.MsgText,
			},
			Body: []byte(msg),
		}
		if err := aliceMgr.EncryptPacket(pkt); err != nil {
			t.Fatalf("Encrypt failed for msg %d: %v", i, err)
		}
		encryptedPkts[i] = pkt
	}

	for i, pkt := range encryptedPkts {
		err := bobMgr.DecryptPacket(pkt)
		if err != nil {
			t.Fatalf("Decrypt failed for msg %d: %v", i, err)
		}
		if string(pkt.Body) != msgs[i] {
			t.Errorf("Message mismatch. Got %s, want %s", string(pkt.Body), msgs[i])
		}
	}
	fmt.Println("In-Order Test Passed")

	// 4. Test Out-of-Order Communication (Alice -> Bob)
	// Messages: 5, 6, 7, 8, 9 (indices relative to session start, so actually 5..9)
	moreMsgs := []string{"Msg5", "Msg6", "Msg7", "Msg8", "Msg9"}
	oooPkts := make([]*common.Packet, len(moreMsgs))

	for i, msg := range moreMsgs {
		pkt := &common.Packet{
			Header: common.Header{
				ConversationID: convID,
				MsgType:        common.MsgText,
			},
			Body: []byte(msg),
		}
		if err := aliceMgr.EncryptPacket(pkt); err != nil {
			t.Fatalf("Encrypt failed for OOO msg %d: %v", i, err)
		}
		oooPkts[i] = pkt
		// Only after encrypt does the body contain the ciphertext
	}

	// Deliver Order: 7, 9, 5, 6, 8 (Indices: 2, 4, 0, 1, 3)
	order := []int{2, 4, 0, 1, 3}

	for _, idx := range order {
		pkt := oooPkts[idx]
		// We encounter a "FlagEncrypted must be set" check potentially
		// Note that DecryptPacket strips the flag.
		// So we must be careful if we reuse pointers?
		// Here test reuses the pointer, but it's fine because we decrypt once per packet.

		fmt.Printf("Bob receiving message index %d (SeqNum should be %d)...\n", 5+idx, 5+idx)
		err := bobMgr.DecryptPacket(pkt)
		if err != nil {
			t.Fatalf("OOO Decrypt failed for msg index %d: %v", idx, err)
		}
		if string(pkt.Body) != moreMsgs[idx] {
			t.Errorf("OOO Message mismatch. Got %s, want %s", string(pkt.Body), moreMsgs[idx])
		}
	}
	fmt.Println("Out-of-Order Test Passed")
}
