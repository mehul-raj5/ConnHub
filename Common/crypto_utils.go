package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	KeySize   = 32
	NonceSize = 24
)

// GenerateIdentityKeys generates a long-term Identity Key Pair (X25519).
func GenerateIdentityKeys() (private, public [KeySize]byte, err error) {
	return generateKeyPair()
}

func GenerateEphemeralKeys() (private, public [KeySize]byte, err error) {
	return generateKeyPair()
}

func generateKeyPair() (private, public [KeySize]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		return private, public, err
	}

	// Clamp the private key (RFC 7748)
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	curve25519.ScalarBaseMult(&public, &private)
	return private, public, nil
}

func DeriveSharedSecret(private, peerPublic [KeySize]byte) ([KeySize]byte, error) {
	secretSlice, err := curve25519.X25519(private[:], peerPublic[:])
	if err != nil {
		return [KeySize]byte{}, err
	}
	var secret [KeySize]byte
	copy(secret[:], secretSlice)
	return secret, nil
}

func DeriveSessionKey(sharedSecret [KeySize]byte, salt, infoContext []byte) ([KeySize]byte, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret[:], salt, infoContext)
	var sessionKey [KeySize]byte
	if _, err := io.ReadFull(hkdf, sessionKey[:]); err != nil {
		return sessionKey, err
	}
	return sessionKey, nil
}

func Encrypt(key [KeySize]byte, plaintext []byte, headerBytes []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, headerBytes), nil
}

func Decrypt(key [KeySize]byte, data []byte, headerBytes []byte) ([]byte, error) {
	if len(data) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	return aead.Open(nil, nonce, ciphertext, headerBytes)
}

func HashIDs(id1, id2 [16]byte) [16]byte {
	first, second := id1, id2
	for i := 0; i < 16; i++ {
		if id1[i] < id2[i] {
			break
		} else if id1[i] > id2[i] {
			first, second = id2, id1
			break
		}
	}

	h := sha256.New()
	h.Write(first[:])
	h.Write(second[:])
	fullHash := h.Sum(nil)

	var convID [16]byte
	copy(convID[:], fullHash[:16])
	return convID
}

func IsValidKey(k [KeySize]byte) bool {
	zero := [KeySize]byte{}
	return k != zero
}

func RatchetStep(chainKey [KeySize]byte) (messageKey, nextChainKey [KeySize]byte) {
	macMsg := hmac.New(sha256.New, chainKey[:])
	macMsg.Write([]byte{0x01})
	copy(messageKey[:], macMsg.Sum(nil))

	macChain := hmac.New(sha256.New, chainKey[:])
	macChain.Write([]byte{0x02})
	copy(nextChainKey[:], macChain.Sum(nil))

	return
}

func DeriveRatchetRoots(sharedSecret [KeySize]byte) (rootA, rootB [KeySize]byte) {
	macA := hmac.New(sha256.New, sharedSecret[:])
	macA.Write([]byte("ConnHub_Ratchet_Root_A"))
	copy(rootA[:], macA.Sum(nil))

	macB := hmac.New(sha256.New, sharedSecret[:])
	macB.Write([]byte("ConnHub_Ratchet_Root_B"))
	copy(rootB[:], macB.Sum(nil))

	return
}
