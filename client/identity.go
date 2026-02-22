package main

import (
	common "common"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/curve25519"
)

const KeyFileName = "identity.key"

// IdentityManager handles the client's long-term identity keys.
type IdentityManager struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func NewIdentityManager() (*IdentityManager, error) {
	mgr := &IdentityManager{}
	if err := mgr.loadOrGenerate(); err != nil {
		return nil, err
	}
	return mgr, nil
}

func (im *IdentityManager) loadOrGenerate() error {
	f, err := os.Open(KeyFileName)
	if err == nil {
		defer f.Close()
		buf := make([]byte, 64)
		if _, err := io.ReadFull(f, buf); err != nil {
			return err
		}
		copy(im.PrivateKey[:], buf[:32])

		// CRITICAL: Derive Public Key from Private Key to ensure consistency
		curve25519.ScalarBaseMult(&im.PublicKey, &im.PrivateKey)

		fmt.Printf("Loaded Identity Key: %x... (derived from priv)\n", im.PublicKey[:4])
		return nil
	}

	fmt.Println("Generating new Identity Keys...")
	priv, pub, err := common.GenerateIdentityKeys()
	if err != nil {
		return err
	}
	im.PrivateKey = priv
	im.PublicKey = pub

	f, err = os.Create(KeyFileName)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(im.PrivateKey[:]); err != nil {
		return err
	}
	if _, err := f.Write(im.PublicKey[:]); err != nil {
		return err
	}

	return nil
}

func (im *IdentityManager) GetPublicKey() [32]byte {
	return im.PublicKey
}
