// SPDX-License-Identifier: BSD-2-Clause
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"

	xbps_crypto "github.com/Duncaen/go-xbps/crypto"
)

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func writeToFileAtomic(path string, data []byte) error {
	sigf, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpfile := sigf.Name()
	if _, err := sigf.Write(data); err != nil {
		sigf.Close()
		os.Remove(tmpfile)
		return err
	}
	if err := sigf.Close(); err != nil {
		return os.Remove(tmpfile)
	}
	return os.Rename(tmpfile, path)
}

func sign1(priv *rsa.PrivateKey, hash []byte, path string) error {
	sig, err := xbps_crypto.Sign(priv, hash)
	if err != nil {
		return err
	}
	return writeToFileAtomic(path, sig)
}

func sign2(priv *rsa.PrivateKey, hash []byte, path string) error {
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash)
	if err != nil {
		return err
	}
	return writeToFileAtomic(path, sig)
}

func missing(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

func sign(priv *rsa.PrivateKey, path string) error {
	needSig1, err := missing(path + ".sig")
	if err != nil {
		return err
	}
	needSig2, err := missing(path + ".sig2")
	if err != nil {
		return err
	}
	if !needSig1 && !needSig2 {
		return nil
	}
	log.Printf("Signing: %s\n", path)
	hash, err := hashFile(path)
	if err != nil {
		return err
	}
	if needSig1 {
		if err := sign1(priv, hash, path+".sig"); err != nil {
			return err
		}
	}
	if needSig2 {
		if err := sign2(priv, hash, path+".sig2"); err != nil {
			return err
		}
	}
	return nil
}

func watch(priv *rsa.PrivateKey, dirs []string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		err = watcher.Add(dir)
		if err != nil {
			log.Fatal(err)
		}
		files, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, file := range files {
			if filepath.Ext(file.Name()) != ".xbps" {
				continue
			}
			if err := sign(priv, filepath.Join(dir, file.Name())); err != nil {
				return err
			}
		}
	}
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !event.Has(fsnotify.Create) || filepath.Ext(event.Name) != ".xbps" {
				continue
			}
			if err := sign(priv, event.Name); err != nil {
				return err
			}
		case err := <-watcher.Errors:
			return err
		}
	}
}

func loadPrivateKey(path string, passphrase []byte) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(*privKeyFlag)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	var buf []byte
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		buf, err = x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			if err == x509.IncorrectPasswordError {
				return nil, err
			}
			return nil, err
		}
	} else {
		buf = block.Bytes
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(buf)
	default:
		return nil, fmt.Errorf("unsupported private key format: %s\n", block.Type)
	}
}

var (
	privKeyFlag        = flag.String("private-key", "", "private key path")
	watchFlag          = flag.Bool("watch", false, "watch for changes to sign new files")
	passphraseFileFlag = flag.String("passphrase-file", "", "passphrase file path")
)

func main() {
	flag.Parse()
	var passphrase []byte
	if *privKeyFlag == "" {
		log.Fatal("-private-key flag required")
	}
	if *passphraseFileFlag != "" {
		var err error
		passphrase, err = os.ReadFile(*passphraseFileFlag)
		if err != nil {
			log.Fatal(err)
		}
		passphrase = bytes.TrimSpace(passphrase)
	}
	privKey, err := loadPrivateKey(*privKeyFlag, passphrase)
	if err != nil {
		log.Fatal(err)
	}
	if *watchFlag {
		log.Fatal(watch(privKey, flag.Args()))
	} else {
		for _, path := range flag.Args() {
			if !strings.HasSuffix(path, ".xbps") {
				continue
			}
			if err := sign(privKey, path); err != nil {
				log.Println(err)
			}
		}
	}
}
