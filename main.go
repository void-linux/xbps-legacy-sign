package main

import (
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

	"github.com/Duncaen/go-xbps/crypto"
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

func sign(priv *rsa.PrivateKey, filepath string) error {
	sigpath := filepath + ".sig"
	if _, err := os.Stat(sigpath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	log.Printf("Signing: %s\n", filepath)
	hash, err := hashFile(filepath)
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(priv, hash)
	if err != nil {
		return err
	}
	sigf, err := os.Create(sigpath)
	if err != nil {
		return err
	}
	if _, err := sigf.Write(sig); err != nil {
		sigf.Close()
		os.Remove(sigpath)
		return err
	}
	return sigf.Close()
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

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(*privKeyFlag)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, fmt.Errorf("encrypted private keys not supported")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key format: %s\n", block.Type)
	}
}

var (
	privKeyFlag = flag.String("private-key", "", "private key path")
	watchFlag = flag.Bool("watch", false, "watch for changes to sign new files")
)

func main() {
	flag.Parse()
	if *privKeyFlag == "" {
		log.Fatal("-private-key flag required")
	}
	privKey, err := loadPrivateKey(*privKeyFlag)
	if err != nil {
		log.Fatal(err)
	}
	if *watchFlag {
		log.Fatal(watch(privKey,flag.Args()))
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
