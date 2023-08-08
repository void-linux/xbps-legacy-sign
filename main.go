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
	"strings"

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

func sign(priv *rsa.PrivateKey, filepath, sigpath string) error {
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
	for _, path := range flag.Args() {
		if !strings.HasSuffix(path, ".xbps") {
			continue
		}
		sigpath := path + ".sig"
		if _, err := os.Stat(sigpath); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			log.Println(err)
			continue
		}
		if err := sign(privKey, path, sigpath); err != nil {
			log.Println(err)
		}
	}
}
