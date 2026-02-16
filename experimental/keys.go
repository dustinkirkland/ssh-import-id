package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type FingerprintInfo struct {
	Bits    string
	Hash    string
	Comment string
	Type    string
}

// getKeyFingerprint computes the SSH key fingerprint
func getKeyFingerprint(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}

	// Parse the public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}

	// Compute SHA256 fingerprint
	hash := sha256.Sum256(pubKey.Marshal())
	fp := base64.StdEncoding.EncodeToString(hash[:])
	fp = strings.TrimRight(fp, "=")

	return fmt.Sprintf("SHA256:%s", fp)
}

// getKeyFingerprintInfo returns detailed fingerprint information
func getKeyFingerprintInfo(line string) *FingerprintInfo {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	// Parse the public key
	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil
	}

	// Compute SHA256 fingerprint
	hash := sha256.Sum256(pubKey.Marshal())
	fp := base64.StdEncoding.EncodeToString(hash[:])
	fp = strings.TrimRight(fp, "=")

	// Get key type and bits
	keyType := pubKey.Type()
	bits := getBitLength(pubKey)

	// Format the comment (extract from fields or use default)
	if comment == "" && len(fields) > 2 {
		comment = strings.Join(fields[2:], " ")
	}
	if comment == "" {
		comment = "no comment"
	}

	// Map key types to display names
	displayType := mapKeyType(keyType)

	return &FingerprintInfo{
		Bits:    fmt.Sprintf("%d", bits),
		Hash:    fmt.Sprintf("SHA256:%s", fp),
		Comment: comment,
		Type:    fmt.Sprintf("(%s)", displayType),
	}
}

// getBitLength returns the bit length of the key
func getBitLength(pubKey ssh.PublicKey) int {
	switch key := pubKey.(type) {
	case ssh.CryptoPublicKey:
		switch k := key.CryptoPublicKey().(type) {
		case interface{ Size() int }:
			return k.Size() * 8
		}
	}

	// Default bit lengths for known key types
	switch pubKey.Type() {
	case "ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com":
		return 256
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com":
		return 256
	case "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384-cert-v01@openssh.com":
		return 384
	case "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521-cert-v01@openssh.com":
		return 521
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		return 256
	case "sk-ssh-ed25519@openssh.com":
		return 256
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		// Try to get actual RSA key size
		return 2048 // Default if we can't determine
	case "ssh-dss":
		return 1024
	}

	return 0
}

// mapKeyType maps SSH key types to display names
func mapKeyType(keyType string) string {
	switch keyType {
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		return "RSA"
	case "ssh-dss":
		return "DSA"
	case "ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com":
		return "ED25519"
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com":
		return "ECDSA"
	case "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384-cert-v01@openssh.com":
		return "ECDSA"
	case "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521-cert-v01@openssh.com":
		return "ECDSA"
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		return "ECDSA-SK"
	case "sk-ssh-ed25519@openssh.com":
		return "ED25519-SK"
	default:
		return keyType
	}
}

// readKeyfile reads the authorized_keys file
func readKeyfile(path string) ([]string, error) {
	if path == "-" || !fileExists(path) {
		return []string{}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

// writeKeyfile writes keys to the authorized_keys file
func writeKeyfile(path string, keys []string, append bool) error {
	if path == "-" {
		// Write to stdout
		for _, key := range keys {
			fmt.Println(key)
			fmt.Println()
		}
		return nil
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	flags := os.O_CREATE | os.O_WRONLY
	if append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	file, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, key := range keys {
		if key != "" {
			writer.WriteString(key)
			writer.WriteString("\n\n")
		}
	}

	return writer.Flush()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
