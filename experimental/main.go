package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	Version        = "6.0"
	DefaultProto   = "lp"
	DefaultTimeout = 15 * time.Second
)

var (
	outputFile  string
	removeMode  bool
	userAgent   string
	showVersion bool
)

func init() {
	flag.StringVar(&outputFile, "o", "", "Write output to file (default ~/.ssh/authorized_keys)")
	flag.StringVar(&outputFile, "output", "", "Write output to file (default ~/.ssh/authorized_keys)")
	flag.BoolVar(&removeMode, "r", false, "Remove a key from authorized keys file")
	flag.BoolVar(&removeMode, "remove", false, "Remove a key from authorized keys file")
	flag.StringVar(&userAgent, "u", "", "Append to the http user agent string")
	flag.StringVar(&userAgent, "useragent", "", "Append to the http user agent string")
	flag.BoolVar(&showVersion, "version", false, "Show version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ssh-import-id [OPTIONS] USERID [USERID...]\n\n")
		fmt.Fprintf(os.Stderr, "Authorize SSH public keys from trusted online identities.\n\n")
		fmt.Fprintf(os.Stderr, "Positional arguments:\n")
		fmt.Fprintf(os.Stderr, "  USERID    User IDs to import (e.g., gh:username, lp:username, gl:username)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSupported protocols:\n")
		fmt.Fprintf(os.Stderr, "  gh:  GitHub\n")
		fmt.Fprintf(os.Stderr, "  gl:  GitLab\n")
		fmt.Fprintf(os.Stderr, "  lp:  Launchpad (default)\n")
	}

	// Set up logging to match Python behavior
	log.SetFlags(0)
	log.SetPrefix("")
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Printf("ssh-import-id %s\n", Version)
		os.Exit(0)
	}

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Set restrictive umask
	oldUmask := setUmask(0177)
	defer setUmask(oldUmask)

	userIDs := flag.Args()
	var errors []string
	allKeys := []string{}

	for _, userID := range userIDs {
		proto, username := parseUserID(userID)

		var keys []string
		var err error

		if removeMode {
			keys, err = removeKeys(proto, username, outputFile)
			if err != nil {
				log.Printf("ERROR: %v", err)
				errors = append(errors, userID)
				continue
			}
			if len(keys) == 0 {
				errors = append(errors, userID)
			}
		} else {
			keys, err = importKeys(proto, username, outputFile, userAgent)
			if err != nil {
				log.Printf("ERROR: %v", err)
				errors = append(errors, userID)
				continue
			}
			if len(keys) == 0 {
				errors = append(errors, userID)
			}
		}

		allKeys = append(allKeys, keys...)
	}

	action := "Authorized"
	if removeMode {
		action = "Removed"
	}

	log.Printf("INFO: [%d] SSH keys [%s]", len(allKeys), action)

	if len(errors) > 0 {
		log.Fatalf("ERROR: No matching keys found for [%s]", strings.Join(errors, ","))
	}
}

func parseUserID(userID string) (proto, username string) {
	parts := strings.SplitN(userID, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return DefaultProto, userID
}

func importKeys(proto, username, output, userAgent string) ([]string, error) {
	// Fetch keys from the specified protocol
	fetchedKeys, err := fetchKeys(proto, username, userAgent)
	if err != nil {
		return nil, err
	}

	if len(fetchedKeys) == 0 {
		return nil, fmt.Errorf("no keys found for %s:%s", proto, username)
	}

	// Get the output keyfile path
	keyfile, err := getKeyfilePath(output)
	if err != nil {
		return nil, err
	}

	// Read existing keys
	existingKeys, err := readKeyfile(keyfile)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("could not read authorized key file [%s]: %v", keyfile, err)
	}

	// Build map of existing key fingerprints
	existingFPs := make(map[string]bool)
	for _, line := range existingKeys {
		if fp := getKeyFingerprint(line); fp != "" {
			existingFPs[fp] = true
		}
	}

	// Filter out keys we already have and add comment
	commentStr := fmt.Sprintf("# ssh-import-id %s:%s", proto, username)
	var newKeys []string
	var imported []string

	for _, key := range fetchedKeys {
		fields := strings.Fields(key)
		if len(fields) < 2 {
			continue
		}

		// Add our comment
		keyWithComment := key + " " + commentStr
		fp := getKeyFingerprint(keyWithComment)

		if fp != "" {
			fpInfo := getKeyFingerprintInfo(keyWithComment)
			if existingFPs[fp] {
				log.Printf("INFO: Already authorized %s", formatFingerprint(fpInfo))
			} else {
				newKeys = append(newKeys, keyWithComment)
				log.Printf("INFO: Authorized key %s", formatFingerprint(fpInfo))
			}
			imported = append(imported, keyWithComment)
		}
	}

	// Write new keys to file
	if len(newKeys) > 0 {
		if err := writeKeyfile(keyfile, newKeys, true); err != nil {
			return nil, err
		}
	}

	return imported, nil
}

func removeKeys(proto, username, output string) ([]string, error) {
	keyfile, err := getKeyfilePath(output)
	if err != nil {
		return nil, err
	}

	existingKeys, err := readKeyfile(keyfile)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	commentStr := fmt.Sprintf("# ssh-import-id %s:%s", proto, username)
	var keepKeys []string
	var removed []string

	for _, line := range existingKeys {
		if strings.Contains(line, commentStr) {
			fpInfo := getKeyFingerprintInfo(line)
			log.Printf("INFO: Removed labeled key %s", formatFingerprint(fpInfo))
			removed = append(removed, line)
		} else {
			keepKeys = append(keepKeys, line)
		}
	}

	if len(removed) > 0 {
		if err := writeKeyfile(keyfile, keepKeys, false); err != nil {
			return nil, err
		}
	}

	return removed, nil
}

func getKeyfilePath(path string) (string, error) {
	if path == "" {
		home := os.Getenv("HOME")
		if home == "" {
			return "", fmt.Errorf("HOME environment variable not set")
		}
		path = filepath.Join(home, ".ssh", "authorized_keys")
	}

	// Special case: stdout
	if path == "-" {
		return path, nil
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	// Security check: validate path is within user's home or /tmp
	home := os.Getenv("HOME")
	if home == "" {
		return "", fmt.Errorf("HOME environment variable not set")
	}

	homeAbs, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}

	tmpAbs, err := filepath.Abs("/tmp")
	if err != nil {
		return "", err
	}

	// Check if path is within allowed directories
	if !strings.HasPrefix(absPath, homeAbs+string(os.PathSeparator)) &&
		!strings.HasPrefix(absPath, tmpAbs+string(os.PathSeparator)) &&
		absPath != homeAbs {
		return "", fmt.Errorf("output path must be within user's home directory or /tmp: %s", path)
	}

	return absPath, nil
}

func formatFingerprint(info *FingerprintInfo) string {
	if info == nil {
		return ""
	}
	return fmt.Sprintf("[%s, %s, %s, %s]", info.Bits, info.Hash, info.Comment, info.Type)
}
