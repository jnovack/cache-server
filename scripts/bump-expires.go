// bump-expires.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	contentTypeFilter string
	expiresOffset     string
	rootPath          string
)

func init() {
	flag.StringVar(&contentTypeFilter, "content-type", "", "Only bump files with this content_type")
	flag.StringVar(&expiresOffset, "expires", "", "Offset to add to expires_at (e.g. +7d, -3h, +30m)")
	flag.StringVar(&rootPath, "path", ".", "Root directory to scan for *.meta.json files")
}

func main() {
	flag.Parse()
	if contentTypeFilter == "" || expiresOffset == "" {
		log.Fatal("Usage: go run bump-expires.go -content-type <type> -expires <offset> [-path <dir>]")
	}

	offsetDur, err := parseOffset(expiresOffset)
	if err != nil {
		log.Fatalf("Invalid expires offset %q: %v", expiresOffset, err)
	}

	err = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".meta.json") {
			return nil
		}
		return processFile(path, offsetDur)
	})
	if err != nil {
		log.Fatalf("Error scanning directory: %v", err)
	}
}

// parseOffset parses strings like "+7d", "-3h", "+30m", "+45s".
func parseOffset(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("too short")
	}

	sign := 1
	switch s[0] {
	case '+':
		sign = 1
	case '-':
		sign = -1
	default:
		return 0, fmt.Errorf("must start with + or -")
	}

	unit := s[len(s)-1]
	numPart := s[1 : len(s)-1]
	n, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q: %v", numPart, err)
	}

	var dur time.Duration
	switch unit {
	case 'd':
		dur = time.Duration(n*24) * time.Hour
	case 'h':
		dur = time.Duration(n) * time.Hour
	case 'm':
		dur = time.Duration(n) * time.Minute
	case 's':
		dur = time.Duration(n) * time.Second
	default:
		return 0, fmt.Errorf("unknown unit %q, use d (days), h, m, or s", unit)
	}

	return time.Duration(sign) * dur, nil
}

func processFile(path string, offset time.Duration) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("parse JSON %s: %w", path, err)
	}

	// filter by content_type
	ct, _ := obj["content_type"].(string)
	if ct != contentTypeFilter {
		return nil
	}

	// get expires_at
	ea, ok := obj["expires_at"].(string)
	if !ok || ea == "" {
		return nil
	}

	t, err := time.Parse(time.RFC3339Nano, ea)
	if err != nil {
		return fmt.Errorf("parse expires_at %q in %s: %w", ea, path, err)
	}

	// bump and format back
	t2 := t.Add(offset)
	obj["expires_at"] = t2.Format(time.RFC3339Nano)

	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON for %s: %w", path, err)
	}

	// Write back with a trailing newline
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	fmt.Printf("Updated %s: expires_at → %s\n", path, obj["expires_at"])
	return nil
}
