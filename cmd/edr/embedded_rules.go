package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	embeddedrules "edrsystem/rules/yaraRules"
)

const (
	embeddedRulesCacheDirName = ".c-eyes-yara-rules-cache"
	embeddedRulesDigestFile   = ".rules.sha256"
)

var (
	embeddedRulesMu             sync.Mutex
	embeddedRulesDir            string
	embeddedRulesErr            error
	embeddedRulesExecutableFunc = os.Executable
	embeddedRulesTempDirFunc    = os.TempDir
	embeddedRulesMkdirAllFunc   = os.MkdirAll
)

func ensureEmbeddedRulesDir() (string, error) {
	embeddedRulesMu.Lock()
	defer embeddedRulesMu.Unlock()

	if strings.TrimSpace(embeddedRulesDir) != "" || embeddedRulesErr != nil {
		return embeddedRulesDir, embeddedRulesErr
	}

	rulesDigest, err := computeEmbeddedRulesDigest()
	if err != nil {
		embeddedRulesErr = err
		return embeddedRulesDir, embeddedRulesErr
	}

	cacheDir, err := createEmbeddedRulesCacheDir()
	if err != nil {
		embeddedRulesErr = err
		return embeddedRulesDir, embeddedRulesErr
	}

	matched, err := cachedRulesMatch(cacheDir, rulesDigest)
	if err != nil {
		embeddedRulesErr = err
		return embeddedRulesDir, embeddedRulesErr
	}
	if !matched {
		if err := rebuildEmbeddedRulesCache(cacheDir, rulesDigest); err != nil {
			embeddedRulesErr = err
			return embeddedRulesDir, embeddedRulesErr
		}
	}

	embeddedRulesDir = cacheDir

	return embeddedRulesDir, embeddedRulesErr
}

func createEmbeddedRulesCacheDir() (string, error) {
	if exe, err := embeddedRulesExecutableFunc(); err == nil {
		exe = strings.TrimSpace(exe)
		if exe != "" {
			exeDir := strings.TrimSpace(filepath.Dir(exe))
			if exeDir != "" {
				cacheDir := filepath.Join(exeDir, embeddedRulesCacheDirName)
				if err := embeddedRulesMkdirAllFunc(cacheDir, 0o755); err == nil {
					return cacheDir, nil
				}
			}
		}
	}

	fallbackBase := strings.TrimSpace(embeddedRulesTempDirFunc())
	if fallbackBase == "" {
		fallbackBase = os.TempDir()
	}
	cacheDir := filepath.Join(fallbackBase, embeddedRulesCacheDirName)
	if err := embeddedRulesMkdirAllFunc(cacheDir, 0o755); err != nil {
		return "", err
	}
	return cacheDir, nil
}

func rebuildEmbeddedRulesCache(cacheDir, rulesDigest string) error {
	if err := clearDirectory(cacheDir); err != nil {
		return err
	}

	err := fs.WalkDir(embeddedrules.RulesFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		cleaned := filepath.Clean(path)
		if cleaned == "." {
			return nil
		}

		dstPath := filepath.Join(cacheDir, cleaned)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".yar", ".yara", ".yr":
		default:
			return nil
		}

		content, err := embeddedrules.RulesFS.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dstPath, content, 0o644)
	})
	if err != nil {
		return err
	}

	digestPath := filepath.Join(cacheDir, embeddedRulesDigestFile)
	if err := os.WriteFile(digestPath, []byte(rulesDigest+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

func computeEmbeddedRulesDigest() (string, error) {
	paths := make([]string, 0, 64)
	err := fs.WalkDir(embeddedrules.RulesFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".yar", ".yara", ".yr":
			paths = append(paths, filepath.Clean(path))
		default:
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Strings(paths)
	hasher := sha256.New()
	for _, path := range paths {
		content, err := embeddedrules.RulesFS.ReadFile(path)
		if err != nil {
			return "", err
		}
		_, _ = hasher.Write([]byte(path))
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write(content)
		_, _ = hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func cachedRulesMatch(cacheDir, expectedDigest string) (bool, error) {
	digestPath := filepath.Join(cacheDir, embeddedRulesDigestFile)
	content, err := os.ReadFile(digestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(string(content)) == expectedDigest, nil
}

func clearDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dir, 0o755)
		}
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func cleanupEmbeddedRulesDir() {
	embeddedRulesMu.Lock()
	dir := embeddedRulesDir
	embeddedRulesDir = ""
	embeddedRulesErr = nil
	embeddedRulesMu.Unlock()

	if strings.TrimSpace(dir) != "" {
		_ = os.RemoveAll(dir)
	}
}
