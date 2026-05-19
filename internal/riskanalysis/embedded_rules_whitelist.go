package riskanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	embeddedrules "edrsystem/rules/yaraRules"
)

const (
	embeddedRulesCacheDirMarker = `\.c-eyes-yara-rules-cache\`
	embeddedRulesDigestFileName = ".rules.sha256"
)

var (
	embeddedRulesAllowOnce       sync.Once
	embeddedRulesAllowHashes     map[string]string
	embeddedRulesAllowDigestHash string
	embeddedRulesAllowErr        error
)

func initEmbeddedRulesWhitelist() {
	hashes := make(map[string]string, 64)
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
		default:
			return nil
		}

		cleaned := filepath.Clean(path)
		content, err := embeddedrules.RulesFS.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		hashes[hex.EncodeToString(sum[:])] = cleaned
		paths = append(paths, cleaned)
		return nil
	})
	if err != nil {
		embeddedRulesAllowErr = err
		return
	}

	digest, err := computeEmbeddedRulesDigest(paths)
	if err != nil {
		embeddedRulesAllowErr = err
		return
	}

	digestBytes := []byte(digest + "\n")
	digestSum := sha256.Sum256(digestBytes)

	embeddedRulesAllowHashes = hashes
	embeddedRulesAllowDigestHash = hex.EncodeToString(digestSum[:])
}

func computeEmbeddedRulesDigest(paths []string) (string, error) {
	sortedPaths := append([]string{}, paths...)
	sort.Strings(sortedPaths)

	hasher := sha256.New()
	for _, path := range sortedPaths {
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

func matchEmbeddedRulesCache(meta TargetMetadata) (bool, string, []WhitelistEvidence) {
	embeddedRulesAllowOnce.Do(initEmbeddedRulesWhitelist)
	if embeddedRulesAllowErr != nil {
		return false, "", nil
	}

	path := normalizePathLike(meta.TargetPath)
	if path == "" || !strings.Contains(path, embeddedRulesCacheDirMarker) {
		return false, "", nil
	}

	base := strings.ToLower(strings.TrimSpace(filepath.Base(meta.TargetPath)))
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(meta.TargetPath)))

	hash := normalizeHex(meta.Hashes.Sha256)
	if len(hash) != 64 {
		return false, "", nil
	}

	switch {
	case base == embeddedRulesDigestFileName:
		if hash != normalizeHex(embeddedRulesAllowDigestHash) {
			return false, "", nil
		}
	case ext == ".yar" || ext == ".yara" || ext == ".yr":
		if _, ok := embeddedRulesAllowHashes[hash]; !ok {
			return false, "", nil
		}
	default:
		return false, "", nil
	}

	evidence := []WhitelistEvidence{
		{Type: "path", Key: "target_path", Value: meta.TargetPath},
		{Type: "hash", Key: "sha256", Value: hash},
	}
	return true, "embedded-rules-cache", evidence
}

func resetEmbeddedRulesWhitelistForTest() {
	embeddedRulesAllowHashes = nil
	embeddedRulesAllowDigestHash = ""
	embeddedRulesAllowErr = nil
	embeddedRulesAllowOnce = sync.Once{}
}

func embeddedRulesWhitelistSnapshotForTest() (map[string]string, string, error) {
	embeddedRulesAllowOnce.Do(initEmbeddedRulesWhitelist)
	if embeddedRulesAllowErr != nil {
		return nil, "", embeddedRulesAllowErr
	}
	if len(embeddedRulesAllowHashes) == 0 {
		return nil, "", fmt.Errorf("embedded rules whitelist hashes are empty")
	}
	clone := make(map[string]string, len(embeddedRulesAllowHashes))
	for key, val := range embeddedRulesAllowHashes {
		clone[key] = val
	}
	return clone, embeddedRulesAllowDigestHash, nil
}
