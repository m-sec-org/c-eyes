package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureEmbeddedRulesDirCleanupAndRecreate(t *testing.T) {
	origExe := embeddedRulesExecutableFunc
	origTempDir := embeddedRulesTempDirFunc
	origMkdirAll := embeddedRulesMkdirAllFunc
	embeddedRulesExecutableFunc = origExe
	embeddedRulesTempDirFunc = origTempDir
	embeddedRulesMkdirAllFunc = origMkdirAll
	cleanupEmbeddedRulesDir()
	t.Cleanup(func() {
		embeddedRulesExecutableFunc = origExe
		embeddedRulesTempDirFunc = origTempDir
		embeddedRulesMkdirAllFunc = origMkdirAll
		cleanupEmbeddedRulesDir()
	})

	exeDir := t.TempDir()
	embeddedRulesExecutableFunc = func() (string, error) {
		return filepath.Join(exeDir, "c-eyes"), nil
	}
	embeddedRulesMkdirAllFunc = os.MkdirAll

	dir, err := ensureEmbeddedRulesDir()
	if err != nil {
		t.Fatalf("ensureEmbeddedRulesDir returned error: %v", err)
	}
	expectedDir := filepath.Join(exeDir, embeddedRulesCacheDirName)
	if dir != expectedDir {
		t.Fatalf("unexpected embedded rules dir: %q", dir)
	}
	if filepath.Dir(dir) != exeDir {
		t.Fatalf("expected embedded rules dir under executable dir %q, got %q", exeDir, dir)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("expected embedded rules dir to exist, err=%v", err)
	}

	cleanupEmbeddedRulesDir()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected embedded rules dir removed, got err=%v", err)
	}

	dir2, err := ensureEmbeddedRulesDir()
	if err != nil {
		t.Fatalf("ensureEmbeddedRulesDir recreate returned error: %v", err)
	}
	if dir2 != expectedDir {
		t.Fatalf("expected recreated embedded rules dir %q, got %q", expectedDir, dir2)
	}
	if info, err := os.Stat(dir2); err != nil || !info.IsDir() {
		t.Fatalf("expected recreated embedded rules dir to exist, err=%v", err)
	}
	if filepath.Dir(dir2) != exeDir {
		t.Fatalf("expected recreated embedded rules dir under executable dir %q, got %q", exeDir, dir2)
	}
}

func TestEnsureEmbeddedRulesDirFallsBackToSystemTempWhenExeDirUnwritable(t *testing.T) {
	origExe := embeddedRulesExecutableFunc
	origTempDir := embeddedRulesTempDirFunc
	origMkdirAll := embeddedRulesMkdirAllFunc
	embeddedRulesExecutableFunc = origExe
	embeddedRulesTempDirFunc = origTempDir
	embeddedRulesMkdirAllFunc = origMkdirAll
	cleanupEmbeddedRulesDir()
	t.Cleanup(func() {
		embeddedRulesExecutableFunc = origExe
		embeddedRulesTempDirFunc = origTempDir
		embeddedRulesMkdirAllFunc = origMkdirAll
		cleanupEmbeddedRulesDir()
	})

	exeDir := t.TempDir()
	fallbackDir := t.TempDir()
	primaryDir := filepath.Join(exeDir, embeddedRulesCacheDirName)
	embeddedRulesExecutableFunc = func() (string, error) {
		return filepath.Join(exeDir, "c-eyes"), nil
	}
	embeddedRulesTempDirFunc = func() string {
		return fallbackDir
	}
	embeddedRulesMkdirAllFunc = func(path string, perm os.FileMode) error {
		if path == primaryDir {
			return errors.New("permission denied")
		}
		return os.MkdirAll(path, perm)
	}

	dir, err := ensureEmbeddedRulesDir()
	if err != nil {
		t.Fatalf("ensureEmbeddedRulesDir returned error: %v", err)
	}
	if filepath.Dir(dir) == exeDir {
		t.Fatalf("expected fallback directory instead of executable dir, got %q", dir)
	}
	expectedFallback := filepath.Join(fallbackDir, embeddedRulesCacheDirName)
	if dir != expectedFallback {
		t.Fatalf("expected fallback dir %q, got %q", expectedFallback, dir)
	}
	if _, err := os.Stat(filepath.Join(dir, embeddedRulesDigestFile)); err != nil {
		t.Fatalf("expected digest file to exist, err=%v", err)
	}
}

func TestEnsureEmbeddedRulesDirReusesCacheWhenDigestMatches(t *testing.T) {
	origExe := embeddedRulesExecutableFunc
	origTempDir := embeddedRulesTempDirFunc
	origMkdirAll := embeddedRulesMkdirAllFunc
	embeddedRulesExecutableFunc = origExe
	embeddedRulesTempDirFunc = origTempDir
	embeddedRulesMkdirAllFunc = origMkdirAll
	cleanupEmbeddedRulesDir()
	t.Cleanup(func() {
		embeddedRulesExecutableFunc = origExe
		embeddedRulesTempDirFunc = origTempDir
		embeddedRulesMkdirAllFunc = origMkdirAll
		cleanupEmbeddedRulesDir()
	})

	exeDir := t.TempDir()
	embeddedRulesExecutableFunc = func() (string, error) {
		return filepath.Join(exeDir, "c-eyes"), nil
	}

	firstDir, err := ensureEmbeddedRulesDir()
	if err != nil {
		t.Fatalf("first ensureEmbeddedRulesDir returned error: %v", err)
	}
	digestPath := filepath.Join(firstDir, embeddedRulesDigestFile)
	firstDigest, err := os.ReadFile(digestPath)
	if err != nil {
		t.Fatalf("failed to read first digest: %v", err)
	}

	cleanupEmbeddedRulesDir()

	secondDir, err := ensureEmbeddedRulesDir()
	if err != nil {
		t.Fatalf("second ensureEmbeddedRulesDir returned error: %v", err)
	}
	secondDigest, err := os.ReadFile(filepath.Join(secondDir, embeddedRulesDigestFile))
	if err != nil {
		t.Fatalf("failed to read second digest: %v", err)
	}
	if secondDir != firstDir {
		t.Fatalf("expected same cache dir across runs, got %q and %q", firstDir, secondDir)
	}
	if strings.TrimSpace(string(firstDigest)) != strings.TrimSpace(string(secondDigest)) {
		t.Fatalf("expected cached digest to stay stable across runs")
	}
}
