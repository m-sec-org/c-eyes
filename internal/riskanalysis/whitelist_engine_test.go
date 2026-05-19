package riskanalysis

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestWhitelistDenyPrecedenceOverTrustedPublisher(t *testing.T) {
	valid := true
	policy := WhitelistPolicy{
		Version: "1",
		TrustedPublishers: []TrustedPublisherRule{
			{ID: "trusted-microsoft", Publisher: "microsoft", RequireValid: true},
		},
		RevokedCertificates: []CertificateRule{
			{ID: "revoked-test", Thumbprint: "AA11BB22"},
		},
	}
	policy.normalize()
	engine := NewDefaultWhitelistEngine(&policy, nil, nil)

	result, err := engine.Evaluate(context.Background(), TargetMetadata{
		TargetPath: `C:\Windows\System32\notepad.exe`,
		Signature: SignatureMetadata{
			Valid:      &valid,
			Signer:     "Microsoft Windows",
			Thumbprint: "AA11BB22",
		},
	}, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Decision != WhitelistDecisionDeny {
		t.Fatalf("expected deny, got %s", result.Decision)
	}
	if result.Source != "certificate_denylist" {
		t.Fatalf("expected certificate_denylist source, got %s", result.Source)
	}
}

func TestWhitelistAuthorityHashAllow(t *testing.T) {
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	policy := WhitelistPolicy{
		Version:    "1",
		NSRLHashes: []string{hash},
	}
	policy.normalize()
	repo, err := NewAuthorityHashRepo(&policy)
	if err != nil {
		t.Fatalf("NewAuthorityHashRepo error: %v", err)
	}
	engine := NewDefaultWhitelistEngine(&policy, repo, nil)

	result, err := engine.Evaluate(context.Background(), TargetMetadata{
		Hashes: Hashes{Sha256: hash},
	}, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Decision != WhitelistDecisionAllow {
		t.Fatalf("expected allow, got %s", result.Decision)
	}
	if result.Source != "nsrl" {
		t.Fatalf("expected nsrl source, got %s", result.Source)
	}
}

func TestWhitelistBYOVDSignerDeny(t *testing.T) {
	policy := WhitelistPolicy{
		Version: "1",
		VulnerableDrivers: []VulnerableDriverRule{
			{
				ID:      "byovd-signer-test",
				Signers: []string{"unsafe vendor"},
			},
		},
	}
	policy.normalize()
	engine := NewDefaultWhitelistEngine(&policy, nil, nil)

	result, err := engine.Evaluate(context.Background(), TargetMetadata{
		TargetPath: `C:\Windows\System32\drivers\vuln.sys`,
		Signature: SignatureMetadata{
			Signer: "Unsafe Vendor Co., Ltd.",
		},
	}, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Decision != WhitelistDecisionDeny {
		t.Fatalf("expected deny, got %s", result.Decision)
	}
	if result.Source != "byovd_blocklist" {
		t.Fatalf("expected byovd_blocklist source, got %s", result.Source)
	}
}

func TestWhitelistLOLBinRequiresCommandPolicy(t *testing.T) {
	valid := true
	policy := WhitelistPolicy{
		Version: "1",
		TrustedPublishers: []TrustedPublisherRule{
			{ID: "trusted-microsoft", Publisher: "microsoft", RequireValid: true},
		},
		LolbinRules: []LOLBinRule{
			{
				ID:     "ps",
				Binary: "powershell.exe",
				Commands: []LOLBinCommandRule{
					{ID: "backup", Match: "prefix", Pattern: "powershell.exe -file c:\\scripts\\backup.ps1"},
				},
			},
		},
	}
	policy.normalize()
	engine := NewDefaultWhitelistEngine(&policy, nil, nil)

	meta := TargetMetadata{
		TargetPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		Process: ProcessMetadata{
			Command: `powershell.exe -nop -enc AAAA`,
		},
		Signature: SignatureMetadata{
			Valid:  &valid,
			Signer: "Microsoft Corporation",
		},
	}

	decision, err := engine.Evaluate(context.Background(), meta, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if decision.Decision != WhitelistDecisionContinue {
		t.Fatalf("expected continue for unapproved lolbin command, got %s", decision.Decision)
	}

	meta.Process.Command = `powershell.exe -file c:\scripts\backup.ps1`
	decision, err = engine.Evaluate(context.Background(), meta, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if decision.Decision != WhitelistDecisionAllow {
		t.Fatalf("expected allow for approved lolbin command, got %s", decision.Decision)
	}
}

func TestWhitelistBusinessPathContextAllow(t *testing.T) {
	policy := WhitelistPolicy{
		Version: "1",
		BusinessPathRules: []BusinessPathRule{
			{
				ID:             "biz-app",
				PathPrefix:     `C:\Program Files\MyCompanyApp\`,
				AllowedParents: []string{"mycompanyhost.exe"},
			},
		},
	}
	policy.normalize()
	engine := NewDefaultWhitelistEngine(&policy, nil, nil)

	result, err := engine.Evaluate(context.Background(), TargetMetadata{
		TargetPath: `C:\Program Files\MyCompanyApp\agent.exe`,
		Process: ProcessMetadata{
			ParentName: "MyCompanyHost.exe",
		},
	}, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Decision != WhitelistDecisionAllow {
		t.Fatalf("expected allow, got %s", result.Decision)
	}
	if result.Source != "path_context" {
		t.Fatalf("expected path_context source, got %s", result.Source)
	}
}

func TestLocalReputationCacheTTLAndLRU(t *testing.T) {
	cache := NewLocalReputationCache(1, time.Minute)
	cache.now = func() time.Time { return time.Unix(0, 0) }
	hashA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cache.Set(hashA, WhitelistDecisionAllow)
	cache.Set(hashB, WhitelistDecisionAllow)
	if _, _, ok := cache.Get(hashA); ok {
		t.Fatal("expected hashA evicted by LRU")
	}
	if _, _, ok := cache.Get(hashB); !ok {
		t.Fatal("expected hashB present")
	}

	cache.now = func() time.Time { return time.Unix(120, 0) }
	if _, _, ok := cache.Get(hashB); ok {
		t.Fatal("expected hashB expired by TTL")
	}
}

func TestWhitelistEmbeddedRulesCacheStrictAllowByHash(t *testing.T) {
	resetEmbeddedRulesWhitelistForTest()
	hashes, _, err := embeddedRulesWhitelistSnapshotForTest()
	if err != nil {
		t.Fatalf("embeddedRulesWhitelistSnapshotForTest error: %v", err)
	}

	var ruleHash string
	for key := range hashes {
		ruleHash = key
		break
	}
	if ruleHash == "" {
		t.Fatal("expected at least one embedded rules hash")
	}

	engine := NewDefaultWhitelistEngine(nil, nil, nil)
	result, err := engine.Evaluate(context.Background(), TargetMetadata{
		TargetPath: filepath.Join(`C:\tools`, `.c-eyes-yara-rules-cache`, "demo.yar"),
		Hashes:     Hashes{Sha256: ruleHash},
	}, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Decision != WhitelistDecisionAllow {
		t.Fatalf("expected allow, got %s", result.Decision)
	}
	if result.Source != "embedded_rules_cache" {
		t.Fatalf("expected embedded_rules_cache source, got %s", result.Source)
	}
}

func TestWhitelistEmbeddedRulesCacheRejectsUnknownHash(t *testing.T) {
	resetEmbeddedRulesWhitelistForTest()
	engine := NewDefaultWhitelistEngine(nil, nil, nil)
	result, err := engine.Evaluate(context.Background(), TargetMetadata{
		TargetPath: filepath.Join(`C:\tools`, `.c-eyes-yara-rules-cache`, "demo.yar"),
		Hashes:     Hashes{Sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Decision != WhitelistDecisionContinue {
		t.Fatalf("expected continue, got %s", result.Decision)
	}
}

func TestWhitelistEmbeddedRulesCacheRejectsUnsupportedFileType(t *testing.T) {
	resetEmbeddedRulesWhitelistForTest()
	hashes, _, err := embeddedRulesWhitelistSnapshotForTest()
	if err != nil {
		t.Fatalf("embeddedRulesWhitelistSnapshotForTest error: %v", err)
	}
	var ruleHash string
	for key := range hashes {
		ruleHash = key
		break
	}
	engine := NewDefaultWhitelistEngine(nil, nil, nil)
	result, err := engine.Evaluate(context.Background(), TargetMetadata{
		TargetPath: filepath.Join(`C:\tools`, `.c-eyes-yara-rules-cache`, "demo.txt"),
		Hashes:     Hashes{Sha256: ruleHash},
	}, ScanRecord{}, whitelistStageSmart)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if result.Decision != WhitelistDecisionContinue {
		t.Fatalf("expected continue, got %s", result.Decision)
	}
}
