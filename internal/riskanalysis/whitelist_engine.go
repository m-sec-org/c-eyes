package riskanalysis

import (
	"context"
	"path/filepath"
	"strings"
	"time"
)

const (
	whitelistStageFast  = "fast"
	whitelistStageSmart = "smart"
	whitelistStageDeep  = "deep"
)

// WhitelistEngine executes whitelist funnel decisions.
type WhitelistEngine interface {
	Evaluate(ctx context.Context, meta TargetMetadata, record ScanRecord, stage string) (WhitelistAnalysis, error)
}

// DefaultWhitelistEngine evaluates policy with precedence deny > allow > continue.
type DefaultWhitelistEngine struct {
	Policy *WhitelistPolicy
	Hashes AuthorityHashRepo
	Cache  *LocalReputationCache
}

func NewDefaultWhitelistEngine(policy *WhitelistPolicy, hashes AuthorityHashRepo, cache *LocalReputationCache) *DefaultWhitelistEngine {
	if policy == nil {
		defaultPolicy := DefaultWhitelistPolicy()
		policy = &defaultPolicy
	}
	policy.normalize()
	if hashes == nil {
		hashes, _ = NewAuthorityHashRepo(policy)
	}
	if cache == nil {
		cache = NewLocalReputationCache(policy.LocalCacheCapacity, policy.cacheTTL())
	}
	return &DefaultWhitelistEngine{
		Policy: policy,
		Hashes: hashes,
		Cache:  cache,
	}
}

func (e *DefaultWhitelistEngine) Evaluate(ctx context.Context, meta TargetMetadata, record ScanRecord, stage string) (WhitelistAnalysis, error) {
	_ = ctx
	out := WhitelistAnalysis{
		Checked:  true,
		Decision: WhitelistDecisionContinue,
		Source:   "whitelist_funnel",
		Reason:   "no whitelist rules matched",
	}
	if e == nil || e.Policy == nil {
		return out, nil
	}

	hash, _ := pickHash(meta.Hashes)
	hash = normalizeHex(hash)

	// 1) Local malicious cache has highest priority.
	if decision, expires, ok := e.Cache.Get(hash); ok && decision == WhitelistDecisionDeny {
		out.Decision = WhitelistDecisionDeny
		out.Source = "local_cache"
		out.PolicyID = "cache-malicious"
		out.Reason = "hash marked malicious in local reputation cache"
		out.Confidence = 100
		out.ExpiresAt = expires
		out.Evidence = []WhitelistEvidence{{Type: "hash", Key: "sha256", Value: hash}}
		return out, nil
	}

	// 2) Deny lists (certificate/BYOVD) override any allow evidence.
	if matched, policyID, evidence := e.matchDeniedCertificate(meta); matched {
		out.Decision = WhitelistDecisionDeny
		out.Source = "certificate_denylist"
		out.PolicyID = policyID
		out.Reason = "certificate matched revoked/stolen denylist"
		out.Confidence = 100
		out.Evidence = evidence
		return out, nil
	}
	if matched, policyID, evidence := e.matchBYOVD(meta); matched {
		out.Decision = WhitelistDecisionDeny
		out.Source = "byovd_blocklist"
		out.PolicyID = policyID
		out.Reason = "known vulnerable driver matched blocklist"
		out.Confidence = 100
		out.Evidence = evidence
		return out, nil
	}

	// 2.5) Strict internal cache allowlist: only known embedded rule artifacts.
	if matched, policyID, evidence := matchEmbeddedRulesCache(meta); matched {
		out.Decision = WhitelistDecisionAllow
		out.Source = "embedded_rules_cache"
		out.PolicyID = policyID
		out.Reason = "embedded rules cache artifact path/type/hash matched strict allowlist"
		out.Confidence = 100
		out.Evidence = evidence
		e.Cache.Set(hash, WhitelistDecisionAllow)
		return out, nil
	}

	// 3) Safe local cache.
	if decision, expires, ok := e.Cache.Get(hash); ok && decision == WhitelistDecisionAllow {
		out.Decision = WhitelistDecisionAllow
		out.Source = "local_cache"
		out.PolicyID = "cache-safe"
		out.Reason = "hash marked safe in local reputation cache"
		out.Confidence = 95
		out.ExpiresAt = expires
		out.Evidence = []WhitelistEvidence{{Type: "hash", Key: "sha256", Value: hash}}
		return out, nil
	}

	// 4) Authority hash repositories (NSRL / enterprise baseline).
	if source, ok := e.Hashes.Lookup(hash); ok {
		out.Decision = WhitelistDecisionAllow
		out.Source = source
		out.PolicyID = "authority-hash"
		out.Reason = "hash matched authority repository"
		out.Confidence = 100
		out.Evidence = []WhitelistEvidence{{Type: "hash", Key: "sha256", Value: hash}}
		e.Cache.Set(hash, WhitelistDecisionAllow)
		return out, nil
	}

	// Fast mode stops after cheap checks.
	stage = strings.ToLower(strings.TrimSpace(stage))
	if stage == whitelistStageFast {
		out.Reason = "fast whitelist checks complete with no final decision"
		return out, nil
	}

	isLOLBin, lolbinRule := e.lookupLOLBin(meta.TargetPath)
	if isLOLBin {
		if matched, policyID, evidence := e.matchLOLBinCommand(meta, lolbinRule); matched {
			out.Decision = WhitelistDecisionAllow
			out.Source = "lolbin_command_whitelist"
			out.PolicyID = policyID
			out.Reason = "dual-use binary command line matched approved policy"
			out.Confidence = 90
			out.Evidence = evidence
			e.Cache.Set(hash, WhitelistDecisionAllow)
			return out, nil
		}
		// For LOLBins, file-level allow is forbidden.
		out.Reason = "dual-use binary requires command-line whitelist match"
		return out, nil
	}

	if matched, policyID, evidence := e.matchTrustedPublisher(meta); matched {
		out.Decision = WhitelistDecisionAllow
		out.Source = "trusted_publisher"
		out.PolicyID = policyID
		out.Reason = "valid trusted publisher signature"
		out.Confidence = 85
		out.Evidence = evidence
		e.Cache.Set(hash, WhitelistDecisionAllow)
		return out, nil
	}
	if matched, policyID, evidence := e.matchPathContext(meta); matched {
		out.Decision = WhitelistDecisionAllow
		out.Source = "path_context"
		out.PolicyID = policyID
		out.Reason = "path and parent context matched allow policy"
		out.Confidence = 80
		out.Evidence = evidence
		e.Cache.Set(hash, WhitelistDecisionAllow)
		return out, nil
	}

	out.Reason = "no whitelist allow/deny rule matched"
	return out, nil
}

func (e *DefaultWhitelistEngine) matchDeniedCertificate(meta TargetMetadata) (bool, string, []WhitelistEvidence) {
	sig := meta.Signature
	thumbprint := normalizeHex(sig.Thumbprint)
	serial := normalizeHex(sig.Serial)
	issuer := strings.ToLower(strings.TrimSpace(sig.Issuer))
	for _, rule := range e.Policy.RevokedCertificates {
		if rule.Thumbprint != "" && thumbprint != "" && thumbprint == normalizeHex(rule.Thumbprint) {
			return true, fallbackID(rule.ID, "revoked-cert-thumbprint"), []WhitelistEvidence{{Type: "certificate", Key: "thumbprint", Value: thumbprint}}
		}
		if rule.Serial != "" && serial != "" && serial == normalizeHex(rule.Serial) {
			return true, fallbackID(rule.ID, "revoked-cert-serial"), []WhitelistEvidence{{Type: "certificate", Key: "serial", Value: serial}}
		}
		if rule.Issuer != "" && issuer != "" && strings.Contains(issuer, strings.ToLower(strings.TrimSpace(rule.Issuer))) {
			return true, fallbackID(rule.ID, "revoked-cert-issuer"), []WhitelistEvidence{{Type: "certificate", Key: "issuer", Value: sig.Issuer}}
		}
	}
	return false, "", nil
}

func (e *DefaultWhitelistEngine) matchBYOVD(meta TargetMetadata) (bool, string, []WhitelistEvidence) {
	path := strings.ToLower(strings.TrimSpace(meta.TargetPath))
	hashes := []string{normalizeHex(meta.Hashes.Sha256), normalizeHex(meta.Hashes.Md5), normalizeHex(meta.Hashes.Sha1)}
	name := strings.ToLower(strings.TrimSpace(filepath.Base(meta.TargetPath)))
	signer := strings.ToLower(strings.TrimSpace(meta.Signature.Signer))
	for _, rule := range e.Policy.VulnerableDrivers {
		for _, hash := range hashes {
			if hash == "" {
				continue
			}
			for _, blocked := range rule.Hashes {
				if hash == normalizeHex(blocked) {
					return true, fallbackID(rule.ID, "byovd-hash"), []WhitelistEvidence{{Type: "hash", Key: "hash", Value: hash}}
				}
			}
		}
		if rule.Name != "" && name != "" && strings.Contains(name, strings.ToLower(strings.TrimSpace(rule.Name))) {
			return true, fallbackID(rule.ID, "byovd-name"), []WhitelistEvidence{{Type: "path", Key: "filename", Value: name}}
		}
		for _, hint := range rule.PathContains {
			hint = strings.ToLower(strings.TrimSpace(hint))
			if hint != "" && strings.Contains(path, hint) {
				return true, fallbackID(rule.ID, "byovd-path"), []WhitelistEvidence{{Type: "path", Key: "target_path", Value: meta.TargetPath}}
			}
		}
		for _, blockedSigner := range rule.Signers {
			blockedSigner = strings.ToLower(strings.TrimSpace(blockedSigner))
			if blockedSigner != "" && signer != "" && strings.Contains(signer, blockedSigner) {
				return true, fallbackID(rule.ID, "byovd-signer"), []WhitelistEvidence{{Type: "signature", Key: "signer", Value: meta.Signature.Signer}}
			}
		}
	}
	return false, "", nil
}

func (e *DefaultWhitelistEngine) matchTrustedPublisher(meta TargetMetadata) (bool, string, []WhitelistEvidence) {
	if meta.Signature.Valid == nil || !*meta.Signature.Valid {
		return false, "", nil
	}
	signer := strings.ToLower(strings.TrimSpace(meta.Signature.Signer))
	product := strings.ToLower(strings.TrimSpace(meta.ProductName))
	for _, rule := range e.Policy.TrustedPublishers {
		pub := strings.ToLower(strings.TrimSpace(rule.Publisher))
		if pub == "" || signer == "" || !strings.Contains(signer, pub) {
			continue
		}
		if rule.RequireValid && (meta.Signature.Valid == nil || !*meta.Signature.Valid) {
			continue
		}
		if len(rule.Products) > 0 {
			match := false
			for _, p := range rule.Products {
				p = strings.ToLower(strings.TrimSpace(p))
				if p == "" {
					continue
				}
				if strings.Contains(product, p) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		return true, fallbackID(rule.ID, "trusted-publisher"), []WhitelistEvidence{
			{Type: "signature", Key: "signer", Value: meta.Signature.Signer},
			{Type: "signature", Key: "thumbprint", Value: normalizeHex(meta.Signature.Thumbprint)},
		}
	}
	return false, "", nil
}

func (e *DefaultWhitelistEngine) matchPathContext(meta TargetMetadata) (bool, string, []WhitelistEvidence) {
	path := normalizePathLike(meta.TargetPath)
	if path == "" {
		return false, "", nil
	}
	if strings.HasPrefix(path, strings.ToLower(`c:\windows\system32\`)) &&
		meta.Signature.Valid != nil && *meta.Signature.Valid &&
		strings.Contains(strings.ToLower(meta.Signature.Signer), "microsoft") {
		return true, "system32-microsoft-signed", []WhitelistEvidence{
			{Type: "path", Key: "target_path", Value: meta.TargetPath},
			{Type: "signature", Key: "signer", Value: meta.Signature.Signer},
		}
	}

	parentName := strings.ToLower(strings.TrimSpace(meta.Process.ParentName))
	parentPath := normalizePathLike(meta.Process.ParentPath)
	for _, rule := range e.Policy.BusinessPathRules {
		if rule.PathPrefix == "" {
			continue
		}
		if !strings.HasPrefix(path, normalizePathLike(rule.PathPrefix)) {
			continue
		}
		parentOK := len(rule.AllowedParents) == 0 && len(rule.ParentPathHints) == 0
		for _, p := range rule.AllowedParents {
			p = strings.ToLower(strings.TrimSpace(p))
			if p != "" && parentName != "" && strings.Contains(parentName, p) {
				parentOK = true
				break
			}
		}
		if !parentOK {
			for _, hint := range rule.ParentPathHints {
				hint = normalizePathLike(hint)
				if hint != "" && parentPath != "" && strings.Contains(parentPath, hint) {
					parentOK = true
					break
				}
			}
		}
		if parentOK {
			return true, fallbackID(rule.ID, "business-path-context"), []WhitelistEvidence{
				{Type: "path", Key: "target_path", Value: meta.TargetPath},
				{Type: "process", Key: "parent_name", Value: meta.Process.ParentName},
			}
		}
	}
	return false, "", nil
}

func (e *DefaultWhitelistEngine) lookupLOLBin(targetPath string) (bool, LOLBinRule) {
	bin := strings.ToLower(strings.TrimSpace(filepath.Base(targetPath)))
	if bin == "" {
		return false, LOLBinRule{}
	}
	for _, rule := range e.Policy.LolbinRules {
		if bin == strings.ToLower(strings.TrimSpace(filepath.Base(rule.Binary))) {
			return true, rule
		}
	}
	return false, LOLBinRule{}
}

func (e *DefaultWhitelistEngine) matchLOLBinCommand(meta TargetMetadata, rule LOLBinRule) (bool, string, []WhitelistEvidence) {
	cmd := strings.TrimSpace(meta.Process.Command)
	if cmd == "" {
		return false, "", nil
	}
	for _, command := range rule.Commands {
		pattern := strings.TrimSpace(command.Pattern)
		if pattern == "" {
			continue
		}
		matchMode := strings.ToLower(strings.TrimSpace(command.Match))
		if matchMode == "" {
			matchMode = "exact"
		}
		matched := false
		cmdLower := strings.ToLower(cmd)
		patLower := strings.ToLower(pattern)
		switch matchMode {
		case "exact":
			matched = cmdLower == patLower
		case "prefix":
			matched = strings.HasPrefix(cmdLower, patLower)
		case "contains":
			matched = strings.Contains(cmdLower, patLower)
		}
		if matched {
			return true, fallbackID(command.ID, fallbackID(rule.ID, "lolbin-command")), []WhitelistEvidence{
				{Type: "process", Key: "command", Value: cmd},
				{Type: "binary", Key: "name", Value: filepath.Base(meta.TargetPath)},
			}
		}
	}
	return false, "", nil
}

func fallbackID(val, fallback string) string {
	val = strings.TrimSpace(val)
	if val != "" {
		return val
	}
	return fallback
}

func (p *WhitelistPolicy) cacheTTL() time.Duration {
	if p == nil {
		return 10 * time.Minute
	}
	ttl, err := time.ParseDuration(strings.TrimSpace(p.LocalCacheTTL))
	if err != nil || ttl <= 0 {
		return 10 * time.Minute
	}
	return ttl
}
