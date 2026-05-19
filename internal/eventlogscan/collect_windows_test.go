//go:build windows

package eventlogscan

import "testing"

func TestParsePIDTokenSupportsHexAndDecimal(t *testing.T) {
	t.Parallel()

	hex := parsePIDToken("0x6e8")
	if hex == nil || *hex != 1768 {
		t.Fatalf("expected hex pid 1768, got %#v", hex)
	}

	dec := parsePIDToken("1234")
	if dec == nil || *dec != 1234 {
		t.Fatalf("expected decimal pid 1234, got %#v", dec)
	}

	if parsePIDToken("-") != nil {
		t.Fatal("expected '-' token to be ignored")
	}
}

func TestExtractSecurityUsernameAndProcessFor4624(t *testing.T) {
	t.Parallel()

	fields := []string{
		"S-1-5-18",
		"WIN-HOST$",
		"WORKGROUP",
		"0x3e7",
		"S-1-5-21-111-222-333-1001",
		"Administrator",
		"WORKGROUP",
		"0x13d320c5",
		"5",
		"Advapi",
		"Negotiate",
		"-",
		"{00000000-0000-0000-0000-000000000000}",
		"-",
		"-",
		"0",
		"0x6e8",
		`C:\Windows\System32\winlogon.exe`,
	}

	username := extractSecurityUsername("4624", fields)
	if username != `WORKGROUP\Administrator` {
		t.Fatalf("unexpected username: %q", username)
	}

	pid := extractSecurityProcessID("4624", fields)
	if pid == nil || *pid != 1768 {
		t.Fatalf("expected processId=1768, got %#v", pid)
	}

	name := extractSecurityProcessName("4624", fields)
	if name != `C:\Windows\System32\winlogon.exe` {
		t.Fatalf("unexpected processName: %q", name)
	}
}

func TestBuildWindowsMessageSummarySecurityCode(t *testing.T) {
	t.Parallel()

	msg := buildWindowsMessageSummary("security", "4624", []string{"a", "b"}, "raw")
	if msg != "An account was successfully logged on. | a | b" {
		t.Fatalf("unexpected summary: %q", msg)
	}
}

func TestBuildWindowsMessageSummaryFallsBackToCanonicalWhenNoTextualParts(t *testing.T) {
	t.Parallel()

	msg := buildWindowsMessageSummary("security", "4624", []string{"0x3e7", "127.0.0.1"}, "raw")
	if msg != "An account was successfully logged on." {
		t.Fatalf("unexpected canonical summary: %q", msg)
	}
}

func TestExtractSecurityProcessMappingsFor4625AndCryptoEvents(t *testing.T) {
	t.Parallel()

	fields4625 := []string{
		"S-1-5-18",
		"WIN-HOST$",
		"WORKGROUP",
		"0x3e7",
		"S-1-0-0",
		"Administrator",
		"WIN-HOST",
		"0xc000006d",
		"%%2313",
		"0xc000006a",
		"2",
		"User32",
		"Negotiate",
		"WIN-HOST",
		"-",
		"-",
		"0",
		"0x538",
		`C:\Windows\System32\svchost.exe`,
		"127.0.0.1",
		"0",
	}
	pid4625 := extractSecurityProcessID("4625", fields4625)
	if pid4625 == nil || *pid4625 != 1336 {
		t.Fatalf("expected 4625 processId=1336, got %#v", pid4625)
	}
	name4625 := extractSecurityProcessName("4625", fields4625)
	if name4625 != `C:\Windows\System32\svchost.exe` {
		t.Fatalf("unexpected 4625 processName: %q", name4625)
	}

	fields5058 := []string{
		"S-1-5-21-xxx-500",
		"Administrator",
		"WIN-HOST",
		"0x123",
		"14356",
		"2026-04-16T03:19:16.7584082Z",
		"Microsoft Software Key Storage Provider",
	}
	pid5058 := extractSecurityProcessID("5058", fields5058)
	if pid5058 == nil || *pid5058 != 14356 {
		t.Fatalf("expected 5058 processId=14356, got %#v", pid5058)
	}

	fields5382 := []string{
		"S-1-5-21-xxx-500",
		"Administrator",
		"WIN-HOST",
		"0x123",
		"Windows Web Password Credential",
		"{3ccd5499-87a8-4b10-a215-608888dd3b55}",
		"SnapshotEncryptionIV",
		"MicrosoftStore-Installs",
		"",
		"0",
		"0",
		"2026-04-16T07:48:47.2325518Z",
		"1804",
	}
	pid5382 := extractSecurityProcessID("5382", fields5382)
	if pid5382 == nil || *pid5382 != 1804 {
		t.Fatalf("expected 5382 processId=1804, got %#v", pid5382)
	}

	fields5382Compacted := []string{
		"S-1-5-21-xxx-500",
		"Administrator",
		"WIN-HOST",
		"0x123",
		"Windows Web Password Credential",
		"{3ccd5499-87a8-4b10-a215-608888dd3b55}",
		"SnapshotEncryptionIV",
		"MicrosoftStore-Installs",
		"0",
		"0",
		"2026-04-16T07:48:47.2325518Z",
		"1804",
	}
	pid5382Compacted := extractSecurityProcessID("5382", fields5382Compacted)
	if pid5382Compacted == nil || *pid5382Compacted != 1804 {
		t.Fatalf("expected compacted 5382 processId=1804, got %#v", pid5382Compacted)
	}
}
