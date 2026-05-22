package eventlogscan

import "testing"

func TestNormalizeLinuxJournalActualSource(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		fields map[string]string
		want   string
	}{
		{name: "audit transport", fields: map[string]string{"_TRANSPORT": "audit"}, want: "audit"},
		{name: "kernel transport", fields: map[string]string{"_TRANSPORT": "kernel"}, want: "kern"},
		{name: "kernel facility", fields: map[string]string{"SYSLOG_FACILITY": "0"}, want: "kern"},
		{name: "auth facility", fields: map[string]string{"SYSLOG_FACILITY": "10"}, want: "auth"},
		{name: "default syslog", fields: map[string]string{"SYSLOG_IDENTIFIER": "cron"}, want: "syslog"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeLinuxJournalActualSource(tc.fields); got != tc.want {
				t.Fatalf("normalizeLinuxJournalActualSource()=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestMatchLinuxJournalSourceAliasMapping(t *testing.T) {
	t.Parallel()

	if got, ok := matchLinuxJournalSource(map[string]string{"_TRANSPORT": "audit"}, []string{"security"}); !ok || got != "security" {
		t.Fatalf("expected security alias for audit source, got ok=%v source=%q", ok, got)
	}
	if got, ok := matchLinuxJournalSource(map[string]string{"SYSLOG_FACILITY": "10"}, []string{"security"}); !ok || got != "security" {
		t.Fatalf("expected security alias for auth source, got ok=%v source=%q", ok, got)
	}
	if got, ok := matchLinuxJournalSource(map[string]string{"SYSLOG_IDENTIFIER": "cron"}, []string{"system"}); !ok || got != "system" {
		t.Fatalf("expected system alias for syslog source, got ok=%v source=%q", ok, got)
	}
	if got, ok := matchLinuxJournalSource(map[string]string{"SYSLOG_IDENTIFIER": "cron"}, nil); !ok || got != "syslog" {
		t.Fatalf("expected default syslog source, got ok=%v source=%q", ok, got)
	}
}

func TestBuildLinuxJournalEventUsesStructuredFields(t *testing.T) {
	t.Parallel()

	event := buildLinuxJournalEvent(map[string]string{
		"MESSAGE":           "Accepted password for root from 10.0.0.5 port 22",
		"_HOSTNAME":         "node-1",
		"SYSLOG_IDENTIFIER": "sshd",
		"_COMM":             "sshd",
		"_PID":              "1234",
		"_UID":              "0",
		"SYSLOG_FACILITY":   "10",
		"PRIORITY":          "4",
	}, 1710000000000, "auth")

	if event.OSType != "linux" {
		t.Fatalf("expected osType linux, got %q", event.OSType)
	}
	if event.Source != "auth" {
		t.Fatalf("expected source auth, got %q", event.Source)
	}
	if event.EventLevel != "warn" {
		t.Fatalf("expected level warn, got %q", event.EventLevel)
	}
	if event.EventCode != "sshd" {
		t.Fatalf("expected eventCode sshd, got %q", event.EventCode)
	}
	if event.Hostname != "node-1" {
		t.Fatalf("expected hostname node-1, got %q", event.Hostname)
	}
	if event.ProcessName != "sshd" {
		t.Fatalf("expected processName sshd, got %q", event.ProcessName)
	}
	if event.ProcessID == nil || *event.ProcessID != 1234 {
		t.Fatalf("expected processId 1234, got %#v", event.ProcessID)
	}
	if event.Username == "" {
		t.Fatal("expected username populated from uid")
	}
}

func TestJournalParseLinuxTargetPathTrimsTrailingPunctuation(t *testing.T) {
	t.Parallel()

	got := journalParseLinuxTargetPath(`WARNING Daemon: could not read agent port file "/mnt/c/Users/Administrator/.ubuntupro/.address": open /mnt/c/Users/Administrator/.ubuntupro/.address: no such file or directory`)
	want := "/mnt/c/Users/Administrator/.ubuntupro/.address"
	if got != want {
		t.Fatalf("expected trimmed target path %q, got %q", want, got)
	}
}

func TestJournalEventTypeInfersSystemdUnitsAsService(t *testing.T) {
	t.Parallel()

	got := journalEventType(map[string]string{
		"_SYSTEMD_UNIT":     "wslg-session.service",
		"SYSLOG_IDENTIFIER": "systemd",
	}, "Startup finished in 166ms.", "syslog")
	if got != "service" {
		t.Fatalf("expected service, got %q", got)
	}
}

func TestJournalEventTypeInfersAuthMessagesAsLogin(t *testing.T) {
	t.Parallel()

	got := journalEventType(map[string]string{
		"SYSLOG_IDENTIFIER": "login",
		"_COMM":             "login",
	}, "ROOT LOGIN on '/dev/pts/1'", "auth")
	if got != "login" {
		t.Fatalf("expected login, got %q", got)
	}
}

func TestJournalEventTypePrefersLoginOverSystemdScopeForAuth(t *testing.T) {
	t.Parallel()

	got := journalEventType(map[string]string{
		"_SYSTEMD_UNIT":     "session-5.scope",
		"SYSLOG_IDENTIFIER": "login",
		"_COMM":             "login",
	}, "ROOT LOGIN on '/dev/pts/1'", "auth")
	if got != "login" {
		t.Fatalf("expected login to win over scope-based service inference, got %q", got)
	}
}

func TestJournalEventTypeTreatsRuleDirectoryLoadsAsFile(t *testing.T) {
	t.Parallel()

	got := journalEventType(map[string]string{
		"SYSLOG_IDENTIFIER": "polkitd",
	}, "Loading rules from directory /etc/polkit-1/rules.d", "auth")
	if got != "file" {
		t.Fatalf("expected file, got %q", got)
	}
}

func TestJournalEventTypeTreatsAcquiredBusNameAsService(t *testing.T) {
	t.Parallel()

	got := journalEventType(map[string]string{
		"SYSLOG_IDENTIFIER": "polkitd",
		"_COMM":             "polkitd",
	}, "Acquired the name org.freedesktop.PolicyKit1 on the system bus", "auth")
	if got != "service" {
		t.Fatalf("expected service, got %q", got)
	}
}

func TestBuildLinuxJournalEventTreatsPolkitBusNameAsService(t *testing.T) {
	t.Parallel()

	event := buildLinuxJournalEvent(map[string]string{
		"MESSAGE":           "Acquired the name org.freedesktop.PolicyKit1 on the system bus",
		"_HOSTNAME":         "node-1",
		"SYSLOG_IDENTIFIER": "polkitd",
		"_COMM":             "polkitd",
		"_PID":              "1067",
		"_UID":              "996",
		"SYSLOG_FACILITY":   "10",
		"PRIORITY":          "5",
	}, 1710000000000, "auth")

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   9999999999999,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	row := buildResult(params, []rawEvent{event}).Rows[0]
	if row.EventType != "service" {
		t.Fatalf("expected normalized eventType service, got %q", row.EventType)
	}
	if row.EventAction != "allow" {
		t.Fatalf("expected normalized eventAction allow, got %q", row.EventAction)
	}
	if row.Result != "success" {
		t.Fatalf("expected normalized result success, got %q", row.Result)
	}
}

func TestJournalEventTypeTreatsSocketListeningAsService(t *testing.T) {
	t.Parallel()

	got := journalEventType(map[string]string{
		"_SYSTEMD_UNIT": "dbus.socket",
	}, "Listening on dbus.socket - D-Bus User Message Bus Socket.", "syslog")
	if got != "service" {
		t.Fatalf("expected service, got %q", got)
	}
}

func TestJournalEventTypeTreatsNewSessionAsLogin(t *testing.T) {
	t.Parallel()

	got := journalEventType(map[string]string{
		"SYSLOG_IDENTIFIER": "systemd-logind",
		"_COMM":             "systemd-logind",
	}, "New session 4 of user root.", "auth")
	if got != "login" {
		t.Fatalf("expected login, got %q", got)
	}
}

func TestJournalEventTypeTreatsNewSeatAsSystem(t *testing.T) {
	t.Parallel()

	got := journalEventType(map[string]string{
		"SYSLOG_IDENTIFIER": "systemd-logind",
		"_COMM":             "systemd-logind",
	}, "New seat seat0.", "auth")
	if got != "system" {
		t.Fatalf("expected system, got %q", got)
	}
}

func TestJournalParseLinuxTargetPathExtractsQuotedCommPath(t *testing.T) {
	t.Parallel()

	got := journalParseLinuxTargetPath(`[system] Activating via systemd: service name='org.freedesktop.PolicyKit1' unit='polkit.service' requested by ':1.14' (uid=0 pid=1062 comm="/usr/libexec/packagekitd" label="kernel")`)
	want := "/usr/libexec/packagekitd"
	if got != want {
		t.Fatalf("expected quoted comm path %q, got %q", want, got)
	}
}
