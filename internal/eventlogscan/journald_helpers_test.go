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
