package eventlogscan

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNormalizeParamsValidation(t *testing.T) {
	t.Parallel()

	if _, err := normalizeParams(QueryParams{}); err == nil {
		t.Fatal("expected missing start/end time error")
	}
	if _, err := normalizeParams(QueryParams{StartTime: 20, EndTime: 10}); err == nil {
		t.Fatal("expected startTime > endTime error")
	}
	if _, err := normalizeParams(QueryParams{StartTime: 10, EndTime: 20, MaxLogs: -1}); err == nil {
		t.Fatal("expected maxLogs bounds error")
	}
	if _, err := normalizeParams(QueryParams{StartTime: 10, EndTime: 20, SortBy: "unknown"}); err == nil {
		t.Fatal("expected sortBy whitelist error")
	}
}

func TestNormalizeParamsDefaults(t *testing.T) {
	t.Parallel()

	got, err := normalizeParams(QueryParams{StartTime: 10, EndTime: 20})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}
	if got.MaxLogs != 0 {
		t.Fatalf("expected default maxLogs=0, got %d", got.MaxLogs)
	}
	if got.SortBy != DefaultSortBy {
		t.Fatalf("expected default sortBy=%s, got %s", DefaultSortBy, got.SortBy)
	}
	if got.SortOrder != DefaultSortOrder {
		t.Fatalf("expected default sortOrder=%s, got %s", DefaultSortOrder, got.SortOrder)
	}
}

func TestCleanEventTextStripsANSIAndControls(t *testing.T) {
	t.Parallel()

	raw := "\u001b[33mWARNING\u001b[0m line one\tline two\r\nnext"
	got := cleanEventText(raw)
	want := "WARNING line one line two next"
	if got != want {
		t.Fatalf("expected cleaned text %q, got %q", want, got)
	}
}

func TestNormalizeEventLevelEscalatesInfoWhenMessageWarns(t *testing.T) {
	t.Parallel()

	got := normalizeEventLevel("info", "WARNING Daemon: could not connect")
	if got != "warn" {
		t.Fatalf("expected warn, got %q", got)
	}
}

func TestBuildResultFilterSemanticsAndKeyword(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
		Sources:   []string{"security"},
		EventTypes: []string{
			"login",
		},
		Results:  []string{"fail", "success"},
		Username: strPtr("alice"),
		Keyword:  strPtr("failed"),
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	pid := 101
	result := buildResult(params, []rawEvent{
		{
			NativeID:    "a",
			Timestamp:   1000,
			Source:      "system",
			EventType:   "process",
			EventLevel:  "info",
			EventCode:   "1000",
			EventAction: "start",
			Result:      "success",
			ProcessName: "cmd.exe",
			ProcessID:   &pid,
			Message:     "process started",
		},
		{
			NativeID:   "b",
			Timestamp:  1001,
			Source:     "security",
			EventType:  "logon",
			EventLevel: "warning",
			EventCode:  "4625",
			Result:     "failed",
			Username:   "alice",
			Message:    "user login failed",
		},
		{
			NativeID:   "c",
			Timestamp:  1002,
			Source:     "security",
			EventType:  "login",
			EventLevel: "info",
			EventCode:  "4624",
			Result:     "success",
			Username:   "bob",
			Message:    "user login success",
		},
	})

	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected rows=1, got %d", len(result.Rows))
	}
	if result.Rows[0].Source != "security" || result.Rows[0].Result != "fail" {
		t.Fatalf("unexpected row: %#v", result.Rows[0])
	}
}

func TestBuildResultReturnsAllRowsWithoutPagination(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	events := []rawEvent{
		{NativeID: "a", Timestamp: 2000, Source: "system", EventType: "system", Message: "first"},
		{NativeID: "b", Timestamp: 2000, Source: "system", EventType: "system", Message: "second"},
		{NativeID: "c", Timestamp: 1000, Source: "system", EventType: "system", Message: "third"},
	}

	result := buildResult(params, events)
	if result.Total != 3 {
		t.Fatalf("expected total=3, got %d", result.Total)
	}
	if len(result.Rows) != 3 {
		t.Fatalf("expected rows=3, got %d", len(result.Rows))
	}
	if result.Rows[0].LogID == result.Rows[1].LogID {
		t.Fatalf("expected distinct rows, got duplicated logId=%s", result.Rows[0].LogID)
	}
}

func TestBuildResultAppliesMaxLogsAfterSort(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
		MaxLogs:   2,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	events := []rawEvent{
		{NativeID: "a", Timestamp: 1000, Source: "system", EventType: "system", Message: "third"},
		{NativeID: "b", Timestamp: 3000, Source: "system", EventType: "system", Message: "first"},
		{NativeID: "c", Timestamp: 2000, Source: "system", EventType: "system", Message: "second"},
	}

	result := buildResult(params, events)
	if result.Total != 2 {
		t.Fatalf("expected total=2, got %d", result.Total)
	}
	if len(result.Rows) != 2 {
		t.Fatalf("expected rows=2, got %d", len(result.Rows))
	}
	if result.Rows[0].Timestamp != 3000 || result.Rows[1].Timestamp != 2000 {
		t.Fatalf("expected maxLogs applied after sort, got %#v", result.Rows)
	}
}

func TestNormalizeMappingWindowsLinuxAndFallback(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
		SortBy:    "timestamp",
		SortOrder: "asc",
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	result := buildResult(params, []rawEvent{
		{
			NativeID:    "win-1",
			Timestamp:   10,
			Source:      "Security",
			EventType:   "logon",
			EventLevel:  "Warning",
			EventCode:   "4625",
			EventAction: "login",
			Result:      "failed",
			Message:     "An account failed to log on",
		},
		{
			NativeID:    "linux-1",
			Timestamp:   20,
			Source:      "auth",
			EventType:   "authentication",
			EventLevel:  "notice",
			EventCode:   "USER_LOGIN",
			EventAction: "",
			Result:      "success",
			Message:     "session opened for user root",
		},
		{
			NativeID:   "unknown-1",
			Timestamp:  30,
			Source:     "mystery",
			EventType:  "something-new",
			EventLevel: "mystery",
			EventCode:  "",
			Message:    "unknown event",
		},
	})
	if len(result.Rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(result.Rows))
	}

	if result.Rows[0].Source != "security" || result.Rows[0].EventType != "login" {
		t.Fatalf("unexpected windows normalization row: %#v", result.Rows[0])
	}
	if result.Rows[1].Source != "auth" || result.Rows[1].EventType != "login" {
		t.Fatalf("unexpected linux normalization row: %#v", result.Rows[1])
	}
	if result.Rows[2].Source != "other" || result.Rows[2].EventType != "other" || result.Rows[2].EventCode != "unknown" {
		t.Fatalf("unexpected fallback normalization row: %#v", result.Rows[2])
	}
}

func TestNormalizeEventTypeTreatsSystemdUnitMessagesAsService(t *testing.T) {
	t.Parallel()

	got := normalizeEventType("", "syslog", "Reached target sockets.target - Sockets.")
	if got != "service" {
		t.Fatalf("expected service for systemd target message, got %q", got)
	}
}

func TestNormalizeEventTypeDoesNotInferLoginFromAuthSourceAlone(t *testing.T) {
	t.Parallel()

	got := normalizeEventType("", "auth", "Acquired the name org.freedesktop.PolicyKit1 on the system bus")
	if got == "login" {
		t.Fatalf("expected non-login classification for non-login auth message, got %q", got)
	}
}

func TestNormalizeResultTreatsRootLoginAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "ROOT LOGIN on '/dev/pts/1'")
	if got != "success" {
		t.Fatalf("expected success for root login message, got %q", got)
	}
}

func TestNormalizeResultTreatsCouldNotAsFail(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", `WARNING Daemon: could not connect to Windows Agent: open /path: no such file or directory`)
	if got != "fail" {
		t.Fatalf("expected fail for could-not message, got %q", got)
	}
}

func TestNormalizeEventActionTreatsRootLoginAsLogin(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "ROOT LOGIN on '/dev/pts/1'")
	if got != "login" {
		t.Fatalf("expected login action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsListeningOnAsStart(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "Listening on dbus.socket - D-Bus User Message Bus Socket.")
	if got != "start" {
		t.Fatalf("expected start action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsAcquiredNameAsAllow(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "Acquired the name org.freedesktop.PolicyKit1 on the system bus")
	if got != "allow" {
		t.Fatalf("expected allow action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsRuleDirectoryLoadAsRead(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "Loading rules from directory /etc/polkit-1/rules.d")
	if got != "read" {
		t.Fatalf("expected read action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsActivatingViaSystemdAsStart(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", `[system] Activating via systemd: service name='org.freedesktop.PolicyKit1' unit='polkit.service' requested by ':1.14'`)
	if got != "start" {
		t.Fatalf("expected start action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsGenericDirectoryLoadAsRead(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "Loaded policy from directory /etc/app/policies")
	if got != "read" {
		t.Fatalf("expected read action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsExitingAfterAsStop(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "WARNING Exiting after <nil>: check if the Windows agent is installed and running.")
	if got != "stop" {
		t.Fatalf("expected stop action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsNewSessionAsLogin(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "New session 4 of user root.")
	if got != "login" {
		t.Fatalf("expected login action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsNewSeatAsStart(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "New seat seat0.")
	if got != "start" {
		t.Fatalf("expected start action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsSessionClosedAsLogout(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "pam_unix(cron:session): session closed for user root")
	if got != "logout" {
		t.Fatalf("expected logout action, got %q", got)
	}
}

func TestNormalizeEventActionTreatsPoweringDownAsStop(t *testing.T) {
	t.Parallel()

	got := normalizeEventAction("", "System is powering down.")
	if got != "stop" {
		t.Fatalf("expected stop action, got %q", got)
	}
}

func TestNormalizeResultTreatsListeningOnAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "Listening on dbus.socket - D-Bus User Message Bus Socket.")
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestNormalizeResultTreatsAcquiredNameAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "Acquired the name org.freedesktop.PolicyKit1 on the system bus")
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestNormalizeResultTreatsRuleDirectoryLoadAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "Loading rules from directory /etc/polkit-1/rules.d")
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestNormalizeResultTreatsActivatingViaSystemdAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", `[system] Activating via systemd: service name='org.freedesktop.PolicyKit1' unit='polkit.service' requested by ':1.14'`)
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestNormalizeResultTreatsFaultyModuleAsFail(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "PAM adding faulty module: pam_lastlog.so")
	if got != "fail" {
		t.Fatalf("expected fail for faulty module message, got %q", got)
	}
}

func TestNormalizeResultTreatsNewSessionAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "New session 4 of user root.")
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestNormalizeResultTreatsNewSeatAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "New seat seat0.")
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestNormalizeResultTreatsSessionClosedAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "pam_unix(cron:session): session closed for user root")
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestNormalizeResultTreatsStoppedAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "Stopped polkit.service - Authorization Manager.")
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestNormalizeResultTreatsPoweringDownAsSuccess(t *testing.T) {
	t.Parallel()

	got := normalizeResult("", "System is powering down.")
	if got != "success" {
		t.Fatalf("expected success, got %q", got)
	}
}

func TestRawContentPolicyRedactionAndTruncation(t *testing.T) {
	t.Parallel()

	base := QueryParams{
		StartTime: 1,
		EndTime:   999999999,
	}

	noRawParams, err := normalizeParams(base)
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}
	noRaw := buildResult(noRawParams, []rawEvent{
		{
			NativeID:   "raw-no",
			Timestamp:  10,
			Source:     "system",
			EventType:  "system",
			RawContent: map[string]any{"password": "abc"},
		},
	})
	if len(noRaw.Rows) != 1 {
		t.Fatalf("expected one row, got %d", len(noRaw.Rows))
	}
	if noRaw.Rows[0].RawContent != nil {
		t.Fatalf("expected rawContent omitted by default, got %#v", noRaw.Rows[0].RawContent)
	}

	withRawParams, err := normalizeParams(QueryParams{
		StartTime:         1,
		EndTime:           999999999,
		IncludeRawContent: true,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}
	withRaw := buildResult(withRawParams, []rawEvent{
		{
			NativeID:  "raw-yes",
			Timestamp: 20,
			Source:    "system",
			EventType: "system",
			RawContent: map[string]any{
				"password": "abc",
				"nested": map[string]any{
					"token": "secret-token",
				},
			},
		},
		{
			NativeID:  "raw-big",
			Timestamp: 21,
			Source:    "system",
			EventType: "system",
			RawContent: map[string]any{
				"blob": strings.Repeat("x", maxRawContentBytes+128),
			},
		},
	})
	if len(withRaw.Rows) != 2 {
		t.Fatalf("expected two rows, got %d", len(withRaw.Rows))
	}

	rowsByTS := map[int64]EventRow{}
	for _, row := range withRaw.Rows {
		rowsByTS[row.Timestamp] = row
	}

	redacted, ok := rowsByTS[20].RawContent.(map[string]any)
	if !ok {
		t.Fatalf("expected map rawContent, got %#v", rowsByTS[20].RawContent)
	}
	if redacted["password"] != "[REDACTED]" {
		t.Fatalf("expected password redacted, got %#v", redacted["password"])
	}
	nested, ok := redacted["nested"].(map[string]any)
	if !ok || nested["token"] != "[REDACTED]" {
		t.Fatalf("expected nested token redacted, got %#v", redacted["nested"])
	}

	truncated, ok := rowsByTS[21].RawContent.(map[string]any)
	if !ok {
		t.Fatalf("expected truncated map, got %#v", rowsByTS[21].RawContent)
	}
	if truncated["_truncated"] != true {
		t.Fatalf("expected _truncated=true, got %#v", truncated["_truncated"])
	}
}

func TestLogIDStabilityNativeAndFallback(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	nativeEvent := rawEvent{
		NativeID:   "security:42",
		Timestamp:  100,
		Source:     "security",
		EventType:  "login",
		EventLevel: "warn",
		EventCode:  "4625",
		Message:    "native id event",
	}
	fallbackEvent := rawEvent{
		Timestamp:  200,
		Source:     "system",
		EventType:  "process",
		EventLevel: "info",
		EventCode:  "1000",
		Message:    "fallback id event",
	}

	run1 := buildResult(params, []rawEvent{nativeEvent, fallbackEvent})
	run2 := buildResult(params, []rawEvent{nativeEvent, fallbackEvent})
	if len(run1.Rows) != 2 || len(run2.Rows) != 2 {
		t.Fatalf("unexpected rows count: run1=%d run2=%d", len(run1.Rows), len(run2.Rows))
	}

	ids1 := map[int64]string{}
	ids2 := map[int64]string{}
	for _, row := range run1.Rows {
		ids1[row.Timestamp] = row.LogID
	}
	for _, row := range run2.Rows {
		ids2[row.Timestamp] = row.LogID
	}
	if ids1[100] != ids2[100] || ids1[200] != ids2[200] {
		t.Fatalf("expected stable log IDs across runs, got run1=%v run2=%v", ids1, ids2)
	}
	if !strings.HasPrefix(ids1[100], "native_") {
		t.Fatalf("expected native id prefix for native event, got %s", ids1[100])
	}
	if !strings.HasPrefix(ids1[200], "evt_") {
		t.Fatalf("expected fallback id prefix for non-native event, got %s", ids1[200])
	}
}

func TestEventlogExportAppliesMaxLogsAfterSort(t *testing.T) {
	original := collectEventlogPlatformEvents
	collectEventlogPlatformEvents = func(_ context.Context, _ QueryParams, emit rawEventSink) error {
		for _, event := range []rawEvent{
			{NativeID: "a", Timestamp: 1000, Source: "system", EventType: "system", Message: "third"},
			{NativeID: "b", Timestamp: 3000, Source: "system", EventType: "system", Message: "first"},
			{NativeID: "c", Timestamp: 2000, Source: "system", EventType: "system", Message: "second"},
		} {
			if err := emit(event); err != nil {
				return err
			}
		}
		return nil
	}
	t.Cleanup(func() { collectEventlogPlatformEvents = original })

	exported, err := Export(context.Background(), QueryParams{StartTime: 1, EndTime: 999999999, MaxLogs: 2})
	if err != nil {
		t.Fatalf("Export returned error: %v", err)
	}
	defer func() { _ = exported.Close() }()

	if exported.Total != 2 {
		t.Fatalf("expected total=2, got %d", exported.Total)
	}

	iter, err := exported.OpenRows()
	if err != nil {
		t.Fatalf("OpenRows returned error: %v", err)
	}
	defer func() { _ = iter.Close() }()

	row1, ok, err := iter.Next()
	if err != nil || !ok {
		t.Fatalf("expected first row, err=%v ok=%v", err, ok)
	}
	row2, ok, err := iter.Next()
	if err != nil || !ok {
		t.Fatalf("expected second row, err=%v ok=%v", err, ok)
	}
	if row1.Timestamp != 3000 || row2.Timestamp != 2000 {
		t.Fatalf("expected sort+maxLogs order, got %d then %d", row1.Timestamp, row2.Timestamp)
	}
}

func TestEventlogExportWritesJSONLSpool(t *testing.T) {
	original := collectEventlogPlatformEvents
	collectEventlogPlatformEvents = func(_ context.Context, _ QueryParams, emit rawEventSink) error {
		return emit(rawEvent{NativeID: "x", Timestamp: 1, Source: "system", EventType: "system", Message: "one"})
	}
	t.Cleanup(func() { collectEventlogPlatformEvents = original })

	exported, err := Export(context.Background(), QueryParams{StartTime: 1, EndTime: 2})
	if err != nil {
		t.Fatalf("Export returned error: %v", err)
	}
	defer func() { _ = exported.Close() }()

	data, err := os.ReadFile(exported.RowsPath)
	if err != nil {
		t.Fatalf("read rows path: %v", err)
	}
	if !strings.Contains(string(data), `"timestamp":1`) {
		t.Fatalf("expected JSONL spool content, got %s", string(data))
	}

	var rows []EventRow
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var row EventRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("unmarshal row: %v", err)
		}
		rows = append(rows, row)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
}

func TestExportResultCloseRemovesSpoolDir(t *testing.T) {
	original := collectEventlogPlatformEvents
	collectEventlogPlatformEvents = func(_ context.Context, _ QueryParams, emit rawEventSink) error {
		return emit(rawEvent{NativeID: "x", Timestamp: 1, Source: "system", EventType: "system", Message: "one"})
	}
	t.Cleanup(func() { collectEventlogPlatformEvents = original })

	exported, err := Export(context.Background(), QueryParams{StartTime: 1, EndTime: 2})
	if err != nil {
		t.Fatalf("Export returned error: %v", err)
	}
	spoolDir := exported.SpoolDir
	if err := exported.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if _, err := os.Stat(spoolDir); !os.IsNotExist(err) {
		t.Fatalf("expected spool dir removed, stat err=%v", err)
	}
}

func TestEventlogExportGuardFailsWithSuggestions(t *testing.T) {
	originalCollector := collectEventlogPlatformEvents
	originalMaxRows := eventlogGuardMaxRows
	collectEventlogPlatformEvents = func(_ context.Context, _ QueryParams, emit rawEventSink) error {
		for i := 0; i < 3; i++ {
			if err := emit(rawEvent{
				NativeID:   "guard",
				Timestamp:  int64(1000 + i),
				Source:     "system",
				EventType:  "system",
				EventLevel: "info",
				Message:    "guard-trigger",
			}); err != nil {
				return err
			}
		}
		return nil
	}
	eventlogGuardMaxRows = 2
	t.Cleanup(func() {
		collectEventlogPlatformEvents = originalCollector
		eventlogGuardMaxRows = originalMaxRows
	})

	_, err := Export(context.Background(), QueryParams{StartTime: 1, EndTime: 999999999})
	if err == nil {
		t.Fatal("expected safety guard error")
	}
	got := err.Error()
	if !strings.Contains(got, "safety guard triggered") {
		t.Fatalf("expected guard marker, got %q", got)
	}
	if !strings.Contains(got, "OOM/SIGKILL") {
		t.Fatalf("expected OOM/SIGKILL hint, got %q", got)
	}
	if !strings.Contains(got, "narrow time range") {
		t.Fatalf("expected narrowing suggestion, got %q", got)
	}
}

func strPtr(value string) *string {
	return &value
}
