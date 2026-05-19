package eventlogscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"edrsystem/internal/processscan"
)

const (
	maxRawContentBytes = 8 * 1024
)

var (
	allowedSortBy = map[string]struct{}{
		"timestamp":   {},
		"eventlevel":  {},
		"source":      {},
		"eventtype":   {},
		"processname": {},
	}
	allowedSortOrder = map[string]struct{}{
		"asc":  {},
		"desc": {},
	}
)

// Scan collects host logs, applies deterministic filtering/sorting,
// and returns all normalized eventlog rows in a single result envelope.
func Scan(ctx context.Context, params QueryParams) (ScanResult, error) {
	normalized, err := normalizeParams(params)
	if err != nil {
		return ScanResult{}, err
	}
	if normalized.Progress != nil {
		normalized.Progress(0, 1, "collect_events")
	}

	events, err := collectPlatformEvents(ctx, normalized)
	if err != nil {
		return ScanResult{}, err
	}

	result := buildResult(normalized, events)
	if normalized.Progress != nil {
		normalized.Progress(1, 1, "complete")
	}
	return result, nil
}

func normalizeParams(params QueryParams) (QueryParams, error) {
	if params.StartTime <= 0 {
		return params, fmt.Errorf("invalid argument: -startTime must be a unix timestamp in milliseconds")
	}
	if params.EndTime <= 0 {
		return params, fmt.Errorf("invalid argument: -endTime must be a unix timestamp in milliseconds")
	}
	if params.StartTime > params.EndTime {
		return params, fmt.Errorf("invalid argument: startTime cannot be greater than endTime")
	}
	if params.MaxLogs < 0 {
		return params, fmt.Errorf("invalid argument: maxLogs must be >= 0")
	}

	params.SortBy = normalizeSortBy(params.SortBy)
	if _, ok := allowedSortBy[params.SortBy]; !ok {
		return params, fmt.Errorf("invalid argument: sortBy only supports timestamp/eventLevel/source/eventType/processName")
	}
	params.SortOrder = normalizeSortOrder(params.SortOrder)
	if _, ok := allowedSortOrder[params.SortOrder]; !ok {
		return params, fmt.Errorf("invalid argument: sortOrder only supports asc/desc")
	}

	params.Sources = normalizeLowerUniqueList(params.Sources)
	params.EventTypes = normalizeLowerUniqueList(params.EventTypes)
	params.EventLevels = normalizeLowerUniqueList(params.EventLevels)
	params.EventCodes = normalizeLowerUniqueList(params.EventCodes)
	params.EventActions = normalizeLowerUniqueList(params.EventActions)
	params.Results = normalizeLowerUniqueList(params.Results)
	params.Protocols = normalizeLowerUniqueList(params.Protocols)

	params.ProcessName = trimStringPtr(params.ProcessName)
	params.Username = trimStringPtr(params.Username)
	params.TargetPath = trimStringPtr(params.TargetPath)
	params.LocalIP = trimStringPtr(params.LocalIP)
	params.RemoteIP = trimStringPtr(params.RemoteIP)
	params.Keyword = trimStringPtr(params.Keyword)

	if params.ProcessID != nil && *params.ProcessID <= 0 {
		return params, fmt.Errorf("invalid argument: processId must be a positive integer")
	}
	if params.LocalPort != nil && (*params.LocalPort < 0 || *params.LocalPort > 65535) {
		return params, fmt.Errorf("invalid argument: localPort must be between 0 and 65535")
	}
	if params.RemotePort != nil && (*params.RemotePort < 0 || *params.RemotePort > 65535) {
		return params, fmt.Errorf("invalid argument: remotePort must be between 0 and 65535")
	}

	return params, nil
}

func normalizeSortBy(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return DefaultSortBy
	}
	return trimmed
}

func normalizeSortOrder(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return DefaultSortOrder
	}
	return trimmed
}

func normalizeLowerUniqueList(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	out := make([]string, 0, len(input))
	for _, item := range input {
		key := strings.ToLower(strings.TrimSpace(item))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func trimStringPtr(ptr *string) *string {
	if ptr == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*ptr)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func buildResult(params QueryParams, events []rawEvent) ScanResult {
	hostInfo, _ := processscan.GetHostInfo()
	rows := normalizeEvents(events, hostInfo, params.IncludeRawContent)
	rows = applyFilters(rows, params)
	sortRows(rows, params.SortBy, params.SortOrder)
	if params.MaxLogs > 0 && len(rows) > params.MaxLogs {
		rows = rows[:params.MaxLogs]
	}

	total := len(rows)
	allRows := make([]EventRow, total)
	copy(allRows, rows)

	return ScanResult{
		Total: total,
		Rows:  allRows,
	}
}

func normalizeEvents(events []rawEvent, host processscan.HostInfo, includeRaw bool) []EventRow {
	rows := make([]EventRow, 0, len(events))
	for _, event := range events {
		row := EventRow{
			Timestamp: event.Timestamp,
			OSType:    normalizeOSType(event.OSType),
			Source:    normalizeSource(event.Source),
		}
		if row.Timestamp <= 0 {
			continue
		}

		row.EventType = normalizeEventType(event.EventType, row.Source, event.Message)
		row.EventLevel = normalizeEventLevel(event.EventLevel, event.Message)
		row.EventCode = normalizeEventCode(event.EventCode)
		row.EventAction = normalizeEventAction(event.EventAction, event.Message)
		row.Result = normalizeResult(event.Result, event.Message)

		row.Hostname = firstNonEmptyPtr(event.Hostname, host.Hostname)
		row.DisplayIP = resolveDisplayIP(event.DisplayIP, host.DisplayIP)
		row.InternalIPList = resolveIPList(event.InternalIPs, host.InternalIPs)
		row.ExternalIPList = resolveIPList(event.ExternalIPs, host.ExternalIPs)

		row.Username = optionalString(event.Username)
		row.ProcessName = optionalString(event.ProcessName)
		row.ProcessID = cloneIntPtr(event.ProcessID)
		row.ParentProcessName = optionalString(event.ParentProcName)
		row.ParentProcessID = cloneIntPtr(event.ParentProcID)
		row.TargetPath = optionalString(event.TargetPath)
		row.LocalIP = optionalString(event.LocalIP)
		row.LocalPort = cloneIntPtr(event.LocalPort)
		row.RemoteIP = optionalString(event.RemoteIP)
		row.RemotePort = cloneIntPtr(event.RemotePort)
		row.Protocol = optionalString(normalizeProtocol(event.Protocol))
		row.Message = optionalString(event.Message)

		if includeRaw {
			if event.RawContent == nil {
				row.RawContent = map[string]any{}
			} else {
				row.RawContent = sanitizeRawContent(event.RawContent)
			}
		}

		row.LogID = generateLogID(event, row)
		rows = append(rows, row)
	}
	return rows
}

func normalizeOSType(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "windows" || trimmed == "linux" {
		return trimmed
	}
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	default:
		return runtime.GOOS
	}
}

func normalizeSource(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	switch key {
	case "system":
		return "system"
	case "security":
		return "security"
	case "application":
		return "application"
	case "syslog", "message", "messages":
		return "syslog"
	case "auth", "authpriv":
		return "auth"
	case "audit":
		return "audit"
	case "kern", "kernel":
		return "kern"
	default:
		return "other"
	}
}

func normalizeEventType(raw, source, message string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	switch key {
	case "process", "proc", "process_create", "process_start", "exec", "execution":
		return "process"
	case "file", "fs", "filesystem":
		return "file"
	case "network", "net", "socket", "connection":
		return "network"
	case "registry", "reg":
		return "registry"
	case "account", "user", "identity":
		return "account"
	case "service", "daemon":
		return "service"
	case "login", "logon", "auth", "authentication":
		return "login"
	case "system", "kernel", "boot":
		return "system"
	case "policy":
		return "policy"
	case "other":
		return "other"
	}

	infer := inferEventTypeFromMessage(source, message)
	if infer != "" {
		return infer
	}
	return "other"
}

func inferEventTypeFromMessage(source, message string) string {
	lower := strings.ToLower(source + " " + message)
	switch {
	case strings.Contains(lower, "logon"),
		strings.Contains(lower, "login"),
		strings.Contains(lower, "auth"),
		strings.Contains(lower, "ssh"):
		return "login"
	case strings.Contains(lower, "process"),
		strings.Contains(lower, "exec"),
		strings.Contains(lower, "pid="):
		return "process"
	case strings.Contains(lower, "registry"):
		return "registry"
	case strings.Contains(lower, "socket"),
		strings.Contains(lower, "connect"),
		strings.Contains(lower, "tcp"),
		strings.Contains(lower, "udp"),
		strings.Contains(lower, "http"):
		return "network"
	case strings.Contains(lower, "file"),
		strings.Contains(lower, "path="),
		strings.Contains(lower, "unlink"),
		strings.Contains(lower, "chmod"),
		strings.Contains(lower, "rename"):
		return "file"
	case strings.Contains(lower, "service"),
		strings.Contains(lower, "systemd"):
		return "service"
	case strings.Contains(lower, "user"),
		strings.Contains(lower, "account"):
		return "account"
	case strings.Contains(lower, "policy"),
		strings.Contains(lower, "rule"):
		return "policy"
	case strings.Contains(lower, "kernel"),
		strings.Contains(lower, "boot"),
		strings.Contains(lower, "system"):
		return "system"
	default:
		return ""
	}
}

func normalizeEventLevel(raw, message string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	switch key {
	case "debug":
		return "debug"
	case "info", "information":
		return "info"
	case "notice":
		return "notice"
	case "warn", "warning":
		return "warn"
	case "error", "err":
		return "error"
	case "critical", "crit":
		return "critical"
	case "fatal":
		return "fatal"
	case "other":
		return "other"
	}

	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "fatal"):
		return "fatal"
	case strings.Contains(lower, "critical"), strings.Contains(lower, "panic"):
		return "critical"
	case strings.Contains(lower, "error"), strings.Contains(lower, "fail"):
		return "error"
	case strings.Contains(lower, "warn"):
		return "warn"
	case strings.Contains(lower, "notice"):
		return "notice"
	case strings.Contains(lower, "debug"):
		return "debug"
	case lower != "":
		return "info"
	default:
		return "other"
	}
}

func normalizeEventCode(raw string) string {
	code := strings.TrimSpace(raw)
	if code == "" {
		return "unknown"
	}
	return code
}

func normalizeEventAction(raw, message string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	switch key {
	case "create", "modify", "delete", "start", "stop", "connect", "login", "logout", "read", "write", "execute", "allow", "deny":
		return key
	case "update":
		return "modify"
	case "other":
		return "other"
	}

	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "create"):
		return "create"
	case strings.Contains(lower, "modify"), strings.Contains(lower, "change"), strings.Contains(lower, "update"):
		return "modify"
	case strings.Contains(lower, "delete"), strings.Contains(lower, "remove"), strings.Contains(lower, "unlink"):
		return "delete"
	case strings.Contains(lower, "start"), strings.Contains(lower, "launch"):
		return "start"
	case strings.Contains(lower, "stop"), strings.Contains(lower, "shutdown"):
		return "stop"
	case strings.Contains(lower, "connect"), strings.Contains(lower, "accept"):
		return "connect"
	case strings.Contains(lower, "logon"), strings.Contains(lower, "login"), strings.Contains(lower, "signin"):
		return "login"
	case strings.Contains(lower, "logout"), strings.Contains(lower, "signout"):
		return "logout"
	case strings.Contains(lower, "read"):
		return "read"
	case strings.Contains(lower, "write"):
		return "write"
	case strings.Contains(lower, "exec"), strings.Contains(lower, "run"):
		return "execute"
	case strings.Contains(lower, "allow"), strings.Contains(lower, "accepted"), strings.Contains(lower, "success"):
		return "allow"
	case strings.Contains(lower, "deny"), strings.Contains(lower, "reject"), strings.Contains(lower, "block"):
		return "deny"
	default:
		return "other"
	}
}

func normalizeResult(raw, message string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	switch key {
	case "success", "ok", "passed", "allow", "allowed":
		return "success"
	case "fail", "failed", "error", "deny", "denied", "blocked", "block":
		return "fail"
	case "unknown":
		return "unknown"
	}

	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "fail"),
		strings.Contains(lower, "denied"),
		strings.Contains(lower, "blocked"),
		strings.Contains(lower, "error"),
		strings.Contains(lower, "reject"):
		return "fail"
	case strings.Contains(lower, "success"),
		strings.Contains(lower, "accepted"),
		strings.Contains(lower, "allowed"),
		strings.Contains(lower, "ok"):
		return "success"
	default:
		return "unknown"
	}
}

func normalizeProtocol(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	switch key {
	case "tcp", "udp", "http", "https", "icmp", "dns":
		return key
	default:
		return key
	}
}

func resolveDisplayIP(raw string, fallback *string) *string {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return &raw
	}
	if fallback == nil {
		return nil
	}
	dup := strings.TrimSpace(*fallback)
	if dup == "" {
		return nil
	}
	return &dup
}

func resolveIPList(raw, fallback []string) []string {
	if len(raw) > 0 {
		return copyNormalizedList(raw)
	}
	if len(fallback) > 0 {
		return copyNormalizedList(fallback)
	}
	return []string{}
}

func copyNormalizedList(input []string) []string {
	out := make([]string, 0, len(input))
	seen := map[string]struct{}{}
	for _, item := range input {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return []string{}
	}
	return out
}

func firstNonEmptyPtr(primary, fallback string) *string {
	if trimmed := strings.TrimSpace(primary); trimmed != "" {
		return &trimmed
	}
	if trimmed := strings.TrimSpace(fallback); trimmed != "" {
		return &trimmed
	}
	return nil
}

func optionalString(raw string) *string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func cloneIntPtr(ptr *int) *int {
	if ptr == nil {
		return nil
	}
	val := *ptr
	return &val
}

func applyFilters(rows []EventRow, params QueryParams) []EventRow {
	if len(rows) == 0 {
		return rows
	}

	sourcesSet := listToSet(params.Sources)
	eventTypesSet := listToSet(params.EventTypes)
	eventLevelsSet := listToSet(params.EventLevels)
	eventCodesSet := listToSet(params.EventCodes)
	eventActionsSet := listToSet(params.EventActions)
	resultsSet := listToSet(params.Results)
	protocolsSet := listToSet(params.Protocols)

	processName := normalizedNeedle(params.ProcessName)
	username := normalizedNeedle(params.Username)
	targetPath := normalizedNeedle(params.TargetPath)
	localIP := normalizedNeedle(params.LocalIP)
	remoteIP := normalizedNeedle(params.RemoteIP)
	keyword := normalizedNeedle(params.Keyword)

	out := make([]EventRow, 0, len(rows))
	for _, row := range rows {
		if !matchesSet(row.Source, sourcesSet) {
			continue
		}
		if !matchesSet(row.EventType, eventTypesSet) {
			continue
		}
		if !matchesSet(row.EventLevel, eventLevelsSet) {
			continue
		}
		if !matchesSet(row.EventCode, eventCodesSet) {
			continue
		}
		if !matchesSet(row.EventAction, eventActionsSet) {
			continue
		}
		if !matchesSet(row.Result, resultsSet) {
			continue
		}
		if !matchesSet(ptrString(row.Protocol), protocolsSet) {
			continue
		}

		if processName != "" && !containsFold(ptrString(row.ProcessName), processName) {
			continue
		}
		if username != "" && !containsFold(ptrString(row.Username), username) {
			continue
		}
		if targetPath != "" && !containsFold(ptrString(row.TargetPath), targetPath) {
			continue
		}
		if localIP != "" && !containsFold(ptrString(row.LocalIP), localIP) {
			continue
		}
		if remoteIP != "" && !containsFold(ptrString(row.RemoteIP), remoteIP) {
			continue
		}
		if params.ProcessID != nil {
			if row.ProcessID == nil || *row.ProcessID != *params.ProcessID {
				continue
			}
		}
		if params.LocalPort != nil {
			if row.LocalPort == nil || *row.LocalPort != *params.LocalPort {
				continue
			}
		}
		if params.RemotePort != nil {
			if row.RemotePort == nil || *row.RemotePort != *params.RemotePort {
				continue
			}
		}
		if keyword != "" && !matchesKeyword(row, keyword) {
			continue
		}

		out = append(out, row)
	}
	return out
}

func listToSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item))
		if key == "" {
			continue
		}
		set[key] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func matchesSet(value string, set map[string]struct{}) bool {
	if len(set) == 0 {
		return true
	}
	key := strings.ToLower(strings.TrimSpace(value))
	_, ok := set[key]
	return ok
}

func normalizedNeedle(value *string) string {
	if value == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(*value))
}

func ptrString(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return strings.TrimSpace(*ptr)
}

func containsFold(value, needle string) bool {
	if needle == "" {
		return true
	}
	if value == "" {
		return false
	}
	return strings.Contains(strings.ToLower(value), needle)
}

func matchesKeyword(row EventRow, keyword string) bool {
	if keyword == "" {
		return true
	}

	fields := []string{
		row.Source,
		row.EventType,
		row.EventLevel,
		row.EventCode,
		row.EventAction,
		row.Result,
		ptrString(row.Hostname),
		ptrString(row.DisplayIP),
		strings.Join(row.InternalIPList, " "),
		strings.Join(row.ExternalIPList, " "),
		ptrString(row.Username),
		ptrString(row.ProcessName),
		ptrString(row.TargetPath),
		ptrString(row.LocalIP),
		ptrString(row.RemoteIP),
		ptrString(row.Protocol),
		ptrString(row.Message),
		strconv.FormatInt(row.Timestamp, 10),
	}
	if row.ProcessID != nil {
		fields = append(fields, strconv.Itoa(*row.ProcessID))
	}
	if row.LocalPort != nil {
		fields = append(fields, strconv.Itoa(*row.LocalPort))
	}
	if row.RemotePort != nil {
		fields = append(fields, strconv.Itoa(*row.RemotePort))
	}
	if row.RawContent != nil {
		if bytes, err := json.Marshal(row.RawContent); err == nil {
			fields = append(fields, string(bytes))
		}
	}

	all := strings.ToLower(strings.Join(fields, " "))
	return strings.Contains(all, keyword)
}

func sortRows(rows []EventRow, sortBy, sortOrder string) {
	desc := strings.EqualFold(sortOrder, "desc")
	sort.SliceStable(rows, func(i, j int) bool {
		cmp := comparePrimary(rows[i], rows[j], sortBy)
		if cmp != 0 {
			if desc {
				return cmp > 0
			}
			return cmp < 0
		}

		// Keep page boundaries deterministic regardless of primary collisions.
		if rows[i].Timestamp != rows[j].Timestamp {
			return rows[i].Timestamp > rows[j].Timestamp
		}
		return rows[i].LogID < rows[j].LogID
	})
}

func comparePrimary(a, b EventRow, sortBy string) int {
	switch sortBy {
	case "timestamp":
		return compareInt64(a.Timestamp, b.Timestamp)
	case "eventlevel":
		return compareInt(levelRank(a.EventLevel), levelRank(b.EventLevel))
	case "source":
		return compareStringFold(a.Source, b.Source)
	case "eventtype":
		return compareStringFold(a.EventType, b.EventType)
	case "processname":
		return compareStringFold(ptrString(a.ProcessName), ptrString(b.ProcessName))
	default:
		return compareInt64(a.Timestamp, b.Timestamp)
	}
}

func compareInt64(a, b int64) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	default:
		return 0
	}
}

func compareInt(a, b int) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	default:
		return 0
	}
}

func compareStringFold(a, b string) int {
	la := strings.ToLower(strings.TrimSpace(a))
	lb := strings.ToLower(strings.TrimSpace(b))
	switch {
	case la > lb:
		return 1
	case la < lb:
		return -1
	default:
		return 0
	}
}

func levelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return 1
	case "info":
		return 2
	case "notice":
		return 3
	case "warn":
		return 4
	case "error":
		return 5
	case "critical":
		return 6
	case "fatal":
		return 7
	default:
		return 0
	}
}

func generateLogID(event rawEvent, row EventRow) string {
	native := strings.TrimSpace(event.NativeID)
	if native != "" {
		candidate := sanitizeIDToken(strings.ToLower(row.Source) + ":" + native)
		if candidate != "" && len(candidate) <= 56 {
			return "native_" + candidate
		}
		return "native_" + shortHash(strings.ToLower(row.Source)+"|"+native)
	}

	payload := strings.Join([]string{
		strconv.FormatInt(row.Timestamp, 10),
		row.OSType,
		row.Source,
		row.EventType,
		row.EventLevel,
		row.EventCode,
		row.EventAction,
		row.Result,
		ptrString(row.Hostname),
		ptrString(row.Username),
		ptrString(row.ProcessName),
		intPtrString(row.ProcessID),
		ptrString(row.TargetPath),
		ptrString(row.LocalIP),
		intPtrString(row.LocalPort),
		ptrString(row.RemoteIP),
		intPtrString(row.RemotePort),
		ptrString(row.Protocol),
		ptrString(row.Message),
	}, "|")
	return "evt_" + shortHash(payload)
}

func intPtrString(ptr *int) string {
	if ptr == nil {
		return ""
	}
	return strconv.Itoa(*ptr)
}

func sanitizeIDToken(input string) string {
	if strings.TrimSpace(input) == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(strings.TrimSpace(b.String()), "_")
}

func shortHash(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:16])
}

func sanitizeRawContent(raw any) any {
	normalized := normalizeRawValue(raw)
	redacted := redactSensitive(normalized)
	bytes, err := json.Marshal(redacted)
	if err != nil {
		return map[string]any{
			"_truncated": false,
			"_error":     "rawContent marshal failed",
		}
	}
	if len(bytes) <= maxRawContentBytes {
		return redacted
	}
	return map[string]any{
		"_truncated":      true,
		"_truncatedBytes": len(bytes) - maxRawContentBytes,
		"_preview":        string(bytes[:maxRawContentBytes]),
	}
}

func normalizeRawValue(raw any) any {
	if raw == nil {
		return map[string]any{}
	}
	switch raw.(type) {
	case map[string]any, []any, string, bool, float64, int, int64, uint64, nil:
		return raw
	}

	bytes, err := json.Marshal(raw)
	if err != nil {
		return map[string]any{"value": fmt.Sprint(raw)}
	}
	var out any
	if err := json.Unmarshal(bytes, &out); err != nil {
		return map[string]any{"value": string(bytes)}
	}
	return out
}

func redactSensitive(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if isSensitiveKey(key) {
				out[key] = "[REDACTED]"
				continue
			}
			out[key] = redactSensitive(typed[key])
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, redactSensitive(item))
		}
		return out
	default:
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Map, reflect.Struct, reflect.Slice, reflect.Array:
			return redactSensitive(normalizeRawValue(value))
		default:
			return value
		}
	}
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(key), "-", ""), "_", ""))
	if normalized == "" {
		return false
	}
	sensitive := []string{
		"password",
		"passwd",
		"pwd",
		"secret",
		"token",
		"apikey",
		"authorization",
		"cookie",
		"session",
		"privatekey",
		"accesskey",
		"credential",
	}
	for _, marker := range sensitive {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
