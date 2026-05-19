//go:build windows

package eventlogscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	eventLogSequentialRead uint32 = 0x0001
	eventLogBackwardsRead  uint32 = 0x0008

	eventLogErrorType    uint16 = 0x0001
	eventLogWarningType  uint16 = 0x0002
	eventLogInfoType     uint16 = 0x0004
	eventLogAuditSuccess uint16 = 0x0008
	eventLogAuditFailure uint16 = 0x0010
)

type eventLogRecord struct {
	Length              uint32
	Reserved            uint32
	RecordNumber        uint32
	TimeGenerated       uint32
	TimeWritten         uint32
	EventID             uint32
	EventType           uint16
	NumStrings          uint16
	EventCategory       uint16
	ReservedFlags       uint16
	ClosingRecordNumber uint32
	StringOffset        uint32
	UserSidLength       uint32
	UserSidOffset       uint32
	DataLength          uint32
	DataOffset          uint32
}

var (
	modAdvapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procOpenEventLog  = modAdvapi32.NewProc("OpenEventLogW")
	procReadEventLog  = modAdvapi32.NewProc("ReadEventLogW")
	procCloseEventLog = modAdvapi32.NewProc("CloseEventLog")

	windowsPIDPattern      = regexp.MustCompile(`(?i)\b(?:pid|process id|processid|new process id|caller process id|execution process id)[\s:=]+(0x[0-9a-f]+|\d+)\b`)
	windowsHexPattern      = regexp.MustCompile(`(?i)^0x[0-9a-f]+$`)
	windowsGuidPattern     = regexp.MustCompile(`(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$`)
	windowsSIDPattern      = regexp.MustCompile(`(?i)^s-\d-\d+(?:-\d+)+$`)
	windowsDecimalPattern  = regexp.MustCompile(`^\d+$`)
	windowsPercentRef      = regexp.MustCompile(`(?i)^%%\d+$`)
	windowsPathPattern     = regexp.MustCompile(`([A-Za-z]:\\[^\s"']+)`)
	windowsEventCode       = regexp.MustCompile(`(?i)\b(?:event id|eventid|code)[\s:=]+([A-Za-z0-9_.-]+)\b`)
	windowsIPPattern       = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	windowsPortPattern     = regexp.MustCompile(`(?i)\b(?:port|srcport|dstport|source port|destination port)[\s:=]+(\d{1,5})\b`)
	windowsProtocolPattern = regexp.MustCompile(`(?i)\b(tcp|udp|http|https|icmp|dns)\b`)
)

var windowsSecurityMessageSummary = map[string]string{
	"4624": "An account was successfully logged on.",
	"4625": "An account failed to log on.",
	"4627": "Group membership information.",
	"4634": "An account was logged off.",
	"4647": "User initiated logoff.",
	"4648": "A logon was attempted using explicit credentials.",
	"4672": "Special privileges assigned to new logon.",
	"4688": "A new process has been created.",
	"4689": "A process has exited.",
	"4776": "The computer attempted to validate the credentials for an account.",
	"4798": "A user's local group membership was enumerated.",
}

func collectPlatformEvents(ctx context.Context, params QueryParams) ([]rawEvent, error) {
	channels := resolveWindowsChannels(params.Sources)
	events := make([]rawEvent, 0, 512)
	totalChannels := len(channels)
	completedChannels := 0

	for _, channel := range channels {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		handle, err := openEventLog(channel)
		if err != nil {
			completedChannels++
			if params.Progress != nil {
				params.Progress(completedChannels, totalChannels, "collect_"+strings.ToLower(channel))
			}
			continue
		}

		buffer := make([]byte, 64*1024)
		stopChannel := false

		for !stopChannel {
			select {
			case <-ctx.Done():
				_ = closeEventLog(handle)
				return events, ctx.Err()
			default:
			}

			bytesRead, minNeeded, err := readEventLog(handle, eventLogSequentialRead|eventLogBackwardsRead, 0, buffer)
			if err != nil {
				if errors.Is(err, syscall.ERROR_HANDLE_EOF) {
					break
				}
				if errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) && minNeeded > uint32(len(buffer)) {
					buffer = make([]byte, minNeeded)
					continue
				}
				break
			}
			if bytesRead == 0 {
				break
			}

			offset := 0
			for offset < int(bytesRead) {
				if offset+int(unsafe.Sizeof(eventLogRecord{})) > int(bytesRead) {
					break
				}
				rec := (*eventLogRecord)(unsafe.Pointer(&buffer[offset]))
				if rec.Length == 0 {
					break
				}
				next := offset + int(rec.Length)
				if next > int(bytesRead) {
					break
				}

				timestamp := int64(rec.TimeGenerated) * 1000
				if timestamp < params.StartTime {
					stopChannel = true
					break
				}
				if timestamp > params.EndTime {
					offset = next
					continue
				}

				payload := buffer[offset:next]
				parsed := parseWindowsRecord(channel, payload, rec)
				parsed.Timestamp = timestamp
				events = append(events, parsed)

				offset = next
			}
		}

		_ = closeEventLog(handle)

		completedChannels++
		if params.Progress != nil {
			params.Progress(completedChannels, totalChannels, "collect_"+strings.ToLower(channel))
		}
	}

	return events, nil
}

func resolveWindowsChannels(sources []string) []string {
	sourceToChannel := map[string][]string{
		"system":      {"System"},
		"application": {"Application"},
		"security":    {"Security"},
		"auth":        {"Security"},
		"audit":       {"Security"},
		"kern":        {"System"},
		"syslog":      {"System"},
	}

	selected := sources
	if len(selected) == 0 {
		selected = []string{"system", "application", "security"}
	}

	seen := map[string]struct{}{}
	channels := make([]string, 0, 4)
	for _, src := range selected {
		norm := normalizeSource(src)
		for _, channel := range sourceToChannel[norm] {
			if _, ok := seen[channel]; ok {
				continue
			}
			seen[channel] = struct{}{}
			channels = append(channels, channel)
		}
	}
	return channels
}

func openEventLog(channel string) (windows.Handle, error) {
	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	r1, _, e1 := procOpenEventLog.Call(0, uintptr(unsafe.Pointer(channelPtr)))
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); ok && errno != 0 {
			return 0, errno
		}
		return 0, fmt.Errorf("open event log %s failed", channel)
	}
	return windows.Handle(r1), nil
}

func readEventLog(handle windows.Handle, flags, offset uint32, buffer []byte) (uint32, uint32, error) {
	if len(buffer) == 0 {
		return 0, 0, syscall.ERROR_INSUFFICIENT_BUFFER
	}
	var bytesRead uint32
	var minNeeded uint32
	r1, _, e1 := procReadEventLog.Call(
		uintptr(handle),
		uintptr(flags),
		uintptr(offset),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(uint32(len(buffer))),
		uintptr(unsafe.Pointer(&bytesRead)),
		uintptr(unsafe.Pointer(&minNeeded)),
	)
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); ok && errno != 0 {
			return 0, minNeeded, errno
		}
		return 0, minNeeded, syscall.EINVAL
	}
	return bytesRead, minNeeded, nil
}

func closeEventLog(handle windows.Handle) error {
	r1, _, e1 := procCloseEventLog.Call(uintptr(handle))
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); ok && errno != 0 {
			return errno
		}
		return syscall.EINVAL
	}
	return nil
}

func parseWindowsRecord(channel string, payload []byte, rec *eventLogRecord) rawEvent {
	headerLen := int(unsafe.Sizeof(eventLogRecord{}))
	sourceName, offset := readUTF16Z(payload, headerLen)
	computerName, _ := readUTF16Z(payload, offset)
	stringsList := readInsertionStrings(payload, int(rec.StringOffset), int(rec.NumStrings))
	channelLower := strings.ToLower(channel)
	fullText := strings.TrimSpace(strings.Join(stringsList, " | "))
	eventCode := parseWindowsEventCode(fullText, rec.EventID)
	message := buildWindowsMessageSummary(channelLower, eventCode, stringsList, fullText)

	sidUsername := lookupRecordUserSID(payload, rec)
	username := extractWindowsUsername(channelLower, eventCode, stringsList, sidUsername)
	processName, processID := parseWindowsProcess(channelLower, eventCode, stringsList, fullText)
	targetPath := parseWindowsTargetPath(stringsList, fullText, processName)

	localIP, remoteIP := parseWindowsIPs(fullText)
	localPort, remotePort := parseWindowsPorts(fullText)
	protocol := parseWindowsProtocol(fullText)

	result := ""
	switch rec.EventType {
	case eventLogAuditSuccess:
		result = "success"
	case eventLogAuditFailure:
		result = "fail"
	default:
		result = ""
	}

	return rawEvent{
		NativeID:    fmt.Sprintf("%s:%d", strings.ToLower(channel), rec.RecordNumber),
		OSType:      "windows",
		Source:      strings.ToLower(channel),
		EventType:   "",
		EventLevel:  mapWindowsEventLevel(rec.EventType),
		EventCode:   eventCode,
		EventAction: "",
		Result:      result,
		Hostname:    computerName,
		Username:    username,
		ProcessName: processName,
		ProcessID:   processID,
		TargetPath:  targetPath,
		LocalIP:     localIP,
		LocalPort:   localPort,
		RemoteIP:    remoteIP,
		RemotePort:  remotePort,
		Protocol:    protocol,
		Message:     message,
		RawContent: map[string]any{
			"collector":    "windows-eventlog-api",
			"channel":      channel,
			"sourceName":   sourceName,
			"computerName": computerName,
			"recordNumber": rec.RecordNumber,
			"eventID":      rec.EventID,
			"eventTypeRaw": rec.EventType,
			"strings":      stringsList,
			"sidUser":      sidUsername,
		},
	}
}

func mapWindowsEventLevel(eventType uint16) string {
	switch eventType {
	case eventLogErrorType:
		return "error"
	case eventLogWarningType:
		return "warn"
	case eventLogInfoType, eventLogAuditSuccess:
		return "info"
	case eventLogAuditFailure:
		return "error"
	default:
		return "other"
	}
}

func parseWindowsEventCode(message string, eventID uint32) string {
	if matches := windowsEventCode.FindStringSubmatch(message); len(matches) == 2 {
		return strings.TrimSpace(matches[1])
	}
	return fmt.Sprintf("%d", eventID&0xFFFF)
}

func readUTF16Z(payload []byte, offset int) (string, int) {
	if offset < 0 || offset >= len(payload) {
		return "", offset
	}
	words := make([]uint16, 0, 32)
	for offset+1 < len(payload) {
		word := binary.LittleEndian.Uint16(payload[offset : offset+2])
		offset += 2
		if word == 0 {
			break
		}
		words = append(words, word)
	}
	if len(words) == 0 {
		return "", offset
	}
	return strings.TrimSpace(string(utf16.Decode(words))), offset
}

func readInsertionStrings(payload []byte, offset, count int) []string {
	if offset < 0 || offset >= len(payload) || count <= 0 {
		return nil
	}
	out := make([]string, 0, count)
	for i := 0; i < count && offset < len(payload); i++ {
		value, next := readUTF16Z(payload, offset)
		if next <= offset {
			break
		}
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
		offset = next
	}
	return out
}

func parseWindowsProcess(channel, eventCode string, stringsList []string, fullText string) (string, *int) {
	if channel == "security" {
		secProcessName := extractSecurityProcessName(eventCode, stringsList)
		secProcessID := extractSecurityProcessID(eventCode, stringsList)
		if secProcessName != "" || secProcessID != nil {
			return secProcessName, secProcessID
		}
	}

	for _, item := range stringsList {
		if path := windowsPathPattern.FindString(item); path != "" {
			if pid := extractPIDFromLabeledText(item); pid != nil {
				return path, pid
			}
			return path, nil
		}
	}

	if path := windowsPathPattern.FindString(fullText); path != "" {
		if pid := extractPIDFromLabeledText(fullText); pid != nil {
			return path, pid
		}
		return path, nil
	}

	if pid := extractPIDFromLabeledText(fullText); pid != nil {
		return "", pid
	}
	return "", nil
}

func buildWindowsMessageSummary(channel, eventCode string, stringsList []string, fallback string) string {
	candidates := make([]string, 0, 3)
	for _, item := range stringsList {
		trimmed := strings.TrimSpace(item)
		if !isLikelyTextualMessagePart(trimmed) {
			continue
		}
		candidates = append(candidates, trimmed)
		if len(candidates) >= 3 {
			break
		}
	}

	if channel == "security" {
		if summary, ok := windowsSecurityMessageSummary[eventCode]; ok {
			if len(candidates) > 0 {
				return summary + " | " + strings.Join(candidates, " | ")
			}
			return summary
		}
	}

	if len(candidates) > 0 {
		return strings.Join(candidates, " | ")
	}
	if strings.TrimSpace(fallback) != "" {
		return strings.TrimSpace(fallback)
	}
	return fmt.Sprintf("event %s", eventCode)
}

func isLikelyTextualMessagePart(value string) bool {
	if value == "" {
		return false
	}
	if value == "-" || windowsSIDPattern.MatchString(value) || windowsGuidPattern.MatchString(value) ||
		windowsHexPattern.MatchString(value) || windowsPercentRef.MatchString(value) ||
		windowsPathPattern.MatchString(value) || windowsDecimalPattern.MatchString(value) {
		return false
	}
	if net.ParseIP(value) != nil {
		return false
	}
	hasLetter := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

func lookupRecordUserSID(payload []byte, rec *eventLogRecord) string {
	if rec == nil || rec.UserSidLength == 0 {
		return ""
	}
	start := int(rec.UserSidOffset)
	end := start + int(rec.UserSidLength)
	if start < 0 || end > len(payload) || start >= end {
		return ""
	}

	sid := (*windows.SID)(unsafe.Pointer(&payload[start]))
	if sid == nil {
		return ""
	}

	account, domain, _, err := sid.LookupAccount("")
	if err == nil && strings.TrimSpace(account) != "" {
		account = strings.TrimSpace(account)
		domain = strings.TrimSpace(domain)
		if domain != "" {
			return domain + `\` + account
		}
		return account
	}

	if sidText := strings.TrimSpace(sid.String()); sidText != "" {
		return sidText
	}
	return ""
}

func extractWindowsUsername(channel, eventCode string, stringsList []string, sidUser string) string {
	if channel == "security" {
		if user := extractSecurityUsername(eventCode, stringsList); user != "" {
			return user
		}
	}

	if user := extractGenericUsername(stringsList); user != "" {
		return user
	}
	return strings.TrimSpace(sidUser)
}

func extractSecurityUsername(eventCode string, fields []string) string {
	specs := []struct {
		userIdx   int
		domainIdx int
	}{
		{-1, -1},
		{-1, -1},
	}

	switch eventCode {
	case "4624", "4625":
		specs[0] = struct{ userIdx, domainIdx int }{5, 6}
		specs[1] = struct{ userIdx, domainIdx int }{1, 2}
	case "4627":
		specs[0] = struct{ userIdx, domainIdx int }{5, 6}
		specs[1] = struct{ userIdx, domainIdx int }{1, 2}
	case "4634", "4647", "4672", "4688", "4689":
		specs[0] = struct{ userIdx, domainIdx int }{1, 2}
	case "4648":
		specs[0] = struct{ userIdx, domainIdx int }{5, 6}
		specs[1] = struct{ userIdx, domainIdx int }{1, 2}
	case "4776":
		specs[0] = struct{ userIdx, domainIdx int }{1, -1}
	case "4798":
		specs[0] = struct{ userIdx, domainIdx int }{4, 5}
		specs[1] = struct{ userIdx, domainIdx int }{1, 2}
	case "4799":
		specs[0] = struct{ userIdx, domainIdx int }{4, 5}
		specs[1] = struct{ userIdx, domainIdx int }{1, 2}
	default:
		specs[0] = struct{ userIdx, domainIdx int }{1, 2}
	}

	for _, spec := range specs {
		user := cleanWindowsToken(fieldAt(fields, spec.userIdx))
		domain := cleanWindowsToken(fieldAt(fields, spec.domainIdx))
		if !isLikelyUsernameToken(user) {
			continue
		}
		return composeWindowsAccount(domain, user)
	}

	return extractGenericUsername(fields)
}

func extractGenericUsername(fields []string) string {
	for _, item := range fields {
		token := cleanWindowsToken(item)
		if !isLikelyUsernameToken(token) {
			continue
		}
		return token
	}
	return ""
}

func composeWindowsAccount(domain, user string) string {
	user = cleanWindowsToken(user)
	domain = cleanWindowsToken(domain)
	if user == "" {
		return ""
	}
	if domain == "" || domain == "-" || strings.Contains(user, `\`) {
		return user
	}
	if windowsGuidPattern.MatchString(domain) || windowsSIDPattern.MatchString(domain) || windowsHexPattern.MatchString(domain) {
		return user
	}
	return domain + `\` + user
}

func isLikelyUsernameToken(token string) bool {
	if token == "" || token == "-" {
		return false
	}
	if windowsSIDPattern.MatchString(token) || windowsGuidPattern.MatchString(token) ||
		windowsHexPattern.MatchString(token) || windowsPercentRef.MatchString(token) ||
		windowsPathPattern.MatchString(token) || windowsDecimalPattern.MatchString(token) {
		return false
	}
	if net.ParseIP(token) != nil {
		return false
	}
	upper := strings.ToUpper(token)
	switch upper {
	case "WORKGROUP", "BUILTIN", "NT AUTHORITY", "LOCAL", "NONE":
		return false
	}
	if strings.Contains(token, "{") || strings.Contains(token, "}") {
		return false
	}
	return true
}

func extractSecurityProcessID(eventCode string, fields []string) *int {
	switch eventCode {
	case "4624":
		return parsePIDToken(fieldAt(fields, 16))
	case "4625":
		// Some templates expose ProcessId at index 17, others at 18.
		if pid := parsePIDToken(fieldAt(fields, 17)); pid != nil {
			return pid
		}
		return parsePIDToken(fieldAt(fields, 18))
	case "4648":
		return parsePIDToken(fieldAt(fields, 10))
	case "4688":
		// Prefer creator process id, fallback to new process id.
		if pid := parsePIDToken(fieldAt(fields, 7)); pid != nil {
			return pid
		}
		return parsePIDToken(fieldAt(fields, 4))
	case "4689":
		return parsePIDToken(fieldAt(fields, 4))
	case "4798":
		return parsePIDToken(fieldAt(fields, 7))
	case "4799":
		return parsePIDToken(fieldAt(fields, 7))
	case "5058":
		return parsePIDToken(fieldAt(fields, 4))
	case "5059":
		return parsePIDToken(fieldAt(fields, 4))
	case "5379":
		return parsePIDToken(fieldAt(fields, 10))
	case "5382":
		if pid := parsePIDToken(fieldAt(fields, 12)); pid != nil {
			return pid
		}
		// Insertion string parsing drops empty entries, which can shift this by -1.
		return parsePIDToken(fieldAt(fields, 11))
	default:
		return nil
	}
}

func extractSecurityProcessName(eventCode string, fields []string) string {
	switch eventCode {
	case "4624":
		return cleanWindowsPath(fieldAt(fields, 17))
	case "4625":
		// Some templates expose ProcessName at index 18, others at 19.
		if name := cleanWindowsPath(fieldAt(fields, 18)); name != "" {
			return name
		}
		return cleanWindowsPath(fieldAt(fields, 19))
	case "4648":
		return cleanWindowsPath(fieldAt(fields, 11))
	case "4688":
		return cleanWindowsPath(fieldAt(fields, 5))
	case "4689":
		return cleanWindowsPath(fieldAt(fields, 5))
	case "4798":
		return cleanWindowsPath(fieldAt(fields, 8))
	case "4799":
		return cleanWindowsPath(fieldAt(fields, 8))
	default:
		return ""
	}
}

func parseWindowsTargetPath(stringsList []string, fullText string, processName string) string {
	for _, item := range stringsList {
		if path := cleanWindowsPath(item); path != "" {
			return path
		}
	}
	if path := cleanWindowsPath(fullText); path != "" {
		return path
	}
	return strings.TrimSpace(processName)
}

func cleanWindowsPath(raw string) string {
	match := windowsPathPattern.FindString(raw)
	if strings.TrimSpace(match) == "" {
		return ""
	}
	return strings.TrimSpace(match)
}

func extractPIDFromLabeledText(text string) *int {
	matches := windowsPIDPattern.FindStringSubmatch(text)
	if len(matches) != 2 {
		return nil
	}
	return parsePIDToken(matches[1])
}

func parsePIDToken(raw string) *int {
	token := strings.TrimSpace(raw)
	if token == "" || token == "-" {
		return nil
	}

	var (
		value int64
		err   error
	)
	if windowsHexPattern.MatchString(token) {
		value, err = strconv.ParseInt(strings.TrimPrefix(strings.ToLower(token), "0x"), 16, 64)
	} else if windowsDecimalPattern.MatchString(token) {
		value, err = strconv.ParseInt(token, 10, 64)
	} else {
		return nil
	}
	if err != nil || value <= 0 || value > 2147483647 {
		return nil
	}
	parsed := int(value)
	return &parsed
}

func fieldAt(fields []string, idx int) string {
	if idx < 0 || idx >= len(fields) {
		return ""
	}
	return fields[idx]
}

func cleanWindowsToken(raw string) string {
	return strings.Trim(strings.TrimSpace(raw), "\"'")
}

func parseWindowsIPs(message string) (string, string) {
	all := windowsIPPattern.FindAllString(message, -1)
	if len(all) == 0 {
		return "", ""
	}
	var local string
	var remote string
	for _, ip := range all {
		if parsed := net.ParseIP(ip); parsed == nil {
			continue
		}
		if isPrivateWindowsIPv4(ip) && local == "" {
			local = ip
			continue
		}
		if remote == "" {
			remote = ip
		}
	}
	if local == "" {
		local = all[0]
	}
	if remote == "" && len(all) > 1 {
		remote = all[1]
	}
	return local, remote
}

func parseWindowsPorts(message string) (*int, *int) {
	matches := windowsPortPattern.FindAllStringSubmatch(message, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	parse := func(raw string) *int {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 65535 {
			return nil
		}
		return &n
	}
	local := parse(matches[0][1])
	var remote *int
	if len(matches) > 1 {
		remote = parse(matches[1][1])
	}
	return local, remote
}

func parseWindowsProtocol(message string) string {
	if match := windowsProtocolPattern.FindString(strings.ToLower(message)); match != "" {
		return strings.ToLower(match)
	}
	return ""
}

func isPrivateWindowsIPv4(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return false
	}
	if ipv4[0] == 10 {
		return true
	}
	if ipv4[0] == 172 && ipv4[1]&0xf0 == 16 {
		return true
	}
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}
	return false
}
