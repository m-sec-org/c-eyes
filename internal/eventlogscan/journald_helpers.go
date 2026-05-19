package eventlogscan

import (
	"net"
	"os/user"
	"regexp"
	"strconv"
	"strings"
)

var (
	journalEventCodePattern  = regexp.MustCompile(`\b(?:eventid|event_id|id|code)=([A-Za-z0-9_.-]+)\b`)
	journalAuditTypePattern  = regexp.MustCompile(`\btype=([A-Za-z0-9_.-]+)\b`)
	journalTargetPathPattern = regexp.MustCompile(`\b(?:path|file|filename|exe|cmd|cwd)=["']?([^"'\s]+)`)
	journalIPPattern         = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	journalPortPattern       = regexp.MustCompile(`\b(?:port|sport|dport)=(\d{1,5})\b`)
	journalProtocolPattern   = regexp.MustCompile(`\b(tcp|udp|http|https|icmp|dns)\b`)
)

func matchLinuxJournalSource(fields map[string]string, requested []string) (string, bool) {
	actual := normalizeLinuxJournalActualSource(fields)
	sources := requested
	if len(sources) == 0 {
		sources = []string{"syslog", "auth", "audit", "kern"}
	}
	for _, source := range sources {
		switch normalizeSource(source) {
		case "security":
			if actual == "auth" || actual == "audit" {
				return "security", true
			}
		case "system":
			if actual == "syslog" {
				return "system", true
			}
		case "application":
			if actual == "syslog" {
				return "application", true
			}
		case actual:
			return actual, true
		}
	}
	return "", false
}

func normalizeLinuxJournalActualSource(fields map[string]string) string {
	transport := strings.ToLower(strings.TrimSpace(fields["_TRANSPORT"]))
	facility := strings.TrimSpace(fields["SYSLOG_FACILITY"])

	switch {
	case transport == "audit":
		return "audit"
	case transport == "kernel" || facility == "0":
		return "kern"
	case facility == "4" || facility == "10":
		return "auth"
	default:
		return "syslog"
	}
}

func buildLinuxJournalEvent(fields map[string]string, timestamp int64, source string) rawEvent {
	message := strings.TrimSpace(fields["MESSAGE"])
	processName := firstNonEmptyJournalValue(fields["_EXE"], fields["_COMM"], fields["SYSLOG_IDENTIFIER"], fields["_SYSTEMD_UNIT"])
	processID := parseJournalPID(fields["_PID"])
	username := lookupJournalUsername(fields["_UID"])
	localIP, remoteIP := journalParseLinuxIPs(message)
	localPort, remotePort := journalParseLinuxPorts(message)

	return rawEvent{
		Timestamp:   timestamp,
		OSType:      "linux",
		Source:      source,
		EventLevel:  mapLinuxJournalPriority(fields["PRIORITY"]),
		EventCode:   parseLinuxJournalEventCode(fields, message),
		Hostname:    strings.TrimSpace(fields["_HOSTNAME"]),
		ProcessName: processName,
		ProcessID:   processID,
		Username:    username,
		TargetPath:  journalParseLinuxTargetPath(message),
		LocalIP:     localIP,
		LocalPort:   localPort,
		RemoteIP:    remoteIP,
		RemotePort:  remotePort,
		Protocol:    journalParseLinuxProtocol(message),
		Message:     message,
		RawContent: map[string]any{
			"collector":        "linux-journald-api",
			"hostname":         fields["_HOSTNAME"],
			"syslogIdentifier": fields["SYSLOG_IDENTIFIER"],
			"comm":             fields["_COMM"],
			"exe":              fields["_EXE"],
			"pid":              fields["_PID"],
			"uid":              fields["_UID"],
			"transport":        fields["_TRANSPORT"],
			"facility":         fields["SYSLOG_FACILITY"],
			"systemdUnit":      fields["_SYSTEMD_UNIT"],
			"priority":         fields["PRIORITY"],
			"message":          message,
		},
	}
}

func firstNonEmptyJournalValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func parseJournalPID(raw string) *int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	pid, err := strconv.Atoi(raw)
	if err != nil || pid <= 0 {
		return nil
	}
	return &pid
}

func lookupJournalUsername(uid string) string {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return ""
	}
	account, err := user.LookupId(uid)
	if err != nil {
		return uid
	}
	return strings.TrimSpace(account.Username)
}

func mapLinuxJournalPriority(raw string) string {
	switch strings.TrimSpace(raw) {
	case "0", "1", "2":
		return "critical"
	case "3":
		return "error"
	case "4":
		return "warn"
	case "5":
		return "notice"
	case "6":
		return "info"
	case "7":
		return "debug"
	default:
		return ""
	}
}

func parseLinuxJournalEventCode(fields map[string]string, message string) string {
	if code := journalParseLinuxEventCode(message); code != "unknown" {
		return code
	}
	if ident := strings.TrimSpace(fields["SYSLOG_IDENTIFIER"]); ident != "" {
		return ident
	}
	if unit := strings.TrimSpace(fields["_SYSTEMD_UNIT"]); unit != "" {
		return unit
	}
	return "unknown"
}

func journalParseLinuxEventCode(line string) string {
	if matches := journalEventCodePattern.FindStringSubmatch(line); len(matches) == 2 {
		return strings.TrimSpace(matches[1])
	}
	if matches := journalAuditTypePattern.FindStringSubmatch(line); len(matches) == 2 {
		return strings.TrimSpace(matches[1])
	}
	return "unknown"
}

func journalParseLinuxTargetPath(line string) string {
	if matches := journalTargetPathPattern.FindStringSubmatch(line); len(matches) == 2 {
		return strings.TrimSpace(matches[1])
	}
	parts := strings.Fields(line)
	for _, part := range parts {
		if strings.Contains(part, "/") {
			candidate := strings.Trim(part, "\"' ,;")
			if candidate == "/" {
				continue
			}
			return candidate
		}
	}
	return ""
}

func journalParseLinuxIPs(line string) (string, string) {
	all := journalIPPattern.FindAllString(line, -1)
	if len(all) == 0 {
		return "", ""
	}

	var localIP string
	var remoteIP string
	for _, ip := range all {
		if parsed := net.ParseIP(ip); parsed == nil {
			continue
		}
		if journalIsPrivateIPv4(ip) && localIP == "" {
			localIP = ip
			continue
		}
		if remoteIP == "" {
			remoteIP = ip
		}
	}
	if localIP == "" {
		localIP = all[0]
	}
	if remoteIP == "" && len(all) > 1 {
		remoteIP = all[1]
	}
	return localIP, remoteIP
}

func journalParseLinuxPorts(line string) (*int, *int) {
	matches := journalPortPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	toPort := func(raw string) *int {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 65535 {
			return nil
		}
		return &n
	}
	local := toPort(matches[0][1])
	var remote *int
	if len(matches) > 1 {
		remote = toPort(matches[1][1])
	}
	return local, remote
}

func journalParseLinuxProtocol(line string) string {
	if match := journalProtocolPattern.FindString(strings.ToLower(line)); match != "" {
		return match
	}
	return ""
}

func journalIsPrivateIPv4(ip string) bool {
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
