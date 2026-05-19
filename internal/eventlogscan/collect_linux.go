//go:build linux

package eventlogscan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type linuxLogTarget struct {
	Source string
	Path   string
}

var (
	auditEpochPattern      = regexp.MustCompile(`audit\((\d+)(?:\.\d+)?:`)
	rfc3339Pattern         = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)
	syslogTimestampPattern = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})`)
	processTokenPattern    = regexp.MustCompile(`\s([A-Za-z0-9_./-]+)(?:\[(\d+)\])?:`)
	pidPattern             = regexp.MustCompile(`\bpid=(\d+)\b`)
	eventCodePattern       = regexp.MustCompile(`\b(?:eventid|event_id|id|code)=([A-Za-z0-9_.-]+)\b`)
	auditTypePattern       = regexp.MustCompile(`\btype=([A-Za-z0-9_.-]+)\b`)
	targetPathPattern      = regexp.MustCompile(`\b(?:path|file|filename|exe|cmd|cwd)=["']?([^"'\s]+)`)
	ipPattern              = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	portPattern            = regexp.MustCompile(`\b(?:port|sport|dport)=(\d{1,5})\b`)
	protocolPattern        = regexp.MustCompile(`\b(tcp|udp|http|https|icmp|dns)\b`)
)

func collectPlatformEvents(ctx context.Context, params QueryParams) ([]rawEvent, error) {
	if events, used, err := collectJournaldEvents(ctx, params); err == nil && used {
		return events, nil
	}

	targets := resolveLinuxTargets(params.Sources)
	events := make([]rawEvent, 0, 512)
	totalTargets := len(targets)
	completedTargets := 0

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		file, err := os.Open(target.Path)
		if err != nil {
			completedTargets++
			if params.Progress != nil {
				params.Progress(completedTargets, totalTargets, "collect_"+target.Source)
			}
			continue
		}

		info, _ := file.Stat()
		fallbackTimestamp := time.Now().UnixMilli()
		if info != nil {
			fallbackTimestamp = info.ModTime().UnixMilli()
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		lineNo := 0
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				_ = file.Close()
				return events, ctx.Err()
			default:
			}

			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			timestamp := parseLinuxTimestamp(line, fallbackTimestamp)
			if timestamp < params.StartTime || timestamp > params.EndTime {
				continue
			}

			processName, processID := parseLinuxProcessContext(line)
			localIP, remoteIP := parseLinuxIPs(line)
			localPort, remotePort := parseLinuxPorts(line)
			protocol := parseLinuxProtocol(line)

			events = append(events, rawEvent{
				NativeID:    fmt.Sprintf("%s:%d", target.Path, lineNo),
				Timestamp:   timestamp,
				OSType:      "linux",
				Source:      target.Source,
				EventType:   "",
				EventLevel:  "",
				EventCode:   parseLinuxEventCode(line),
				EventAction: "",
				Result:      "",
				ProcessName: processName,
				ProcessID:   processID,
				TargetPath:  parseLinuxTargetPath(line),
				LocalIP:     localIP,
				LocalPort:   localPort,
				RemoteIP:    remoteIP,
				RemotePort:  remotePort,
				Protocol:    protocol,
				Message:     line,
				RawContent: map[string]any{
					"collector": "linux-file-reader",
					"file":      target.Path,
					"lineNo":    lineNo,
					"line":      line,
				},
			})
		}
		_ = file.Close()

		completedTargets++
		if params.Progress != nil {
			params.Progress(completedTargets, totalTargets, "collect_"+target.Source)
		}
	}

	return events, nil
}

func resolveLinuxTargets(sources []string) []linuxLogTarget {
	sourceToPaths := map[string][]string{
		"syslog":      {"/var/log/syslog", "/var/log/messages"},
		"auth":        {"/var/log/auth.log", "/var/log/secure"},
		"audit":       {"/var/log/audit/audit.log"},
		"kern":        {"/var/log/kern.log"},
		"system":      {"/var/log/syslog", "/var/log/messages"},
		"application": {"/var/log/syslog", "/var/log/messages"},
		"security":    {"/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log"},
	}

	defaultSources := []string{"syslog", "auth", "audit", "kern"}
	selected := sources
	if len(selected) == 0 {
		selected = defaultSources
	}

	seenPath := map[string]struct{}{}
	targets := make([]linuxLogTarget, 0, 8)
	for _, src := range selected {
		normSource := normalizeSource(src)
		if normSource == "other" {
			continue
		}
		paths := sourceToPaths[normSource]
		for _, path := range paths {
			if _, ok := seenPath[path]; ok {
				continue
			}
			seenPath[path] = struct{}{}
			targets = append(targets, linuxLogTarget{
				Source: normSource,
				Path:   path,
			})
		}
	}
	return targets
}

func parseLinuxTimestamp(line string, fallback int64) int64 {
	if matches := auditEpochPattern.FindStringSubmatch(line); len(matches) == 2 {
		if sec, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			return sec * 1000
		}
	}

	if match := rfc3339Pattern.FindString(line); match != "" {
		if parsed, err := time.Parse(time.RFC3339, match); err == nil {
			return parsed.UnixMilli()
		}
	}

	if matches := syslogTimestampPattern.FindStringSubmatch(line); len(matches) == 2 {
		compact := strings.Join(strings.Fields(matches[1]), " ")
		partial, err := time.ParseInLocation("Jan 2 15:04:05", compact, time.Local)
		if err == nil {
			now := time.Now()
			candidate := time.Date(now.Year(), partial.Month(), partial.Day(), partial.Hour(), partial.Minute(), partial.Second(), 0, time.Local)
			if candidate.After(now.Add(24 * time.Hour)) {
				candidate = candidate.AddDate(-1, 0, 0)
			}
			return candidate.UnixMilli()
		}
	}

	return fallback
}

func parseLinuxProcessContext(line string) (string, *int) {
	if matches := processTokenPattern.FindStringSubmatch(line); len(matches) >= 2 {
		name := strings.TrimSpace(matches[1])
		if len(matches) == 3 && matches[2] != "" {
			if pid, err := strconv.Atoi(matches[2]); err == nil && pid > 0 {
				return name, &pid
			}
		}
		if name != "" {
			return name, nil
		}
	}

	if matches := pidPattern.FindStringSubmatch(line); len(matches) == 2 {
		if pid, err := strconv.Atoi(matches[1]); err == nil && pid > 0 {
			return "", &pid
		}
	}
	return "", nil
}

func parseLinuxEventCode(line string) string {
	if matches := eventCodePattern.FindStringSubmatch(line); len(matches) == 2 {
		return strings.TrimSpace(matches[1])
	}
	if matches := auditTypePattern.FindStringSubmatch(line); len(matches) == 2 {
		return strings.TrimSpace(matches[1])
	}
	return "unknown"
}

func parseLinuxTargetPath(line string) string {
	if matches := targetPathPattern.FindStringSubmatch(line); len(matches) == 2 {
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

func parseLinuxIPs(line string) (string, string) {
	all := ipPattern.FindAllString(line, -1)
	if len(all) == 0 {
		return "", ""
	}

	var localIP string
	var remoteIP string
	for _, ip := range all {
		if parsed := net.ParseIP(ip); parsed == nil {
			continue
		}
		if isPrivateIPv4(ip) && localIP == "" {
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

func parseLinuxPorts(line string) (*int, *int) {
	matches := portPattern.FindAllStringSubmatch(line, -1)
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

func parseLinuxProtocol(line string) string {
	if match := protocolPattern.FindString(strings.ToLower(line)); match != "" {
		return match
	}
	return ""
}

func isPrivateIPv4(ip string) bool {
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
