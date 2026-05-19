//go:build linux && cgo

package eventlogscan

/*
#cgo LDFLAGS: -l:libsystemd.so.0
#include <stdint.h>
#include <stdlib.h>

typedef struct sd_journal sd_journal;
int sd_journal_open(sd_journal **ret, int flags);
void sd_journal_close(sd_journal *j);
int sd_journal_seek_tail(sd_journal *j);
int sd_journal_previous(sd_journal *j);
int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret);
int sd_journal_get_cursor(sd_journal *j, char **cursor);
int sd_journal_restart_data(sd_journal *j);
int sd_journal_get_data(sd_journal *j, const char *field, const void **data, size_t *length);

static int go_sd_journal_get_data(sd_journal *j, const char *field, const char **data, size_t *length) {
	const void *tmp = NULL;
	int rc = sd_journal_get_data(j, field, &tmp, length);
	*data = (const char *)tmp;
	return rc;
}
*/
import "C"

import (
	"context"
	"os"
	"strings"
	"unsafe"
)

var linuxJournalFields = []string{
	"MESSAGE",
	"_HOSTNAME",
	"SYSLOG_IDENTIFIER",
	"_COMM",
	"_EXE",
	"_PID",
	"_UID",
	"_TRANSPORT",
	"SYSLOG_FACILITY",
	"_SYSTEMD_UNIT",
	"PRIORITY",
}

func collectJournaldEvents(ctx context.Context, params QueryParams) ([]rawEvent, bool, error) {
	if !journalStorageAvailable() {
		return nil, false, nil
	}

	var journal *C.sd_journal
	if rc := int(C.sd_journal_open(&journal, 0)); rc < 0 || journal == nil {
		return nil, false, nil
	}
	defer C.sd_journal_close(journal)

	if params.Progress != nil {
		params.Progress(0, 1, "collect_journald")
	}

	if rc := int(C.sd_journal_seek_tail(journal)); rc < 0 {
		return nil, false, nil
	}

	events := make([]rawEvent, 0, 512)
	for {
		select {
		case <-ctx.Done():
			return events, true, ctx.Err()
		default:
		}

		rc := int(C.sd_journal_previous(journal))
		if rc < 0 {
			return nil, false, nil
		}
		if rc == 0 {
			break
		}

		timestamp, ok := journalRealtimeMillis(journal)
		if !ok {
			continue
		}
		if timestamp < params.StartTime {
			break
		}
		if timestamp > params.EndTime {
			continue
		}

		fields, ok := readJournalFields(journal)
		if !ok {
			continue
		}

		source, ok := matchLinuxJournalSource(fields, params.Sources)
		if !ok {
			continue
		}

		event := buildLinuxJournalEvent(fields, timestamp, source)
		if cursor, ok := journalCursor(journal); ok && cursor != "" {
			event.NativeID = "journal:" + cursor
		}
		events = append(events, event)
	}

	if params.Progress != nil {
		params.Progress(1, 1, "collect_journald")
	}

	if len(events) == 0 {
		return nil, false, nil
	}
	return events, true, nil
}

func journalStorageAvailable() bool {
	for _, path := range []string{"/run/log/journal", "/var/log/journal"} {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

func journalRealtimeMillis(journal *C.sd_journal) (int64, bool) {
	var usec C.uint64_t
	if rc := int(C.sd_journal_get_realtime_usec(journal, &usec)); rc < 0 {
		return 0, false
	}
	return int64(usec / 1000), true
}

func journalCursor(journal *C.sd_journal) (string, bool) {
	var cursor *C.char
	if rc := int(C.sd_journal_get_cursor(journal, &cursor)); rc < 0 || cursor == nil {
		return "", false
	}
	defer C.free(unsafe.Pointer(cursor))
	return strings.TrimSpace(C.GoString(cursor)), true
}

func readJournalFields(journal *C.sd_journal) (map[string]string, bool) {
	fields := make(map[string]string, len(linuxJournalFields))
	for _, name := range linuxJournalFields {
		cname := C.CString(name)
		var data *C.char
		var length C.size_t
		rc := int(C.go_sd_journal_get_data(journal, cname, &data, &length))
		C.free(unsafe.Pointer(cname))
		if rc < 0 || data == nil || length == 0 {
			continue
		}

		raw := C.GoBytes(unsafe.Pointer(data), C.int(length))
		parts := strings.SplitN(string(raw), "=", 2)
		if len(parts) != 2 {
			continue
		}
		fields[name] = strings.TrimSpace(parts[1])
	}
	return fields, true
}
