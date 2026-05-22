package eventlogscan

import (
	"bufio"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"edrsystem/internal/processscan"
)

const defaultEventlogChunkSize = 2048

var collectEventlogPlatformEvents = collectPlatformEvents
var eventlogGuardMaxRows = 1_500_000
var eventlogGuardMaxChunks = 4096
var eventlogGuardMaxSpoolBytes int64 = 8 << 30

// Export streams normalized rows to disk-backed sorted chunks and returns the
// merged ordered result as a JSONL spool file.
func Export(ctx context.Context, params QueryParams) (*ExportResult, error) {
	return exportWithChunkSize(ctx, params, defaultEventlogChunkSize)
}

func exportWithChunkSize(ctx context.Context, params QueryParams, chunkSize int) (_ *ExportResult, err error) {
	normalized, err := normalizeParams(params)
	if err != nil {
		return nil, err
	}
	if chunkSize <= 0 {
		chunkSize = defaultEventlogChunkSize
	}

	hostInfo, _ := processscan.GetHostInfo()
	filter := newFilterState(normalized)

	spoolDir, err := os.MkdirTemp("", "eventlog-export-*")
	if err != nil {
		return nil, err
	}

	result := &ExportResult{
		SpoolDir:  spoolDir,
		SortBy:    normalized.SortBy,
		SortOrder: normalized.SortOrder,
		MaxLogs:   normalized.MaxLogs,
	}
	result.closeFn = func() error {
		return os.RemoveAll(spoolDir)
	}

	defer func() {
		if err != nil {
			_ = result.Close()
		}
	}()

	sink := &eventlogChunkSink{
		ctx:       ctx,
		params:    normalized,
		host:      hostInfo,
		filter:    filter,
		chunkSize: chunkSize,
		spoolDir:  spoolDir,
	}

	if normalized.Progress != nil {
		normalized.Progress(0, 1, "collect_events")
	}
	if err = collectEventlogPlatformEvents(ctx, normalized, sink.emit); err != nil {
		return nil, err
	}
	if err = sink.close(); err != nil {
		return nil, err
	}

	finalPath := filepath.Join(spoolDir, "rows.jsonl")
	var total int
	if total, err = mergeEventlogChunks(ctx, finalPath, sink.chunks, normalized); err != nil {
		return nil, err
	}
	result.Total = total
	result.RowsPath = finalPath

	if normalized.Progress != nil {
		normalized.Progress(1, 1, "complete")
	}

	return result, nil
}

func (r *ExportResult) OpenRows() (RowIterator, error) {
	if r == nil {
		return nil, fmt.Errorf("eventlog export result is nil")
	}
	if strings.TrimSpace(r.RowsPath) == "" {
		return nil, fmt.Errorf("eventlog export result does not contain a rows file")
	}
	return openJSONLRowIterator(r.RowsPath)
}

type eventlogChunkSink struct {
	ctx       context.Context
	params    QueryParams
	host      processscan.HostInfo
	filter    filterState
	chunkSize int
	spoolDir  string

	chunkIndex int
	buffer     []EventRow
	chunks     []ChunkMeta
	matchedRows int
	spoolBytes  int64
}

func (s *eventlogChunkSink) emit(event rawEvent) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	row, ok := normalizeEvent(event, s.host, s.params.IncludeRawContent)
	if !ok {
		return nil
	}
	if !s.filter.matches(row) {
		return nil
	}

	s.buffer = append(s.buffer, row)
	s.matchedRows++
	if err := s.guard("collect"); err != nil {
		return err
	}
	if len(s.buffer) < s.chunkSize {
		return nil
	}
	return s.flush()
}

func (s *eventlogChunkSink) close() error {
	return s.flush()
}

func (s *eventlogChunkSink) flush() error {
	if len(s.buffer) == 0 {
		return nil
	}

	sort.SliceStable(s.buffer, func(i, j int) bool {
		return eventlogRowLess(s.buffer[i], s.buffer[j], s.params.SortBy, s.params.SortOrder)
	})

	path := filepath.Join(s.spoolDir, fmt.Sprintf("chunk-%06d.jsonl", s.chunkIndex))
	writer, err := newJSONLRowWriter(path)
	if err != nil {
		return err
	}
	for _, row := range s.buffer {
		if err := writer.Write(row); err != nil {
			_ = writer.Close()
			return err
		}
	}
	writtenBytes := writer.BytesWritten()
	if err := writer.Close(); err != nil {
		return err
	}

	s.chunks = append(s.chunks, ChunkMeta{Path: path, Rows: len(s.buffer)})
	s.spoolBytes += writtenBytes
	s.chunkIndex++
	s.buffer = s.buffer[:0]
	if err := s.guard("flush"); err != nil {
		return err
	}
	return nil
}

func (s *eventlogChunkSink) guard(stage string) error {
	if s == nil {
		return nil
	}
	projectedChunks := s.chunkIndex
	if len(s.buffer) > 0 {
		projectedChunks++
	}
	if eventlogGuardMaxRows > 0 && s.matchedRows > eventlogGuardMaxRows {
		return newEventlogSafetyGuardError(stage, "row count", s.matchedRows, projectedChunks, s.spoolBytes)
	}
	if eventlogGuardMaxChunks > 0 && projectedChunks > eventlogGuardMaxChunks {
		return newEventlogSafetyGuardError(stage, "chunk count", s.matchedRows, projectedChunks, s.spoolBytes)
	}
	if eventlogGuardMaxSpoolBytes > 0 && s.spoolBytes > eventlogGuardMaxSpoolBytes {
		return newEventlogSafetyGuardError(stage, "spool size", s.matchedRows, projectedChunks, s.spoolBytes)
	}
	return nil
}

func newEventlogSafetyGuardError(stage, trigger string, rows, chunks int, spoolBytes int64) error {
	return fmt.Errorf(
		"eventlog safety guard triggered (%s at %s): matchedRows=%d, chunks=%d, spoolBytes=%d. "+
			"This query may overwhelm host resources and be terminated by the OS (OOM/SIGKILL). "+
			"Suggestions: narrow time range (-last/-startTime/-endTime), add filters (-sources/-eventTypes/-eventLevels/-processName/-username/-localIp/-remoteIp), "+
			"split into smaller time windows and merge offline, and prefer JSON/CSV output for very large collections",
		trigger,
		stage,
		rows,
		chunks,
		spoolBytes,
	)
}

func mergeEventlogChunks(ctx context.Context, finalPath string, chunks []ChunkMeta, params QueryParams) (int, error) {
	writer, err := newJSONLRowWriter(finalPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = writer.Close() }()

	if len(chunks) == 0 {
		return 0, nil
	}

	readers := make([]*jsonlRowIterator, 0, len(chunks))
	defer func() {
		for _, reader := range readers {
			_ = reader.Close()
		}
	}()

	h := &eventlogMergeHeap{
		sortBy:    params.SortBy,
		sortOrder: params.SortOrder,
	}

	for _, chunk := range chunks {
		reader, err := openJSONLRowIterator(chunk.Path)
		if err != nil {
			return 0, err
		}
		readers = append(readers, reader)
		row, ok, err := reader.Next()
		if err != nil {
			return 0, err
		}
		if ok {
			heap.Push(h, eventlogMergeItem{row: row, source: len(readers) - 1, chunk: len(readers) - 1})
		}
	}

	emitted := 0
	for h.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return emitted, err
		}
		if params.MaxLogs > 0 && emitted >= params.MaxLogs {
			break
		}

		item := heap.Pop(h).(eventlogMergeItem)
		if err := writer.Write(item.row); err != nil {
			return emitted, err
		}
		emitted++

		nextRow, ok, err := readers[item.source].Next()
		if err != nil {
			return emitted, err
		}
		if ok {
			heap.Push(h, eventlogMergeItem{row: nextRow, source: item.source, chunk: item.chunk})
		}
	}

	return emitted, nil
}

type eventlogMergeItem struct {
	row    EventRow
	source int
	chunk  int
}

type eventlogMergeHeap struct {
	items     []eventlogMergeItem
	sortBy    string
	sortOrder string
}

func (h eventlogMergeHeap) Len() int { return len(h.items) }

func (h eventlogMergeHeap) Less(i, j int) bool {
	if eventlogRowLess(h.items[i].row, h.items[j].row, h.sortBy, h.sortOrder) {
		return true
	}
	if eventlogRowLess(h.items[j].row, h.items[i].row, h.sortBy, h.sortOrder) {
		return false
	}
	return h.items[i].chunk < h.items[j].chunk
}

func (h eventlogMergeHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
}

func (h *eventlogMergeHeap) Push(x any) {
	h.items = append(h.items, x.(eventlogMergeItem))
}

func (h *eventlogMergeHeap) Pop() any {
	old := h.items
	n := len(old)
	item := old[n-1]
	h.items = old[:n-1]
	return item
}

func eventlogRowLess(a, b EventRow, sortBy, sortOrder string) bool {
	cmp := comparePrimary(a, b, sortBy)
	desc := strings.EqualFold(sortOrder, "desc")
	if cmp != 0 {
		if desc {
			return cmp > 0
		}
		return cmp < 0
	}
	if a.Timestamp != b.Timestamp {
		return a.Timestamp > b.Timestamp
	}
	return a.LogID < b.LogID
}

type jsonlRowWriter struct {
	file   *os.File
	writer *bufio.Writer
	bytes  int64
}

func newJSONLRowWriter(path string) (*jsonlRowWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &jsonlRowWriter{
		file:   file,
		writer: bufio.NewWriter(file),
	}, nil
}

func (w *jsonlRowWriter) Write(row EventRow) error {
	if w == nil || w.writer == nil {
		return fmt.Errorf("jsonl writer is closed")
	}
	data, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	if err := w.writer.WriteByte('\n'); err != nil {
		return err
	}
	w.bytes += int64(len(data) + 1)
	return nil
}

func (w *jsonlRowWriter) BytesWritten() int64 {
	if w == nil {
		return 0
	}
	return w.bytes
}

func (w *jsonlRowWriter) Close() error {
	if w == nil {
		return nil
	}
	var err error
	if w.writer != nil {
		if flushErr := w.writer.Flush(); flushErr != nil && err == nil {
			err = flushErr
		}
		w.writer = nil
	}
	if w.file != nil {
		if closeErr := w.file.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		w.file = nil
	}
	return err
}

type jsonlRowIterator struct {
	file   *os.File
	dec    *json.Decoder
	closed bool
}

func openJSONLRowIterator(path string) (*jsonlRowIterator, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &jsonlRowIterator{
		file: file,
		dec:  json.NewDecoder(file),
	}, nil
}

func (it *jsonlRowIterator) Next() (EventRow, bool, error) {
	if it == nil || it.dec == nil {
		return EventRow{}, false, nil
	}
	var row EventRow
	if err := it.dec.Decode(&row); err != nil {
		if err == io.EOF {
			return EventRow{}, false, nil
		}
		return EventRow{}, false, err
	}
	return row, true, nil
}

func (it *jsonlRowIterator) Close() error {
	if it == nil || it.closed || it.file == nil {
		return nil
	}
	it.closed = true
	return it.file.Close()
}

func readAllEventRows(it RowIterator) ([]EventRow, error) {
	if it == nil {
		return nil, nil
	}
	rows := make([]EventRow, 0, 16)
	for {
		row, ok, err := it.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		rows = append(rows, row)
	}
	return rows, nil
}
