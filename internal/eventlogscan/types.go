package eventlogscan

const (
	// DefaultSortBy is the default sort field.
	DefaultSortBy = "timestamp"
	// DefaultSortOrder is the default sort direction.
	DefaultSortOrder = "desc"
)

// ProgressFunc reports collection/query progress.
type ProgressFunc func(done, total int, stage string)

type rawEventSink func(rawEvent) error

// RowSink receives normalized rows during streaming export.
type RowSink func(EventRow) error

// RowIterator streams normalized rows from a disk-backed source.
type RowIterator interface {
	Next() (EventRow, bool, error)
	Close() error
}

// RowWriter consumes normalized rows and persists them somewhere.
type RowWriter interface {
	Write(EventRow) error
	Close() error
}

// ChunkMeta describes a persisted sorted chunk.
type ChunkMeta struct {
	Path string
	Rows int
}

// QueryParams describes eventlog query inputs.
type QueryParams struct {
	StartTime int64
	EndTime   int64
	MaxLogs   int

	Sources      []string
	EventTypes   []string
	EventLevels  []string
	EventCodes   []string
	EventActions []string
	Results      []string

	ProcessName *string
	ProcessID   *int
	Username    *string
	TargetPath  *string

	LocalIP    *string
	LocalPort  *int
	RemoteIP   *string
	RemotePort *int
	Protocols  []string

	Keyword *string

	SortBy    string
	SortOrder string

	IncludeRawContent bool
	Progress          ProgressFunc
}

// ScanResult is the compatibility envelope for materialized eventlog results.
type ScanResult struct {
	Total int        `json:"total"`
	Rows  []EventRow `json:"rows"`
}

// ExportResult is a disk-backed ordered export of eventlog rows.
type ExportResult struct {
	Total     int
	RowsPath  string
	SpoolDir  string
	SortBy    string
	SortOrder string
	MaxLogs   int
	closeFn   func() error
}

// Close removes any temporary export artifacts.
func (r *ExportResult) Close() error {
	if r == nil || r.closeFn == nil {
		return nil
	}
	closeFn := r.closeFn
	r.closeFn = nil
	return closeFn()
}

// EventRow is the normalized eventlog row schema.
type EventRow struct {
	LogID     string `json:"logId"`
	Timestamp int64  `json:"timestamp"`

	OSType      string `json:"osType"`
	Source      string `json:"source"`
	EventType   string `json:"eventType"`
	EventLevel  string `json:"eventLevel"`
	EventCode   string `json:"eventCode"`
	EventAction string `json:"eventAction"`
	Result      string `json:"result"`

	Hostname       *string  `json:"hostname"`
	DisplayIP      *string  `json:"displayIp"`
	InternalIPList []string `json:"internalIpList"`
	ExternalIPList []string `json:"externalIpList"`

	Username          *string `json:"username"`
	ProcessName       *string `json:"processName"`
	ProcessID         *int    `json:"processId"`
	ParentProcessName *string `json:"parentProcessName"`
	ParentProcessID   *int    `json:"parentProcessId"`

	TargetPath *string `json:"targetPath"`

	LocalIP    *string `json:"localIp"`
	LocalPort  *int    `json:"localPort"`
	RemoteIP   *string `json:"remoteIp"`
	RemotePort *int    `json:"remotePort"`
	Protocol   *string `json:"protocol"`

	Message    *string `json:"message"`
	RawContent any     `json:"rawContent,omitempty"`
}

type rawEvent struct {
	NativeID  string
	Timestamp int64

	OSType      string
	Source      string
	EventType   string
	EventLevel  string
	EventCode   string
	EventAction string
	Result      string

	Hostname       string
	DisplayIP      string
	InternalIPs    []string
	ExternalIPs    []string
	Username       string
	ProcessName    string
	ProcessID      *int
	ParentProcName string
	ParentProcID   *int
	TargetPath     string
	LocalIP        string
	LocalPort      *int
	RemoteIP       string
	RemotePort     *int
	Protocol       string
	Message        string
	RawContent     any
}
