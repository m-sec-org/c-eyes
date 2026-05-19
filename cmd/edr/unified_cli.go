package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"edrsystem/internal/accountscan"
	"edrsystem/internal/benchmark"
	"edrsystem/internal/databasescan"
	"edrsystem/internal/environmentscan"
	"edrsystem/internal/eventlogscan"
	"edrsystem/internal/filescan"
	"edrsystem/internal/jarpackagescan"
	"edrsystem/internal/kernelscan"
	"edrsystem/internal/netscan"
	"edrsystem/internal/portscan"
	"edrsystem/internal/processscan"
	"edrsystem/internal/riskanalysis"
	"edrsystem/internal/sbom"
	"edrsystem/internal/scheduledtaskscan"
	"edrsystem/internal/softwarescan"
	"edrsystem/internal/startupscan"
	"edrsystem/internal/usergroupscan"
	"edrsystem/internal/webapplicationscan"
	"edrsystem/internal/webframescan"
	"edrsystem/internal/websitescan"

	"github.com/xuri/excelize/v2"
)

var hostscanModuleOrder = []string{
	"account",
	"usergroup",
	"process",
	"port",
	"startup",
	"scheduledtask",
	"environment",
	"kernel",
	"database",
	"application",
}

var hostscanRiskModuleOrder = []string{
	"process",
	"startup",
	"scheduledtask",
	"kernel",
	"database",
	"application",
}

var filescanWebModuleOrder = []string{
	"site",
	"framework",
	"jarpackage",
	"software",
}

const (
	autoExcelOutputSentinel      = "__AUTO_RESULT_XLSX__"
	autoSBOMOutputSentinel       = "__AUTO_RESULT_JSON__"
	defaultEventlogWindow        = 24 * time.Hour
	reachableDefaultScanModesCSV = "ICP,T"
	reachableDefaultMaxTargets   = 2048
	xlsxMaxRows                  = 1048576
	xlsxMaxColumns               = 16384
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

var autoResultIndexPattern = regexp.MustCompile(`^result([0-9]+)\.xlsx$`)
var autoJSONResultIndexPattern = regexp.MustCompile(`^result([0-9]+)\.json$`)
var eventlogLastPattern = regexp.MustCompile(`^(\d+)\s*([dDwW])$`)
var eventlogScanFunc = eventlogscan.Scan

type globalCLIOptions struct {
	ShowHelp    bool
	RiskEnabled bool
	RiskMode    string
	OutputPath  string
}

type scanAggregateResult struct {
	Total int              `json:"total"`
	Rows  []map[string]any `json:"rows"`
}

type hostCommonFilters struct {
	Hostname *string
	IP       *string
}

type filescanWebCommonFilters struct {
	Groups   []int64
	Hostname *string
	IP       *string
}

type hostscanParseResult struct {
	ShowHelp        bool
	Modules         []string
	ModuleArgs      []string
	MultiMode       bool
	Filters         hostCommonFilters
	RiskArgs        []string
	CustomSpecified bool
}

type filescanParseResult struct {
	ShowHelp        bool
	IsLocalMode     bool
	LocalMode       filescan.ScanMode
	LocalPath       string
	LocalSmart      bool
	LocalMaxTarget  int
	WebModules      []string
	ModuleArgs      []string
	WebFilters      filescanWebCommonFilters
	RiskArgs        []string
	CustomSpecified bool
}

type eventlogParseResult struct {
	ShowHelp bool
	Params   eventlogscan.QueryParams
	RiskArgs []string
}

type netscanParseResult struct {
	ShowHelp                          bool
	Params                            netscan.Params
	RiskArgs                          []string
	ReachableDefaultScanModeApplied   bool
	ReachableDefaultMaxTargetsApplied bool
}

type sbomParseResult struct {
	ShowHelp    bool
	Path        string
	ImageTarget string
	TargetType  string
	Format      string
	RiskArgs    []string
}

type benchmarkParseResult struct {
	ShowHelp      bool
	Template      benchmark.Template
	BaselineLevel benchmark.BaselineLevel
	RiskArgs      []string
}

func runUnifiedCLI(rawArgs []string) int {
	opts, remaining, err := parseGlobalCLIOptions(rawArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if len(remaining) == 0 {
		if opts.ShowHelp && opts.RiskEnabled {
			return runStandaloneRiskCLI(nil, opts)
		}
		if opts.ShowHelp {
			usage()
			return 0
		}
		if opts.RiskEnabled {
			return runStandaloneRiskCLI(nil, opts)
		}
		usage()
		return 2
	}

	switch remaining[0] {
	case "hostscan":
		return runHostscanCLI(remaining[1:], opts)
	case "filescan":
		return runFilescanCLI(remaining[1:], opts)
	case "benchmark":
		return runBenchmarkCLI(remaining[1:], opts)
	case "sbom":
		return runSBOMCLI(remaining[1:], opts)
	case "eventlog":
		return runEventlogCLI(remaining[1:], opts)
	case "netscan":
		return runNetscanCLI(remaining[1:], opts)
	default:
		if opts.RiskEnabled {
			return runStandaloneRiskCLI(remaining, opts)
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", remaining[0])
		usage()
		return 2
	}
}

func parseGlobalCLIOptions(args []string) (globalCLIOptions, []string, error) {
	opts := globalCLIOptions{
		OutputPath: autoExcelOutputSentinel,
	}
	remaining := make([]string, 0, len(args))

	i := 0
	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			opts.ShowHelp = true
			i++
		case arg == "-r" || arg == "--riskanalyze":
			opts.RiskEnabled = true
			i++
		case arg == "--risk-mode" || arg == "-risk-mode":
			if i+1 >= len(args) {
				return opts, nil, fmt.Errorf("invalid argument: --risk-mode requires a value")
			}
			opts.RiskMode = strings.TrimSpace(args[i+1])
			i += 2
		case strings.HasPrefix(arg, "--risk-mode=") || strings.HasPrefix(arg, "-risk-mode="):
			parts := strings.SplitN(arg, "=", 2)
			opts.RiskMode = strings.TrimSpace(parts[1])
			i++
		case arg == "-o" || arg == "--output":
			if i+1 >= len(args) {
				return opts, nil, fmt.Errorf("invalid argument: -o/--output requires a path")
			}
			next := strings.TrimSpace(args[i+1])
			if next == "" || strings.HasPrefix(next, "-") {
				return opts, nil, fmt.Errorf("invalid argument: -o/--output requires a path")
			}
			opts.OutputPath = next
			i += 2
		case strings.HasPrefix(arg, "-o=") || strings.HasPrefix(arg, "--output="):
			parts := strings.SplitN(arg, "=", 2)
			if value := strings.TrimSpace(parts[1]); value == "" {
				return opts, nil, fmt.Errorf("invalid argument: -o/--output requires a path")
			}
			opts.OutputPath = strings.TrimSpace(parts[1])
			i++
		default:
			remaining = append(remaining, arg)
			i++
		}
	}

	if opts.RiskMode != "" {
		if !opts.RiskEnabled {
			return opts, nil, fmt.Errorf("invalid argument: --risk-mode can only be used when -r/--riskanalyze is enabled")
		}
		if _, err := resolveRiskMode(opts.RiskMode); err != nil {
			return opts, nil, fmt.Errorf("invalid argument: --risk-mode: %s", opts.RiskMode)
		}
	}

	if opts.OutputPath != "" && opts.OutputPath != autoExcelOutputSentinel {
		if _, err := detectOutputFormat(opts.OutputPath); err != nil {
			return opts, nil, err
		}
	}

	return opts, remaining, nil
}

func runHostscanCLI(args []string, global globalCLIOptions) int {
	if global.ShowHelp && len(args) == 0 {
		hostscanUsage()
		return 0
	}

	parseArgs := args
	if global.ShowHelp {
		// Global -h is consumed before subcommand parsing; append local help marker
		// so hostscan parser can bypass strict required-arg checks.
		parseArgs = append(append([]string{}, args...), "-h")
	}
	parsed, err := parseHostscanArgs(parseArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	parsed, err = applyHostscanRiskModuleSelection(parsed, global.RiskEnabled)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := rejectRiskOptionsWithoutEnable(parsed.RiskArgs, global); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if global.ShowHelp || parsed.ShowHelp {
		if parsed.CustomSpecified {
			printHostscanCustomOptionsHelp(parsed.Modules)
			return 0
		}
		hostscanUsage()
		return 0
	}

	if err := rejectLegacyOutputFlags(parsed.ModuleArgs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	var riskOpts riskOptions

	if global.RiskEnabled {
		riskOpts, err = parseChainedRiskOptions(
			parsed.RiskArgs,
			global.RiskMode,
			true,
			hostscanHasModule(parsed.Modules, "process"),
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}

	progress := newTerminalProgress(os.Stderr, "hostscan")
	defer progress.Done()

	agg, records, err := executeHostscan(parsed, riskOpts.ProcessMemory, riskOpts.MemoryMaxBytes, progress)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	progress.Done()

	if global.RiskEnabled {
		riskProgress := newRiskTerminalProgress(os.Stderr)
		defer riskProgress.Done()

		results, err := analyzeRiskResults(riskOpts, records, riskProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		payload := riskanalysis.SummaryResult{
			Summary: riskanalysis.BuildSummary(results),
			Results: results,
		}
		if err := emitOutput(payload, global.OutputPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}

	if err := emitOutput(agg, global.OutputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runFilescanCLI(args []string, global globalCLIOptions) int {
	if global.ShowHelp && len(args) == 0 {
		filescanUsage()
		return 0
	}

	parseArgs := args
	if global.ShowHelp {
		// Global -h is consumed before subcommand parsing; append local help marker so
		// filescan parser can bypass strict local-mode required-arg checks.
		parseArgs = append(append([]string{}, args...), "-h")
	}
	parsed, err := parseFilescanArgs(parseArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := rejectRiskOptionsWithoutEnable(parsed.RiskArgs, global); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if global.ShowHelp || parsed.ShowHelp {
		if parsed.CustomSpecified && !parsed.IsLocalMode {
			printFilescanCustomOptionsHelp(parsed.WebModules)
			return 0
		}
		filescanUsage()
		return 0
	}

	if err := rejectLegacyOutputFlags(parsed.ModuleArgs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	var (
		agg     scanAggregateResult
		records []riskanalysis.ScanRecord
	)

	progress := newTerminalProgressWithBottomPin(os.Stderr, "filescan", shouldPinFilescanProgress(os.Stderr))
	defer progress.Done()

	if parsed.IsLocalMode {
		rows, riskRecords, err := executeFilescanLocalMode(parsed, progress)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		agg = scanAggregateResult{Total: len(rows), Rows: rows}
		records = riskRecords
	} else {
		result, riskRecords, err := executeFilescanWebMode(parsed, progress)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		agg = result
		records = riskRecords
	}
	progress.Done()
	if agg.Total == 0 {
		if parsed.IsLocalMode {
			scope := "full"
			if parsed.LocalMode != "" {
				scope = string(parsed.LocalMode)
			}
			if parsed.LocalMode == filescan.ScanModePath && strings.TrimSpace(parsed.LocalPath) != "" {
				fmt.Fprintf(os.Stderr, "filescan: no scan targets found in %s path: %s\n", scope, parsed.LocalPath)
			} else {
				fmt.Fprintf(os.Stderr, "filescan: no scan targets found in %s scope\n", scope)
			}
		} else {
			fmt.Fprintln(os.Stderr, "filescan: no scan targets found for selected module/filter set")
		}
	}

	if global.RiskEnabled {
		if len(records) == 0 {
			fmt.Fprintln(os.Stderr, "risk analyze: no scan records available, output will be empty")
		}
		riskOpts, err := parseChainedRiskOptions(parsed.RiskArgs, global.RiskMode, false, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}

		riskProgress := newRiskTerminalProgress(os.Stderr)
		defer riskProgress.Done()

		results, err := analyzeRiskResults(riskOpts, records, riskProgress)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		payload := riskanalysis.SummaryResult{
			Summary: riskanalysis.BuildSummary(results),
			Results: results,
		}
		if err := emitOutput(payload, global.OutputPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}

	if err := emitOutput(agg, global.OutputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runBenchmarkCLI(args []string, global globalCLIOptions) int {
	if global.ShowHelp && len(args) == 0 {
		benchmarkUsage()
		return 0
	}
	if global.RiskEnabled {
		fmt.Fprintln(os.Stderr, "invalid argument: benchmark is collection-only and does not support -r/--riskanalyze")
		return 2
	}

	_, riskArgs, splitErr := splitRiskArgs(args)
	if splitErr != nil {
		fmt.Fprintln(os.Stderr, splitErr)
		return 2
	}
	if len(riskArgs) > 0 {
		name, _ := splitFlagToken(strings.TrimSpace(riskArgs[0]))
		if !strings.HasPrefix(name, "-") {
			name = strings.TrimSpace(riskArgs[0])
		}
		fmt.Fprintf(os.Stderr, "invalid argument: benchmark does not support risk-analysis option: %s\n", name)
		return 2
	}

	parseArgs := args
	if global.ShowHelp {
		// Global -h is consumed before subcommand parsing; append local help marker
		// so benchmark parser can short-circuit strict argument validation.
		parseArgs = append(append([]string{}, args...), "-h")
	}
	parsed, err := parseBenchmarkArgs(parseArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if global.ShowHelp || parsed.ShowHelp {
		benchmarkUsage()
		return 0
	}

	progress := newTerminalProgress(os.Stderr, "benchmark")
	defer progress.Done()

	result, err := benchmark.Scan(context.Background(), benchmark.ScanOptions{
		Template:      parsed.Template,
		BaselineLevel: parsed.BaselineLevel,
		Progress:      scopedProgressUpdate(progress, "scan"),
	})
	if err != nil {
		progress.PrintLine(err.Error())
		return 1
	}

	printBenchmarkSummary(progress, result)

	// Clear the in-place progress row before emitOutput writes generated file hints.
	progress.PrintLine("")
	if err := emitOutput(result, global.OutputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runSBOMCLI(args []string, global globalCLIOptions) int {
	if global.ShowHelp && len(args) == 0 {
		sbomUsage()
		return 0
	}

	if global.RiskEnabled {
		fmt.Fprintln(os.Stderr, "invalid argument: sbom is collection-only and does not support -r/--riskanalyze")
		return 2
	}

	_, riskArgs, splitErr := splitRiskArgs(args)
	if splitErr != nil {
		fmt.Fprintln(os.Stderr, splitErr)
		return 2
	}
	if len(riskArgs) > 0 {
		name, _ := splitFlagToken(strings.TrimSpace(riskArgs[0]))
		if !strings.HasPrefix(name, "-") {
			name = strings.TrimSpace(riskArgs[0])
		}
		fmt.Fprintf(os.Stderr, "invalid argument: sbom does not support risk-analysis option: %s\n", name)
		return 2
	}

	parseArgs := args
	if global.ShowHelp {
		// Global -h is consumed before subcommand parsing; append local help marker
		// so sbom parser can short-circuit strict argument validation.
		parseArgs = append(append([]string{}, args...), "-h")
	}
	parsed, err := parseSBOMArgs(parseArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if global.ShowHelp || parsed.ShowHelp {
		sbomUsage()
		return 0
	}

	outputPath := global.OutputPath
	if strings.TrimSpace(outputPath) == autoExcelOutputSentinel {
		outputPath = autoSBOMOutputSentinel
	} else if strings.TrimSpace(outputPath) != "" {
		format, err := detectOutputFormat(outputPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if format != "json" {
			fmt.Fprintln(os.Stderr, "invalid argument: sbom output only supports .json")
			return 2
		}
	}

	result, err := sbom.Scan(context.Background(), sbom.ScanOptions{
		Path:        parsed.Path,
		ImageTarget: parsed.ImageTarget,
		TargetType:  parsed.TargetType,
		Format:      parsed.Format,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if err := emitOutput(result, outputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runEventlogCLI(args []string, global globalCLIOptions) int {
	if global.ShowHelp && len(args) == 0 {
		eventlogUsage()
		return 0
	}

	if global.RiskEnabled {
		fmt.Fprintln(os.Stderr, "invalid argument: eventlog is collection-only and does not support -r/--riskanalyze")
		return 2
	}

	_, riskArgs, splitErr := splitRiskArgs(args)
	if splitErr != nil {
		fmt.Fprintln(os.Stderr, splitErr)
		return 2
	}
	if len(riskArgs) > 0 {
		name, _ := splitFlagToken(strings.TrimSpace(riskArgs[0]))
		if !strings.HasPrefix(name, "-") {
			name = strings.TrimSpace(riskArgs[0])
		}
		fmt.Fprintf(os.Stderr, "invalid argument: eventlog does not support risk-analysis option: %s\n", name)
		return 2
	}

	parseArgs := args
	if global.ShowHelp {
		// Global -h is consumed before subcommand parsing; append local help marker
		// so eventlog parser can short-circuit strict argument validation.
		parseArgs = append(append([]string{}, args...), "-h")
	}
	parsed, err := parseEventlogArgs(parseArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	if global.ShowHelp || parsed.ShowHelp {
		eventlogUsage()
		return 0
	}

	progress := newTerminalProgress(os.Stderr, "eventlog")
	defer progress.Done()

	parsed.Params.Progress = scopedProgressUpdate(progress, "")

	result, err := eventlogScanFunc(context.Background(), parsed.Params)
	if err != nil {
		progress.Done()
		fmt.Fprintln(os.Stderr, err)
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(err.Error())), "invalid argument:") {
			return 2
		}
		return 1
	}
	progress.Done()

	if err := emitOutput(result, global.OutputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runNetscanCLI(args []string, global globalCLIOptions) int {
	if global.ShowHelp && len(args) == 0 {
		netscanUsage()
		return 0
	}

	if global.RiskEnabled {
		fmt.Fprintln(os.Stderr, "invalid argument: netscan is collection-only and does not support -r/--riskanalyze")
		return 2
	}

	_, riskArgs, splitErr := splitRiskArgs(args)
	if splitErr != nil {
		fmt.Fprintln(os.Stderr, splitErr)
		return 2
	}
	if len(riskArgs) > 0 {
		name, _ := splitFlagToken(strings.TrimSpace(riskArgs[0]))
		if !strings.HasPrefix(name, "-") {
			name = strings.TrimSpace(riskArgs[0])
		}
		fmt.Fprintf(os.Stderr, "invalid argument: netscan does not support risk-analysis option: %s\n", name)
		return 2
	}

	parseArgs := args
	if global.ShowHelp {
		// Global -h is consumed before subcommand parsing; append local help marker
		// so netscan parser can short-circuit strict argument validation.
		parseArgs = append(append([]string{}, args...), "-h")
	}
	parsed, err := parseNetscanArgs(parseArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if global.ShowHelp || parsed.ShowHelp {
		netscanUsage()
		return 0
	}

	progress := newTerminalProgress(os.Stderr, "netscan")
	defer progress.Done()
	parsed.Params.Progress = scopedProgressUpdate(progress, "discover")
	if parsed.Params.ReachableSegments {
		progress.PrintLine("[INFO] netscan: reachable-segment discovery is enabled and remains bounded by maxTargets/pps/workers")
		if parsed.ReachableDefaultScanModeApplied {
			progress.PrintLine(fmt.Sprintf("[INFO] netscan: reachableSegments default applied: -scanMode=%s (override with -scanMode)", reachableDefaultScanModesCSV))
		}
		if parsed.ReachableDefaultMaxTargetsApplied {
			progress.PrintLine(fmt.Sprintf("[INFO] netscan: reachableSegments default applied: -maxTargets=%d (override with -maxTargets)", reachableDefaultMaxTargets))
		}
	}

	if strings.TrimSpace(parsed.Params.Target) == "" && strings.TrimSpace(parsed.Params.TargetFile) == "" {
		progress.PrintLine("[INFO] netscan: no target specified; defaulting to primary-interface C-segment discovery")
		progress.PrintLine("[INFO] netscan: use -target/-targetFile to narrow scope and reduce scan time")
	}
	// Start the dynamic progress row after initial info lines to avoid early cursor jitter.
	progress.Update(0, 1, "discover")

	result, err := netscan.Scan(context.Background(), parsed.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(err.Error())), "invalid argument:") {
			return 2
		}
		return 1
	}

	if len(result.Warnings) > 0 {
		progress.PrintLine(fmt.Sprintf("[WARN] netscan generated %d warning(s); check output warnings/metrics for details", len(result.Warnings)))
	}
	// Flush the in-place progress row before regular output messages (for example
	// auto-generated file hints) to avoid mixed cursor artifacts.
	progress.Done()

	if err := emitOutput(result, global.OutputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func parseSBOMArgs(args []string) (sbomParseResult, error) {
	var result sbomParseResult

	scanArgs, riskArgs, err := splitRiskArgs(args)
	if err != nil {
		return result, err
	}
	result.RiskArgs = riskArgs
	if err := rejectLegacyOutputFlags(scanArgs); err != nil {
		return result, err
	}
	for _, arg := range scanArgs {
		if arg == "-h" || arg == "--help" {
			result.ShowHelp = true
			return result, nil
		}
	}

	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	scanPath := ""
	fs.StringVar(&scanPath, "p", "", "SBOM scan path")
	fs.StringVar(&scanPath, "path", "", "SBOM scan path")
	imageTarget := ""
	fs.StringVar(&imageTarget, "image-target", "", "SBOM scan image target")
	legacyImage := ""
	fs.StringVar(&legacyImage, "image", "", "SBOM scan image reference")
	legacyImageArchive := ""
	fs.StringVar(&legacyImageArchive, "image-archive", "", "SBOM scan image archive path")
	legacyOCILayout := ""
	fs.StringVar(&legacyOCILayout, "oci-layout", "", "SBOM scan OCI layout path")
	targetType := ""
	fs.StringVar(&targetType, "target-type", "", "SBOM image target type: auto|image|archive|oci-layout")

	format := sbom.FormatXSPDXJSON
	fs.StringVar(&format, "format", sbom.FormatXSPDXJSON, "SBOM output format: xspdx-json|spdx-json")

	if err := fs.Parse(scanArgs); err != nil {
		return result, fmt.Errorf("invalid argument: %v", err)
	}
	if len(fs.Args()) > 0 {
		return result, fmt.Errorf("invalid argument: unknown argument: %s", fs.Args()[0])
	}

	normalizedFormat, err := sbom.NormalizeFormat(format)
	if err != nil {
		return result, err
	}
	result.Path = strings.TrimSpace(scanPath)
	result.ImageTarget = strings.TrimSpace(imageTarget)
	legacyImage = strings.TrimSpace(legacyImage)
	legacyImageArchive = strings.TrimSpace(legacyImageArchive)
	legacyOCILayout = strings.TrimSpace(legacyOCILayout)
	normalizedTargetType, err := sbom.NormalizeTargetType(targetType)
	if err != nil {
		return result, err
	}
	result.TargetType = normalizedTargetType

	imageSelectors := 0
	if result.ImageTarget != "" {
		imageSelectors++
	}
	if legacyImage != "" {
		imageSelectors++
	}
	if legacyImageArchive != "" {
		imageSelectors++
	}
	if legacyOCILayout != "" {
		imageSelectors++
	}
	if imageSelectors > 1 {
		return result, fmt.Errorf("invalid argument: sbom image target options are mutually exclusive")
	}
	switch {
	case result.ImageTarget != "":
		// already normalized through the unified option
	case legacyImage != "":
		result.ImageTarget = legacyImage
		if result.TargetType == sbom.TargetTypeAuto {
			result.TargetType = sbom.TargetTypeImage
		} else if result.TargetType != sbom.TargetTypeImage {
			return result, fmt.Errorf("invalid argument: --target-type conflicts with --image")
		}
	case legacyImageArchive != "":
		result.ImageTarget = legacyImageArchive
		if result.TargetType == sbom.TargetTypeAuto {
			result.TargetType = sbom.TargetTypeArchive
		} else if result.TargetType != sbom.TargetTypeArchive {
			return result, fmt.Errorf("invalid argument: --target-type conflicts with --image-archive")
		}
	case legacyOCILayout != "":
		result.ImageTarget = legacyOCILayout
		if result.TargetType == sbom.TargetTypeAuto {
			result.TargetType = sbom.TargetTypeOCILayout
		} else if result.TargetType != sbom.TargetTypeOCILayout {
			return result, fmt.Errorf("invalid argument: --target-type conflicts with --oci-layout")
		}
	}

	if result.Path != "" && result.ImageTarget != "" {
		return result, fmt.Errorf("invalid argument: sbom target options are mutually exclusive")
	}
	if result.Path != "" && result.TargetType != sbom.TargetTypeAuto {
		return result, fmt.Errorf("invalid argument: --target-type cannot be used with -p/--path")
	}
	if result.Path == "" && result.ImageTarget == "" {
		if result.TargetType != sbom.TargetTypeAuto {
			return result, fmt.Errorf("invalid argument: --target-type requires --image-target")
		}
		return result, fmt.Errorf("invalid argument: sbom requires exactly one target: -p/--path or --image-target")
	}
	result.Format = normalizedFormat
	return result, nil
}

func parseBenchmarkArgs(args []string) (benchmarkParseResult, error) {
	var result benchmarkParseResult

	scanArgs, riskArgs, err := splitRiskArgs(args)
	if err != nil {
		return result, err
	}
	result.RiskArgs = riskArgs
	if err := rejectLegacyOutputFlags(scanArgs); err != nil {
		return result, err
	}

	for _, arg := range scanArgs {
		if arg == "-h" || arg == "--help" {
			result.ShowHelp = true
			return result, nil
		}
	}

	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	templateVal := string(benchmark.TemplateAuto)
	fs.StringVar(&templateVal, "template", string(benchmark.TemplateAuto), "benchmark template: auto|windows|linux|euleros|kylin")
	baselineLevelVal := string(benchmark.BaselineLevel1)
	fs.StringVar(&baselineLevelVal, "baseline-level", string(benchmark.BaselineLevel1), "benchmark baseline level: 1|2|3|4")

	if err := fs.Parse(scanArgs); err != nil {
		return result, fmt.Errorf("invalid argument: %v", err)
	}
	if len(fs.Args()) > 0 {
		return result, fmt.Errorf("invalid argument: unknown argument: %s", fs.Args()[0])
	}

	normalized, err := benchmark.NormalizeTemplate(templateVal)
	if err != nil {
		return result, err
	}
	level, err := benchmark.NormalizeBaselineLevel(baselineLevelVal)
	if err != nil {
		return result, err
	}
	result.Template = normalized
	result.BaselineLevel = level
	return result, nil
}

func parseEventlogArgs(args []string) (eventlogParseResult, error) {
	var result eventlogParseResult

	scanArgs, riskArgs, err := splitRiskArgs(args)
	if err != nil {
		return result, err
	}
	result.RiskArgs = riskArgs
	if err := rejectLegacyOutputFlags(scanArgs); err != nil {
		return result, err
	}

	for _, arg := range scanArgs {
		if arg == "-h" || arg == "--help" {
			result.ShowHelp = true
			return result, nil
		}
	}

	fs := flag.NewFlagSet("eventlog", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		startTimeRaw string
		endTimeRaw   string
		lastRaw      string
		maxLogs      optionalInt
		sources      stringSliceFlag
		eventTypes   stringSliceFlag
		eventLevels  stringSliceFlag
		eventCodes   stringSliceFlag
		eventActions stringSliceFlag
		results      stringSliceFlag
		protocols    stringSliceFlag
		processID    optionalInt
		localPort    optionalInt
		remotePort   optionalInt

		processName string
		username    string
		targetPath  string
		localIP     string
		remoteIP    string
		keyword     string
		sortBy      string
		sortOrder   string

		includeRawContent bool
	)

	fs.StringVar(&startTimeRaw, "startTime", "", "query start time (unix ms / RFC3339 / YYYY-MM-DD[ HH:MM:SS])")
	fs.StringVar(&endTimeRaw, "endTime", "", "query end time (default: now; unix ms / RFC3339 / YYYY-MM-DD[ HH:MM:SS])")
	fs.StringVar(&lastRaw, "last", "", "relative time window (default: 24h; e.g. 30m, 24h, 7d)")
	fs.Var(&maxLogs, "maxLogs", "maximum returned log rows (0 means unlimited)")
	fs.Var(&sources, "sources", "source filters")
	fs.Var(&eventTypes, "eventTypes", "event type filters")
	fs.Var(&eventLevels, "eventLevels", "event level filters")
	fs.Var(&eventCodes, "eventCodes", "event code filters")
	fs.Var(&eventActions, "eventActions", "event action filters")
	fs.Var(&results, "result", "result filters")
	fs.StringVar(&processName, "processName", "", "process name/path filter")
	fs.Var(&processID, "processId", "process id filter")
	fs.StringVar(&username, "username", "", "username filter")
	fs.StringVar(&targetPath, "targetPath", "", "target path filter")
	fs.StringVar(&localIP, "localIp", "", "local ip filter")
	fs.Var(&localPort, "localPort", "local port filter")
	fs.StringVar(&remoteIP, "remoteIp", "", "remote ip filter")
	fs.Var(&remotePort, "remotePort", "remote port filter")
	fs.Var(&protocols, "protocols", "protocol filters")
	fs.StringVar(&keyword, "keyword", "", "keyword filter")
	fs.StringVar(&sortBy, "sortBy", "", "sort field")
	fs.StringVar(&sortOrder, "sortOrder", "", "sort order")
	fs.BoolVar(&includeRawContent, "includeRawContent", false, "include raw log payload")

	if err := fs.Parse(scanArgs); err != nil {
		return result, fmt.Errorf("invalid argument: %v", err)
	}
	if len(fs.Args()) > 0 {
		return result, fmt.Errorf("invalid argument: unknown argument: %s", fs.Args()[0])
	}

	startTime, endTime, err := resolveEventlogTimeRange(startTimeRaw, endTimeRaw, lastRaw, time.Now())
	if err != nil {
		return result, err
	}

	params := eventlogscan.QueryParams{
		StartTime:         startTime,
		EndTime:           endTime,
		MaxLogs:           0,
		Sources:           append([]string{}, sources.values...),
		EventTypes:        append([]string{}, eventTypes.values...),
		EventLevels:       append([]string{}, eventLevels.values...),
		EventCodes:        append([]string{}, eventCodes.values...),
		EventActions:      append([]string{}, eventActions.values...),
		Results:           append([]string{}, results.values...),
		Protocols:         append([]string{}, protocols.values...),
		SortBy:            strings.TrimSpace(sortBy),
		SortOrder:         strings.TrimSpace(sortOrder),
		IncludeRawContent: includeRawContent,
	}

	if maxLogs.set {
		if maxLogs.value < 0 {
			return result, fmt.Errorf("invalid argument: maxLogs must be >= 0")
		}
		params.MaxLogs = maxLogs.value
	}

	if trimmed := strings.TrimSpace(processName); trimmed != "" {
		params.ProcessName = &trimmed
	}
	if processID.set {
		if processID.value <= 0 {
			return result, fmt.Errorf("invalid argument: processId must be a positive integer")
		}
		value := processID.value
		params.ProcessID = &value
	}
	if trimmed := strings.TrimSpace(username); trimmed != "" {
		params.Username = &trimmed
	}
	if trimmed := strings.TrimSpace(targetPath); trimmed != "" {
		params.TargetPath = &trimmed
	}
	if trimmed := strings.TrimSpace(localIP); trimmed != "" {
		params.LocalIP = &trimmed
	}
	if localPort.set {
		if localPort.value < 0 || localPort.value > 65535 {
			return result, fmt.Errorf("invalid argument: localPort must be between 0 and 65535")
		}
		value := localPort.value
		params.LocalPort = &value
	}
	if trimmed := strings.TrimSpace(remoteIP); trimmed != "" {
		params.RemoteIP = &trimmed
	}
	if remotePort.set {
		if remotePort.value < 0 || remotePort.value > 65535 {
			return result, fmt.Errorf("invalid argument: remotePort must be between 0 and 65535")
		}
		value := remotePort.value
		params.RemotePort = &value
	}
	if trimmed := strings.TrimSpace(keyword); trimmed != "" {
		params.Keyword = &trimmed
	}

	result.Params = params
	return result, nil
}

func parseNetscanArgs(args []string) (netscanParseResult, error) {
	var result netscanParseResult

	scanArgs, riskArgs, err := splitRiskArgs(args)
	if err != nil {
		return result, err
	}
	result.RiskArgs = riskArgs
	if err := rejectLegacyOutputFlags(scanArgs); err != nil {
		return result, err
	}
	for _, arg := range scanArgs {
		if arg == "-h" || arg == "--help" {
			result.ShowHelp = true
			return result, nil
		}
	}

	fs := flag.NewFlagSet("netscan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		target            string
		targetFile        string
		exclude           string
		scanModeRaw       string
		tcpPortsRaw       string
		udpPortsRaw       string
		maxTargets        int
		pps               int
		timeoutMs         int
		jitterMs          int
		workers           int
		managedSource     string
		assetStatus       string
		keyword           string
		sortBy            string
		sortOrder         string
		ipv6Enabled       bool
		reachableSegments bool
	)

	fs.StringVar(&target, "target", "", "scan target expression")
	fs.StringVar(&targetFile, "targetFile", "", "path of target list file")
	fs.StringVar(&exclude, "exclude", "", "exclude target expression")
	fs.StringVar(&scanModeRaw, "scanMode", "", "scan mode list")
	fs.BoolVar(&ipv6Enabled, "ipv6", false, "enable IPv6 probing")
	fs.BoolVar(&reachableSegments, "reachableSegments", false, "enable routed reachable-segment discovery")
	fs.StringVar(&tcpPortsRaw, "tcpPorts", "", "tcp port list for T/TS")
	fs.StringVar(&udpPortsRaw, "udpPorts", "", "udp port list for U")
	fs.IntVar(&maxTargets, "maxTargets", 0, "max resolved targets")
	fs.IntVar(&pps, "pps", 0, "packets per second upper bound")
	fs.IntVar(&timeoutMs, "timeoutMs", 0, "single target timeout in ms")
	fs.IntVar(&jitterMs, "jitterMs", 0, "probe jitter in ms")
	fs.IntVar(&workers, "workers", 0, "worker upper bound")
	fs.StringVar(&managedSource, "managedSource", "", "managed source asset file (json/csv/xlsx)")

	fs.StringVar(&assetStatus, "assetStatus", "", "asset status filter")
	fs.StringVar(&keyword, "keyword", "", "keyword filter")
	fs.StringVar(&sortBy, "sortBy", "", "sort field")
	fs.StringVar(&sortOrder, "sortOrder", "", "sort order")

	if err := fs.Parse(scanArgs); err != nil {
		return result, fmt.Errorf("invalid argument: %v", err)
	}
	if len(fs.Args()) > 0 {
		return result, fmt.Errorf("invalid argument: unknown argument: %s", fs.Args()[0])
	}
	seenFlags := map[string]struct{}{}
	fs.Visit(func(f *flag.Flag) {
		seenFlags[f.Name] = struct{}{}
	})

	if _, ok := seenFlags["scanMode"]; !ok {
		if reachableSegments {
			scanModeRaw = reachableDefaultScanModesCSV
			result.ReachableDefaultScanModeApplied = true
		} else {
			scanModeRaw = string(netscan.DefaultScanMode)
		}
	}
	if reachableSegments {
		if _, ok := seenFlags["maxTargets"]; !ok {
			maxTargets = reachableDefaultMaxTargets
			result.ReachableDefaultMaxTargetsApplied = true
		}
	}

	modes, err := netscan.ParseModesCSV(scanModeRaw)
	if err != nil {
		return result, err
	}
	tcpPorts, err := netscan.ParsePortsCSV(tcpPortsRaw, "tcpPorts")
	if err != nil {
		return result, err
	}
	udpPorts, err := netscan.ParsePortsCSV(udpPortsRaw, "udpPorts")
	if err != nil {
		return result, err
	}

	result.Params = netscan.Params{
		Target:            strings.TrimSpace(target),
		TargetFile:        strings.TrimSpace(targetFile),
		Exclude:           strings.TrimSpace(exclude),
		ScanModes:         modes,
		IPv6:              ipv6Enabled,
		ReachableSegments: reachableSegments,
		TCPPorts:          tcpPorts,
		UDPPorts:          udpPorts,
		MaxTargets:        maxTargets,
		PPS:               pps,
		TimeoutMs:         timeoutMs,
		JitterMs:          jitterMs,
		Workers:           workers,
		ManagedSource:     strings.TrimSpace(managedSource),
		AssetStatus:       strings.TrimSpace(assetStatus),
		Keyword:           strings.TrimSpace(keyword),
		SortBy:            strings.TrimSpace(sortBy),
		SortOrder:         strings.TrimSpace(sortOrder),
	}
	return result, nil
}

func resolveEventlogTimeRange(startRaw, endRaw, lastRaw string, now time.Time) (int64, int64, error) {
	startRaw = strings.TrimSpace(startRaw)
	endRaw = strings.TrimSpace(endRaw)
	lastRaw = strings.TrimSpace(lastRaw)

	nowMs := now.UnixMilli()
	if nowMs <= 0 {
		nowMs = time.Now().UnixMilli()
	}

	if startRaw != "" {
		if lastRaw != "" {
			return 0, 0, fmt.Errorf("invalid argument: -startTime cannot be used with -last")
		}
		startTime, err := parseEventlogFlexibleTime("startTime", startRaw)
		if err != nil {
			return 0, 0, err
		}
		endTime := nowMs
		if endRaw != "" {
			endTime, err = parseEventlogFlexibleTime("endTime", endRaw)
			if err != nil {
				return 0, 0, err
			}
		}
		return startTime, endTime, nil
	}

	endTime := nowMs
	if endRaw != "" {
		parsedUntil, err := parseEventlogFlexibleTime("endTime", endRaw)
		if err != nil {
			return 0, 0, err
		}
		endTime = parsedUntil
	}

	windowMs := defaultEventlogWindow.Milliseconds()
	if lastRaw != "" {
		parsedWindow, err := parseEventlogLastWindow("last", lastRaw)
		if err != nil {
			return 0, 0, err
		}
		windowMs = parsedWindow
	}

	startTime := endTime - windowMs
	if startTime <= 0 {
		return 0, 0, fmt.Errorf("invalid argument: resolved startTime must be a positive unix timestamp in milliseconds")
	}
	return startTime, endTime, nil
}

func parseEventlogFlexibleTime(flagName, value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, fmt.Errorf("invalid argument: -%s must not be empty", flagName)
	}

	if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil && parsed > 0 {
		return parsed, nil
	}

	if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return parsed.UnixMilli(), nil
	}

	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.ParseInLocation(layout, trimmed, time.Local); err == nil {
			return parsed.UnixMilli(), nil
		}
	}

	return 0, fmt.Errorf(
		"invalid argument: -%s must be unix milliseconds, RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD",
		flagName,
	)
}

func parseEventlogLastWindow(flagName, value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, fmt.Errorf("invalid argument: -%s must not be empty", flagName)
	}

	if duration, err := time.ParseDuration(trimmed); err == nil {
		if duration <= 0 {
			return 0, fmt.Errorf("invalid argument: -%s must be greater than 0", flagName)
		}
		return duration.Milliseconds(), nil
	}

	if matches := eventlogLastPattern.FindStringSubmatch(trimmed); len(matches) == 3 {
		count, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil || count <= 0 {
			return 0, fmt.Errorf("invalid argument: -%s must be greater than 0", flagName)
		}
		unit := strings.ToLower(matches[2])
		switch unit {
		case "d":
			return (time.Duration(count) * 24 * time.Hour).Milliseconds(), nil
		case "w":
			return (time.Duration(count) * 7 * 24 * time.Hour).Milliseconds(), nil
		}
	}

	return 0, fmt.Errorf("invalid argument: -%s must be a duration like 30m, 24h, or 7d", flagName)
}

func runStandaloneRiskCLI(args []string, global globalCLIOptions) int {
	if global.ShowHelp {
		if _, err := parseRiskFlags([]string{"-h"}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return 0
	}

	if err := rejectLegacyOutputFlags(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	parseArgs := append([]string{}, args...)
	if global.RiskMode != "" {
		parseArgs = append(parseArgs, "-risk-mode", global.RiskMode)
	}

	opts, err := parseRiskFlags(parseArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if opts.ShowHelp {
		return 0
	}

	riskProgress := newRiskTerminalProgress(os.Stderr)
	defer riskProgress.Done()

	results, err := analyzeRiskResults(opts, nil, riskProgress)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := emitOutput(results, global.OutputPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func newRiskTerminalProgress(out io.Writer) *terminalProgress {
	// Risk streaming prints long per-result lines. In some terminals wrapped lines
	// can desynchronize pinned cursor math, so keep risk progress in single-line
	// carriage-return mode to guarantee one stable progress row.
	return newTerminalProgressWithPin(out, "risk analyze", false)
}

func rejectRiskOptionsWithoutEnable(riskArgs []string, global globalCLIOptions) error {
	if global.RiskEnabled {
		return nil
	}
	if strings.TrimSpace(global.RiskMode) != "" {
		return fmt.Errorf("invalid argument: --risk-mode can only be used when -r/--riskanalyze is enabled")
	}
	if len(riskArgs) == 0 {
		return nil
	}

	token := strings.TrimSpace(riskArgs[0])
	if token == "" {
		return fmt.Errorf("invalid argument: risk analysis options can only be used when -r/--riskanalyze is enabled")
	}
	name, _ := splitFlagToken(token)
	if !strings.HasPrefix(name, "-") {
		name = token
	}
	return fmt.Errorf("invalid argument: %s can only be used when -r/--riskanalyze is enabled", name)
}

func parseHostscanArgs(args []string) (hostscanParseResult, error) {
	var result hostscanParseResult

	scanArgs, riskArgs, err := splitRiskArgs(args)
	if err != nil {
		return result, err
	}
	result.RiskArgs = riskArgs

	var (
		customVal  string
		allEnabled bool
		moduleArgs []string
	)

	i := 0
	for i < len(scanArgs) {
		arg := scanArgs[i]
		switch {
		case arg == "-h" || arg == "--help":
			result.ShowHelp = true
			i++
		case arg == "--all" || arg == "-all":
			allEnabled = true
			i++
		case arg == "--custom" || arg == "-custom":
			if i+1 >= len(scanArgs) {
				return result, fmt.Errorf("invalid argument: --custom requires a module list")
			}
			customVal = scanArgs[i+1]
			i += 2
		case strings.HasPrefix(arg, "--custom=") || strings.HasPrefix(arg, "-custom="):
			parts := strings.SplitN(arg, "=", 2)
			customVal = parts[1]
			i++
		default:
			moduleArgs = append(moduleArgs, arg)
			i++
		}
	}

	if customVal != "" && allEnabled {
		return result, fmt.Errorf("invalid argument: --custom and --all cannot be used together")
	}
	if !result.ShowHelp && customVal == "" && !allEnabled {
		return result, fmt.Errorf("invalid argument: hostscan requires either --all or --custom")
	}
	result.CustomSpecified = customVal != ""

	var modules []string
	if customVal != "" {
		modules, err = parseModuleList(customVal, hostscanModuleOrder)
		if err != nil {
			return result, err
		}
	} else if allEnabled {
		modules = append(modules, hostscanModuleOrder...)
	}

	result.MultiMode = len(modules) > 1
	result.Modules = modules
	result.ModuleArgs = moduleArgs

	if result.MultiMode {
		filters, err := parseHostCommonFilters(moduleArgs)
		if err != nil {
			return result, err
		}
		result.Filters = filters
	}

	return result, nil
}

func applyHostscanRiskModuleSelection(parsed hostscanParseResult, riskEnabled bool) (hostscanParseResult, error) {
	if !riskEnabled {
		return parsed, nil
	}
	if parsed.CustomSpecified {
		invalid := make([]string, 0)
		for _, module := range parsed.Modules {
			if !hostscanHasModule(hostscanRiskModuleOrder, module) {
				invalid = append(invalid, module)
			}
		}
		if len(invalid) > 0 {
			return parsed, fmt.Errorf(
				"invalid argument: with hostscan -r, --custom only supports risk modules process,startup,scheduledtask,kernel,database,application; unsupported: %s",
				strings.Join(invalid, ","),
			)
		}
		return parsed, nil
	}
	parsed.Modules = append([]string{}, hostscanRiskModuleOrder...)
	parsed.MultiMode = len(parsed.Modules) > 1
	return parsed, nil
}

func hostscanHasModule(modules []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	for _, module := range modules {
		if strings.ToLower(strings.TrimSpace(module)) == target {
			return true
		}
	}
	return false
}

func parseFilescanArgs(args []string) (filescanParseResult, error) {
	var result filescanParseResult

	scanArgs, riskArgs, err := splitRiskArgs(args)
	if err != nil {
		return result, err
	}
	result.RiskArgs = riskArgs

	var (
		customVal               string
		allEnabled              bool
		moduleArgs              []string
		scanModeSpecified       bool
		localMode               string
		localPath               string
		localSmart              bool
		localMaxTarget          int
		localMaxTargetSpecified bool
	)

	i := 0
	for i < len(scanArgs) {
		arg := scanArgs[i]
		switch {
		case arg == "-h" || arg == "--help":
			result.ShowHelp = true
			i++
		case arg == "--all" || arg == "-all":
			allEnabled = true
			i++
		case arg == "--custom" || arg == "-custom":
			if i+1 >= len(scanArgs) {
				return result, fmt.Errorf("invalid argument: --custom requires a module list")
			}
			customVal = scanArgs[i+1]
			i += 2
		case strings.HasPrefix(arg, "--custom=") || strings.HasPrefix(arg, "-custom="):
			parts := strings.SplitN(arg, "=", 2)
			customVal = parts[1]
			i++
		case arg == "--scan-mode" || arg == "-scan-mode" || arg == "--mode" || arg == "-mode":
			if i+1 >= len(scanArgs) {
				return result, fmt.Errorf("invalid argument: --scan-mode requires a value")
			}
			scanModeSpecified = true
			localMode = scanArgs[i+1]
			i += 2
		case strings.HasPrefix(arg, "--scan-mode=") || strings.HasPrefix(arg, "-scan-mode=") || strings.HasPrefix(arg, "--mode=") || strings.HasPrefix(arg, "-mode="):
			parts := strings.SplitN(arg, "=", 2)
			scanModeSpecified = true
			localMode = parts[1]
			i++
		case arg == "--scan-path" || arg == "-scan-path" || strings.HasPrefix(arg, "--scan-path=") || strings.HasPrefix(arg, "-scan-path="):
			return result, fmt.Errorf("invalid argument: --scan-path is no longer supported; use --scan-mode path <path>")
		case arg == "--max-targets" || arg == "-max-targets":
			if i+1 >= len(scanArgs) {
				return result, fmt.Errorf("invalid argument: --max-targets requires a value")
			}
			parsed, convErr := strconv.Atoi(scanArgs[i+1])
			if convErr != nil {
				return result, fmt.Errorf("invalid argument: --max-targets must be an integer")
			}
			localMaxTargetSpecified = true
			localMaxTarget = parsed
			i += 2
		case strings.HasPrefix(arg, "--max-targets=") || strings.HasPrefix(arg, "-max-targets="):
			parts := strings.SplitN(arg, "=", 2)
			parsed, convErr := strconv.Atoi(parts[1])
			if convErr != nil {
				return result, fmt.Errorf("invalid argument: --max-targets must be an integer")
			}
			localMaxTargetSpecified = true
			localMaxTarget = parsed
			i++
		case arg == "--smart" || arg == "-smart":
			localSmart = true
			i++
		case arg == "--workers" || arg == "-workers" || strings.HasPrefix(arg, "--workers=") || strings.HasPrefix(arg, "-workers="):
			return result, fmt.Errorf("invalid argument: --workers is no longer supported; local scan concurrency is adjusted adaptively by CPU and memory")
		default:
			moduleArgs = append(moduleArgs, arg)
			i++
		}
	}

	if customVal != "" && allEnabled {
		return result, fmt.Errorf("invalid argument: --custom and --all cannot be used together")
	}
	result.CustomSpecified = customVal != ""
	if scanModeSpecified && (customVal != "" || allEnabled) {
		return result, fmt.Errorf("invalid argument: local scan mode cannot be used with site/framework/jarpackage/software module selection")
	}
	if localSmart && (customVal != "" || allEnabled) {
		return result, fmt.Errorf("invalid argument: --smart can only be used with --scan-mode full|path")
	}
	if localMaxTargetSpecified && (customVal != "" || allEnabled) {
		return result, fmt.Errorf("invalid argument: --max-targets can only be used with --scan-mode full|path")
	}
	if !result.ShowHelp && localSmart && !scanModeSpecified {
		return result, fmt.Errorf("invalid argument: --smart can only be used with --scan-mode full|path")
	}
	if !result.ShowHelp && localMaxTargetSpecified && !scanModeSpecified {
		return result, fmt.Errorf("invalid argument: --max-targets can only be used with --scan-mode full|path")
	}
	if !result.ShowHelp && !scanModeSpecified && customVal == "" && !allEnabled {
		return result, fmt.Errorf("invalid argument: filescan requires one of --all, --custom, or --scan-mode")
	}

	if scanModeSpecified {
		if result.ShowHelp {
			// Help mode should not fail on missing local path or unknown local args.
			return result, nil
		}
		mode, err := normalizeFileScanMode(localMode)
		if err != nil {
			return result, err
		}
		if mode == filescan.ScanModePath && strings.TrimSpace(localPath) == "" {
			if len(moduleArgs) == 1 {
				candidate := strings.TrimSpace(moduleArgs[0])
				if candidate != "" && !strings.HasPrefix(candidate, "-") {
					localPath = candidate
					moduleArgs = nil
				}
			}
		}
		if mode == filescan.ScanModePath && strings.TrimSpace(localPath) == "" {
			return result, fmt.Errorf("invalid argument: --scan-mode path requires a path, e.g. --scan-mode path <path>")
		}
		if len(moduleArgs) > 0 {
			return result, fmt.Errorf("invalid argument: local scan mode contains unknown argument: %s", moduleArgs[0])
		}
		result.IsLocalMode = true
		result.LocalMode = mode
		result.LocalPath = strings.TrimSpace(localPath)
		result.LocalSmart = localSmart
		result.LocalMaxTarget = localMaxTarget
		return result, nil
	}

	var modules []string
	if customVal != "" {
		modules, err = parseModuleList(customVal, filescanWebModuleOrder)
		if err != nil {
			return result, err
		}
	} else if allEnabled {
		modules = append(modules, filescanWebModuleOrder...)
	}
	result.WebModules = modules
	result.ModuleArgs = moduleArgs

	if len(modules) > 1 {
		filters, err := parseFilescanWebCommonFilters(moduleArgs)
		if err != nil {
			return result, err
		}
		result.WebFilters = filters
	}

	return result, nil
}

func scopedProgressUpdate(progress *terminalProgress, scope string) func(done, total int, stage string) {
	if progress == nil {
		return nil
	}
	scope = strings.TrimSpace(scope)
	return func(done, total int, stage string) {
		stage = strings.TrimSpace(stage)
		switch {
		case scope == "" && stage == "":
			progress.Update(done, total, "")
		case scope == "":
			progress.Update(done, total, stage)
		case stage == "":
			progress.Update(done, total, scope)
		default:
			progress.Update(done, total, scope+" | "+stage)
		}
	}
}

type moduleExecResult struct {
	rows    []map[string]any
	records []riskanalysis.ScanRecord
	err     error
}

const (
	defaultModuleAdjustInterval = 1500 * time.Millisecond
	defaultModulePollInterval   = 120 * time.Millisecond
	defaultModuleCPUHigh        = 0.90
	defaultModuleCPULow         = 0.60
)

var (
	moduleMetricCPUTotal = "/cpu/classes/total:cpu-seconds"
	moduleMetricMemTotal = "/memory/classes/total:bytes"
)

type moduleWorkerProfile struct {
	min            int
	initial        int
	max            int
	adaptive       bool
	pollInterval   time.Duration
	adjustInterval time.Duration
	cpuHigh        float64
	cpuLow         float64
	memHighBytes   uint64
	memLowBytes    uint64
}

type moduleRuntimeStats struct {
	cpuUtilization float64
	cpuValid       bool
	memoryBytes    uint64
}

type moduleRuntimeSampler struct {
	samples []metrics.Sample
	prevCPU float64
	prevAt  time.Time
	hasPrev bool
}

func resolveModuleWorkerLimit(total int) int {
	return resolveModuleWorkerProfile(total).initial
}

func resolveModuleWorkerProfile(total int) moduleWorkerProfile {
	if total <= 1 {
		return moduleWorkerProfile{
			min:            1,
			initial:        1,
			max:            1,
			adaptive:       false,
			pollInterval:   defaultModulePollInterval,
			adjustInterval: defaultModuleAdjustInterval,
			cpuHigh:        defaultModuleCPUHigh,
			cpuLow:         defaultModuleCPULow,
			memHighBytes:   moduleMiBToBytes(768),
			memLowBytes:    moduleMiBToBytes(512),
		}
	}

	if forced := readPositiveEnvInt("C_EYES_MODULE_WORKERS"); forced > 0 {
		if forced > total {
			forced = total
		}
		return moduleWorkerProfile{
			min:            forced,
			initial:        forced,
			max:            forced,
			adaptive:       false,
			pollInterval:   defaultModulePollInterval,
			adjustInterval: defaultModuleAdjustInterval,
			cpuHigh:        defaultModuleCPUHigh,
			cpuLow:         defaultModuleCPULow,
			memHighBytes:   moduleMiBToBytes(768),
			memLowBytes:    moduleMiBToBytes(512),
		}
	}

	procs := runtime.GOMAXPROCS(0)
	if procs <= 0 {
		procs = runtime.NumCPU()
	}
	if procs <= 0 {
		procs = 1
	}

	maxW := procs / 2
	if maxW < 2 {
		maxW = 2
	}
	if total >= 8 && maxW < 3 {
		maxW = 3
	}
	if maxW > 4 {
		maxW = 4
	}
	if maxW > total {
		maxW = total
	}

	initial := maxW
	if initial > 4 {
		initial = 4
	}
	if total <= 3 && initial > 2 {
		initial = 2
	}
	if initial <= 0 {
		initial = 1
	}

	memoryBytes := readModuleMemoryBytes()
	switch {
	case memoryBytes >= moduleMiBToBytes(1536) && maxW > 2:
		maxW = 2
	case memoryBytes >= moduleMiBToBytes(1024) && maxW > 3:
		maxW = 3
	}
	if initial > maxW {
		initial = maxW
	}

	minW := 1
	if envMin := readPositiveEnvInt("C_EYES_MODULE_WORKERS_MIN"); envMin > 0 {
		minW = envMin
	}
	if envMax := readPositiveEnvInt("C_EYES_MODULE_WORKERS_MAX"); envMax > 0 {
		maxW = envMax
	}
	if maxW < 1 {
		maxW = 1
	}
	if maxW > total {
		maxW = total
	}
	if minW > maxW {
		minW = maxW
	}
	if initial < minW {
		initial = minW
	}
	if initial > maxW {
		initial = maxW
	}

	memHighMiB := 768 + (maxW * 128)
	if memHighMiB < 768 {
		memHighMiB = 768
	}
	memLowMiB := int(float64(memHighMiB) * 0.70)
	if memLowMiB < 512 {
		memLowMiB = 512
	}
	if memLowMiB > memHighMiB {
		memLowMiB = memHighMiB
	}

	return moduleWorkerProfile{
		min:            minW,
		initial:        initial,
		max:            maxW,
		adaptive:       !parseBoolEnvWithDefault("C_EYES_MODULE_DISABLE_ADAPTIVE", false),
		pollInterval:   defaultModulePollInterval,
		adjustInterval: defaultModuleAdjustInterval,
		cpuHigh:        defaultModuleCPUHigh,
		cpuLow:         defaultModuleCPULow,
		memHighBytes:   moduleMiBToBytes(memHighMiB),
		memLowBytes:    moduleMiBToBytes(memLowMiB),
	}
}

func readPositiveEnvInt(name string) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func parseBoolEnvWithDefault(name string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func runModulesWithAdaptiveWorkers(total int, profile moduleWorkerProfile, run func(idx int) error) error {
	if total <= 0 {
		return nil
	}
	if profile.max <= 1 || total <= 1 {
		for idx := 0; idx < total; idx++ {
			if err := run(idx); err != nil {
				return err
			}
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		doneCount  atomic.Int64
		running    atomic.Int64
		wg         sync.WaitGroup
		runErr     error
		runErrOnce sync.Once
	)
	setErr := func(err error) {
		if err == nil {
			return
		}
		runErrOnce.Do(func() {
			runErr = err
			cancel()
		})
	}

	var sampler *moduleRuntimeSampler
	if profile.adaptive && profile.max > profile.min {
		sampler = newModuleRuntimeSampler()
	}
	resolveLimit := func(backlog int) int {
		limit := profile.max
		if sampler != nil {
			stats := sampler.sample()
			current := int(running.Load())
			if current < profile.initial {
				current = profile.initial
			}
			limit = decideNextModuleWorkerLimit(current, backlog, stats, profile)
		}
		if limit < profile.min {
			limit = profile.min
		}
		if limit > profile.max {
			limit = profile.max
		}
		if limit < 1 {
			limit = 1
		}
		return limit
	}

	sem := make(chan struct{}, profile.max)
	for idx := 0; idx < total; idx++ {
		for {
			if ctx.Err() != nil {
				break
			}
			backlog := total - int(doneCount.Load())
			if backlog <= 0 {
				break
			}
			limit := resolveLimit(backlog)
			if int(running.Load()) < limit {
				break
			}
			select {
			case <-ctx.Done():
				break
			case <-time.After(profile.pollInterval):
			}
		}
		if ctx.Err() != nil {
			break
		}

		sem <- struct{}{}
		running.Add(1)
		wg.Add(1)
		go func(taskIdx int) {
			defer wg.Done()
			defer func() {
				<-sem
				running.Add(-1)
				doneCount.Add(1)
			}()
			if err := run(taskIdx); err != nil {
				setErr(err)
			}
		}(idx)
	}
	wg.Wait()

	if runErr != nil {
		return runErr
	}
	if ctx.Err() != nil && doneCount.Load() < int64(total) {
		return ctx.Err()
	}
	return nil
}

func decideNextModuleWorkerLimit(current, backlog int, stats moduleRuntimeStats, profile moduleWorkerProfile) int {
	if current < profile.min {
		current = profile.min
	}
	if current > profile.max {
		current = profile.max
	}

	next := current
	if stats.memoryBytes >= profile.memHighBytes {
		next--
	} else if stats.cpuValid && stats.cpuUtilization >= profile.cpuHigh {
		next--
	} else if backlog > current*2 && stats.memoryBytes <= profile.memLowBytes && (!stats.cpuValid || stats.cpuUtilization <= profile.cpuLow) {
		next++
	} else if backlog < current && current > profile.min {
		next--
	}

	if backlog > 0 && next > backlog {
		next = moduleMaxInt(profile.min, backlog)
	}
	if next < profile.min {
		next = profile.min
	}
	if next > profile.max {
		next = profile.max
	}
	return next
}

func newModuleRuntimeSampler() *moduleRuntimeSampler {
	return &moduleRuntimeSampler{
		samples: []metrics.Sample{
			{Name: moduleMetricCPUTotal},
			{Name: moduleMetricMemTotal},
		},
	}
}

func (s *moduleRuntimeSampler) sample() moduleRuntimeStats {
	now := time.Now()
	metrics.Read(s.samples)

	stats := moduleRuntimeStats{}
	if len(s.samples) >= 2 && s.samples[1].Value.Kind() == metrics.KindUint64 {
		stats.memoryBytes = s.samples[1].Value.Uint64()
	}

	var cpuTotal float64
	if len(s.samples) >= 1 && s.samples[0].Value.Kind() == metrics.KindFloat64 {
		cpuTotal = s.samples[0].Value.Float64()
	}

	if s.hasPrev && cpuTotal >= s.prevCPU {
		wall := now.Sub(s.prevAt).Seconds()
		if wall > 0 {
			procs := float64(runtime.GOMAXPROCS(0))
			if procs <= 0 {
				procs = 1
			}
			util := (cpuTotal - s.prevCPU) / (wall * procs)
			if util < 0 {
				util = 0
			}
			if util > 2 {
				util = 2
			}
			stats.cpuUtilization = util
			stats.cpuValid = true
		}
	}

	s.prevCPU = cpuTotal
	s.prevAt = now
	s.hasPrev = true
	return stats
}

func readModuleMemoryBytes() uint64 {
	samples := []metrics.Sample{{Name: moduleMetricMemTotal}}
	metrics.Read(samples)
	if len(samples) == 0 {
		return 0
	}
	if samples[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return samples[0].Value.Uint64()
}

func moduleMinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func moduleMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func moduleMiBToBytes(mib int) uint64 {
	if mib <= 0 {
		return 0
	}
	return uint64(mib) * 1024 * 1024
}

func executeHostscan(parsed hostscanParseResult, includeProcessMemory bool, memoryMaxBytes int, progress *terminalProgress) (scanAggregateResult, []riskanalysis.ScanRecord, error) {
	rows := make([]map[string]any, 0)
	records := make([]riskanalysis.ScanRecord, 0)
	if len(parsed.Modules) == 0 {
		return scanAggregateResult{Total: 0, Rows: rows}, records, nil
	}

	moduleResults := make([]moduleExecResult, len(parsed.Modules))
	profile := resolveModuleWorkerProfile(len(parsed.Modules))

	runModule := func(idx int) error {
		module := parsed.Modules[idx]
		moduleProgress := scopedProgressUpdate(progress, module)
		var (
			moduleRows    []map[string]any
			moduleRecords []riskanalysis.ScanRecord
			err           error
		)

		if parsed.MultiMode {
			moduleRows, moduleRecords, err = runHostscanModuleWithCommonFilters(module, parsed.Filters, moduleProgress, includeProcessMemory, memoryMaxBytes)
		} else {
			moduleRows, moduleRecords, err = runHostscanSingleModule(module, parsed.ModuleArgs, moduleProgress, includeProcessMemory, memoryMaxBytes)
		}
		moduleResults[idx] = moduleExecResult{
			rows:    moduleRows,
			records: moduleRecords,
			err:     err,
		}
		if err != nil && progress != nil {
			progress.PrintLine(fmt.Sprintf("[WARN] hostscan module %s failed: %v", module, err))
		}
		return nil
	}

	if err := runModulesWithAdaptiveWorkers(len(parsed.Modules), profile, runModule); err != nil {
		return scanAggregateResult{}, nil, err
	}

	skipped := 0
	for _, moduleResult := range moduleResults {
		if moduleResult.err != nil {
			skipped++
			continue
		}
		rows = append(rows, moduleResult.rows...)
		records = append(records, moduleResult.records...)
	}
	if skipped > 0 && progress != nil {
		progress.PrintLine(fmt.Sprintf("[WARN] hostscan skipped %d failed module(s)", skipped))
	}

	rows = dedupeRows(rows)
	records = dedupeRiskRecords(records)
	return scanAggregateResult{Total: len(rows), Rows: rows}, records, nil
}

func runHostscanSingleModule(module string, args []string, progressFn func(done, total int, stage string), includeProcessMemory bool, memoryMaxBytes int) ([]map[string]any, []riskanalysis.ScanRecord, error) {
	switch module {
	case "account":
		opts, err := parseAccountScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := accountscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, ""), nil
	case "usergroup":
		opts, err := parseUserGroupScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := usergroupscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, ""), nil
	case "process":
		opts, err := parseProcessScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := processscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result)
		if err != nil {
			return nil, nil, err
		}
		return rows, processScanResultsToRiskRecords(result, includeProcessMemory, memoryMaxBytes), nil
	case "port":
		opts, err := parsePortScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := portscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, ""), nil
	case "startup":
		opts, err := parseStartupScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := startupscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"execPath"}), nil
	case "scheduledtask":
		opts, err := parseScheduledTaskScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := scheduledtaskscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"execPath", "conf"}), nil
	case "environment":
		opts, err := parseEnvironmentScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := environmentscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, ""), nil
	case "kernel":
		opts, err := parseKernelScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := kernelscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"path"}), nil
	case "database":
		opts, err := parseDatabaseScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := databasescan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"confPath", "logPath", "dataDir", "pluginDir", "mainDbPath", "sysLogPath"}), nil
	case "application":
		opts, err := parseWebApplicationScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := webapplicationscan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"rootPath", "webRoot"}), nil
	default:
		return nil, nil, fmt.Errorf("invalid argument: unknown hostscan module: %s", module)
	}
}

func runHostscanModuleWithCommonFilters(module string, filters hostCommonFilters, progressFn func(done, total int, stage string), includeProcessMemory bool, memoryMaxBytes int) ([]map[string]any, []riskanalysis.ScanRecord, error) {
	switch module {
	case "account":
		params := accountscan.AccountScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := accountscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, ""), nil
	case "usergroup":
		params := usergroupscan.UserGroupScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := usergroupscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, ""), nil
	case "process":
		params := processscan.ProcessScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := processscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result)
		if err != nil {
			return nil, nil, err
		}
		return rows, processScanResultsToRiskRecords(result, includeProcessMemory, memoryMaxBytes), nil
	case "port":
		params := portscan.PortScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := portscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, ""), nil
	case "startup":
		params := startupscan.StartupScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := startupscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"execPath"}), nil
	case "scheduledtask":
		params := scheduledtaskscan.ScheduledTaskScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := scheduledtaskscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"execPath", "conf"}), nil
	case "environment":
		params := environmentscan.EnvironmentScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := environmentscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, ""), nil
	case "kernel":
		params := kernelscan.KernelScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := kernelscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"path"}), nil
	case "database":
		params := databasescan.DatabaseScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := databasescan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"confPath", "logPath", "dataDir", "pluginDir", "mainDbPath", "sysLogPath"}), nil
	case "application":
		params := webapplicationscan.WebApplicationScanParams{Hostname: filters.Hostname, IP: filters.IP, Progress: progressFn}
		result, err := webapplicationscan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"rootPath", "webRoot"}), nil
	default:
		return nil, nil, fmt.Errorf("invalid argument: unknown hostscan module: %s", module)
	}
}

func executeFilescanWebMode(parsed filescanParseResult, progress *terminalProgress) (scanAggregateResult, []riskanalysis.ScanRecord, error) {
	rows := make([]map[string]any, 0)
	records := make([]riskanalysis.ScanRecord, 0)
	if len(parsed.WebModules) == 0 {
		return scanAggregateResult{Total: 0, Rows: rows}, records, nil
	}

	moduleResults := make([]moduleExecResult, len(parsed.WebModules))
	profile := resolveModuleWorkerProfile(len(parsed.WebModules))

	runModule := func(idx int) error {
		module := parsed.WebModules[idx]
		moduleProgress := scopedProgressUpdate(progress, module)
		var (
			moduleRows    []map[string]any
			moduleRecords []riskanalysis.ScanRecord
			err           error
		)

		if len(parsed.WebModules) > 1 {
			moduleRows, moduleRecords, err = runFilescanWebModuleWithCommonFilters(module, parsed.WebFilters, moduleProgress)
		} else {
			moduleRows, moduleRecords, err = runFilescanWebSingleModule(module, parsed.ModuleArgs, moduleProgress)
		}
		moduleResults[idx] = moduleExecResult{
			rows:    moduleRows,
			records: moduleRecords,
			err:     err,
		}
		if err != nil && progress != nil {
			progress.PrintLine(fmt.Sprintf("[WARN] filescan module %s failed: %v", module, err))
		}
		return nil
	}

	if err := runModulesWithAdaptiveWorkers(len(parsed.WebModules), profile, runModule); err != nil {
		return scanAggregateResult{}, nil, err
	}

	skipped := 0
	for _, moduleResult := range moduleResults {
		if moduleResult.err != nil {
			skipped++
			continue
		}
		rows = append(rows, moduleResult.rows...)
		records = append(records, moduleResult.records...)
	}
	if skipped > 0 && progress != nil {
		progress.PrintLine(fmt.Sprintf("[WARN] filescan skipped %d failed module(s)", skipped))
	}

	rows = dedupeRows(rows)
	records = dedupeRiskRecords(records)
	return scanAggregateResult{Total: len(rows), Rows: rows}, records, nil
}

func executeFilescanLocalMode(parsed filescanParseResult, progress *terminalProgress) ([]map[string]any, []riskanalysis.ScanRecord, error) {
	scope := fmt.Sprintf("scan-mode=%s", parsed.LocalMode)
	if parsed.LocalSmart {
		scope += " | smart=true"
	}
	localModeProgress := scopedProgressUpdate(progress, scope)
	var skipped atomic.Int64
	results, err := filescan.Scan(context.Background(), filescan.FileScanParams{
		Mode:         parsed.LocalMode,
		Path:         parsed.LocalPath,
		SmartEnabled: parsed.LocalSmart,
		MaxTargets:   parsed.LocalMaxTarget,
		Progress:     localModeProgress,
		OnTaskError: func(task filescan.ScanTask, stage string, taskErr error) {
			skipped.Add(1)
			if progress != nil {
				targetPath := strings.TrimSpace(task.Path)
				reason := compactScanTargetErrorMessage(targetPath, taskErr)
				if isPermissionDeniedError(taskErr) {
					progress.PrintLine(fmt.Sprintf("[WARN] filescan target %s scan failed: %s", targetPath, reason))
					return
				}
				progress.PrintLine(fmt.Sprintf("[WARN] filescan target %s failed at %s: %s", targetPath, stage, reason))
			}
		},
	})
	if err != nil {
		return nil, nil, err
	}
	if skipped.Load() > 0 && progress != nil {
		progress.PrintLine(fmt.Sprintf("[WARN] filescan skipped %d failed target(s)", skipped.Load()))
	}
	rows, err := anySliceToMapRows(results)
	if err != nil {
		return nil, nil, err
	}
	return rows, fileScanResultsToRiskRecords(results), nil
}

func runFilescanWebSingleModule(module string, args []string, progressFn func(done, total int, stage string)) ([]map[string]any, []riskanalysis.ScanRecord, error) {
	switch module {
	case "site":
		opts, err := parseWebSiteScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := websitescan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, "file"), nil
	case "framework":
		opts, err := parseWebFrameworkScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := webframescan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, "file"), nil
	case "jarpackage":
		opts, err := parseJarPackageScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := jarpackagescan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, "file"), nil
	case "software":
		opts, err := parseSoftwareScanFlags(args)
		if err != nil {
			return nil, nil, err
		}
		opts.Params.Progress = progressFn
		result, err := softwarescan.Scan(context.Background(), opts.Params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"binPath", "configPath"}), nil
	default:
		return nil, nil, fmt.Errorf("invalid argument: unknown filescan module: %s", module)
	}
}

func runFilescanWebModuleWithCommonFilters(module string, filters filescanWebCommonFilters, progressFn func(done, total int, stage string)) ([]map[string]any, []riskanalysis.ScanRecord, error) {
	switch module {
	case "site":
		params := websitescan.WebSiteScanParams{
			Groups:   append([]int64{}, filters.Groups...),
			Hostname: filters.Hostname,
			IP:       filters.IP,
			Progress: progressFn,
		}
		result, err := websitescan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, "file"), nil
	case "framework":
		params := webframescan.WebFrameScanParams{
			Groups:   append([]int64{}, filters.Groups...),
			Hostname: filters.Hostname,
			IP:       filters.IP,
			Progress: progressFn,
		}
		result, err := webframescan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, "file"), nil
	case "jarpackage":
		params := jarpackagescan.JarPackageScanParams{
			Groups:   append([]int64{}, filters.Groups...),
			Hostname: filters.Hostname,
			IP:       filters.IP,
			Progress: progressFn,
		}
		result, err := jarpackagescan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecords(rows, "file"), nil
	case "software":
		params := softwarescan.SoftwareScanParams{
			Groups:   append([]int64{}, filters.Groups...),
			Hostname: filters.Hostname,
			IP:       filters.IP,
			Progress: progressFn,
		}
		result, err := softwarescan.Scan(context.Background(), params)
		if err != nil {
			return nil, nil, err
		}
		rows, err := anySliceToMapRows(result.Rows)
		if err != nil {
			return nil, nil, err
		}
		return rows, mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"binPath", "configPath"}), nil
	default:
		return nil, nil, fmt.Errorf("invalid argument: unknown filescan module: %s", module)
	}
}

func parseHostCommonFilters(args []string) (hostCommonFilters, error) {
	var filters hostCommonFilters

	fs := flag.NewFlagSet("hostscan-common", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var hostname, ip string
	fs.StringVar(&hostname, "hostname", "", "hostname")
	fs.StringVar(&ip, "ip", "", "ip")

	if err := fs.Parse(args); err != nil {
		return filters, fmt.Errorf("invalid argument: hostscan multi-module mode only supports hostname/ip intersection filters")
	}
	if len(fs.Args()) > 0 {
		return filters, fmt.Errorf("invalid argument: hostscan multi-module mode contains non-intersection argument: %s", fs.Args()[0])
	}

	if strings.TrimSpace(hostname) != "" {
		hostname = strings.TrimSpace(hostname)
		filters.Hostname = &hostname
	}
	if strings.TrimSpace(ip) != "" {
		ip = strings.TrimSpace(ip)
		filters.IP = &ip
	}
	return filters, nil
}

func parseFilescanWebCommonFilters(args []string) (filescanWebCommonFilters, error) {
	var filters filescanWebCommonFilters

	fs := flag.NewFlagSet("filescan-common", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		hostname string
		ip       string
		groups   intSliceFlag
	)
	fs.Var(&groups, "groups", "groups")
	fs.StringVar(&hostname, "hostname", "", "hostname")
	fs.StringVar(&ip, "ip", "", "ip")

	if err := fs.Parse(args); err != nil {
		return filters, fmt.Errorf("invalid argument: filescan multi-module mode only supports groups/hostname/ip intersection filters")
	}
	if len(fs.Args()) > 0 {
		return filters, fmt.Errorf("invalid argument: filescan multi-module mode contains non-intersection argument: %s", fs.Args()[0])
	}

	if groups.set {
		filters.Groups = make([]int64, 0, len(groups.values))
		for _, v := range groups.values {
			filters.Groups = append(filters.Groups, int64(v))
		}
	}
	if strings.TrimSpace(hostname) != "" {
		hostname = strings.TrimSpace(hostname)
		filters.Hostname = &hostname
	}
	if strings.TrimSpace(ip) != "" {
		ip = strings.TrimSpace(ip)
		filters.IP = &ip
	}
	return filters, nil
}

func parseModuleList(raw string, allow []string) ([]string, error) {
	allowSet := make(map[string]struct{}, len(allow))
	for _, item := range allow {
		allowSet[item] = struct{}{}
	}

	parts := splitCSV(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid argument: module list cannot be empty")
	}

	seen := map[string]struct{}{}
	modules := make([]string, 0, len(parts))
	for _, item := range parts {
		name := strings.ToLower(strings.TrimSpace(item))
		if name == "" {
			continue
		}
		if _, ok := allowSet[name]; !ok {
			return nil, fmt.Errorf("invalid argument: unknown module: %s", name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		modules = append(modules, name)
	}

	if len(modules) == 0 {
		return nil, fmt.Errorf("invalid argument: module list cannot be empty")
	}
	return modules, nil
}

func normalizeFileScanMode(raw string) (filescan.ScanMode, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	switch filescan.ScanMode(mode) {
	case filescan.ScanModeFull, filescan.ScanModePath:
		return filescan.ScanMode(mode), nil
	default:
		return "", fmt.Errorf("invalid argument: --scan-mode only supports full/path")
	}
}

func splitRiskArgs(args []string) ([]string, []string, error) {
	riskValueFlags := map[string]struct{}{
		"-input":                        {},
		"--input":                       {},
		"-file":                         {},
		"--file":                        {},
		"-dir":                          {},
		"--dir":                         {},
		"-pid":                          {},
		"--pid":                         {},
		"-pname":                        {},
		"--pname":                       {},
		"-mode":                         {},
		"--mode":                        {},
		"-risk-mode":                    {},
		"--risk-mode":                   {},
		"-yara-rules":                   {},
		"--yara-rules":                  {},
		"-yara-read-chunk":              {},
		"--yara-read-chunk":             {},
		"-memory-max-bytes":             {},
		"--memory-max-bytes":            {},
		"-local-weight":                 {},
		"--local-weight":                {},
		"-cloud-weight":                 {},
		"--cloud-weight":                {},
		"-cloud-upload-concurrency":     {},
		"--cloud-upload-concurrency":    {},
		"-cloud-upload-wait":            {},
		"--cloud-upload-wait":           {},
		"-cloud-upload-submit-timeout":  {},
		"--cloud-upload-submit-timeout": {},
		"-cloud-upload-poll-interval":   {},
		"--cloud-upload-poll-interval":  {},
		"-cloud-upload-max-size":        {},
		"--cloud-upload-max-size":       {},
		"-analysis-max-duration":        {},
		"--analysis-max-duration":       {},
	}
	riskBoolFlags := map[string]struct{}{
		"-process-memory":  {},
		"--process-memory": {},
		"-cloud-upload":    {},
		"--cloud-upload":   {},
	}

	scanArgs := make([]string, 0, len(args))
	riskArgs := make([]string, 0, len(args))

	i := 0
	for i < len(args) {
		arg := args[i]
		name, hasInline := splitFlagToken(arg)
		if _, ok := riskBoolFlags[name]; ok {
			riskArgs = append(riskArgs, arg)
			i++
			continue
		}
		if _, ok := riskValueFlags[name]; ok {
			riskArgs = append(riskArgs, arg)
			if !hasInline {
				if i+1 >= len(args) {
					return nil, nil, fmt.Errorf("invalid argument: %s requires a value", name)
				}
				riskArgs = append(riskArgs, args[i+1])
				i += 2
				continue
			}
			i++
			continue
		}
		scanArgs = append(scanArgs, arg)
		i++
	}
	return scanArgs, riskArgs, nil
}

func splitFlagToken(token string) (string, bool) {
	if !strings.HasPrefix(token, "-") {
		return token, false
	}
	if !strings.Contains(token, "=") {
		return token, false
	}
	parts := strings.SplitN(token, "=", 2)
	return parts[0], true
}

func parseChainedRiskOptions(riskArgs []string, riskMode string, hostscanMode bool, hostscanHasProcessModule bool) (riskOptions, error) {
	var opts riskOptions

	if err := rejectLegacyOutputFlags(riskArgs); err != nil {
		return opts, err
	}
	if hasRiskSourceArgs(riskArgs) {
		return opts, fmt.Errorf("invalid argument: chained risk analysis does not support source arguments -input/-file/-dir/-pid/-pname")
	}
	if hostscanMode && strings.TrimSpace(riskMode) != "" {
		return opts, fmt.Errorf("invalid argument: hostscan chained risk analysis is fixed to local_only and does not support --risk-mode/-mode")
	}
	processMemoryEnabled := chainedProcessMemoryEnabled(riskArgs)
	if hostscanMode && processMemoryEnabled && !hostscanHasProcessModule {
		return opts, fmt.Errorf("invalid argument: in hostscan chained risk analysis, -process-memory is supported only with process module")
	}

	parseArgs := append([]string{}, riskArgs...)
	if hostscanMode && processMemoryEnabled {
		parseArgs = stripEnabledProcessMemoryFlags(parseArgs)
	}
	parseArgs = append(parseArgs, "-input", "__chained__.json")
	if riskMode != "" {
		parseArgs = append(parseArgs, "-risk-mode", riskMode)
	}

	parsed, err := parseRiskFlags(parseArgs)
	if err != nil {
		return opts, err
	}

	parsed.InputPath = ""
	parsed.FilePath = ""
	parsed.DirPath = ""
	parsed.ProcessPID = -1
	parsed.ProcessName = ""
	if hostscanMode && processMemoryEnabled {
		parsed.ProcessMemory = true
	}

	if hostscanMode {
		if strings.TrimSpace(parsed.Mode) != "" {
			return opts, fmt.Errorf("invalid argument: hostscan chained risk analysis is fixed to local_only and does not support --risk-mode/-mode")
		}
		if parsed.CloudUpload {
			return opts, fmt.Errorf("invalid argument: hostscan chained risk analysis does not support -cloud-upload")
		}
		parsed.Mode = string(riskanalysis.ModeLocalOnly)
	} else if strings.TrimSpace(parsed.Mode) == "" {
		parsed.Mode = string(riskanalysis.ModeSmart)
	}

	return parsed, nil
}

func chainedProcessMemoryEnabled(args []string) bool {
	enabled := false
	seen := false
	for _, arg := range args {
		name, hasInline := splitFlagToken(arg)
		if !isProcessMemoryFlag(name) {
			continue
		}
		if !hasInline {
			enabled = true
			seen = true
			continue
		}
		parts := strings.SplitN(arg, "=", 2)
		value, err := strconv.ParseBool(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		enabled = value
		seen = true
	}
	return seen && enabled
}

func stripEnabledProcessMemoryFlags(args []string) []string {
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		name, hasInline := splitFlagToken(arg)
		if !isProcessMemoryFlag(name) {
			filtered = append(filtered, arg)
			continue
		}
		if !hasInline {
			continue
		}
		parts := strings.SplitN(arg, "=", 2)
		value, err := strconv.ParseBool(strings.TrimSpace(parts[1]))
		if err != nil || !value {
			filtered = append(filtered, arg)
		}
	}
	return filtered
}

func isProcessMemoryFlag(name string) bool {
	return name == "-process-memory" || name == "--process-memory"
}

func hasRiskSourceArgs(args []string) bool {
	sourceNames := map[string]struct{}{
		"-input":  {},
		"--input": {},
		"-file":   {},
		"--file":  {},
		"-dir":    {},
		"--dir":   {},
		"-pid":    {},
		"--pid":   {},
		"-pname":  {},
		"--pname": {},
	}
	for _, arg := range args {
		name, _ := splitFlagToken(arg)
		if _, ok := sourceNames[name]; ok {
			return true
		}
	}
	return false
}

type riskSeverityBand int

const (
	riskSeverityNone riskSeverityBand = iota
	riskSeverityLow
	riskSeverityMedium
	riskSeverityHigh
)

type riskStreamSummary struct {
	high int
	med  int
	low  int
}

type riskProgressUpdateLimiter struct {
	mu          sync.Mutex
	enabled     bool
	initialized bool
	lastTotal   int
	lastIndex   int
	lastPercent int
	lastStage   string
	lastEmitAt  time.Time
}

func newRiskProgressUpdateLimiter(progress *terminalProgress) *riskProgressUpdateLimiter {
	enabled := true
	if progress != nil && progress.pinned {
		enabled = false
	}
	return &riskProgressUpdateLimiter{
		enabled: enabled,
	}
}

func (l *riskProgressUpdateLimiter) allow(event riskanalysis.ProgressEvent) bool {
	if l == nil || !l.enabled {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	total := event.Total
	index := event.Index
	stage := strings.TrimSpace(event.Stage)
	percent := event.Percent
	if percent < 0 || percent > 100 {
		if total > 0 {
			percent = int(float64(index) / float64(total) * 100)
		} else {
			percent = 0
		}
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	if !l.initialized {
		l.initialized = true
		l.lastTotal = total
		l.lastIndex = index
		l.lastPercent = percent
		l.lastStage = stage
		l.lastEmitAt = now
		return true
	}

	shouldEmit := false
	switch {
	case total != l.lastTotal:
		shouldEmit = true
	case total > 0 && index >= total:
		shouldEmit = true
	case index < l.lastIndex:
		shouldEmit = true
	case percent >= l.lastPercent+5:
		shouldEmit = true
	case now.Sub(l.lastEmitAt) >= 2500*time.Millisecond:
		shouldEmit = true
	}

	if shouldEmit {
		l.lastTotal = total
		l.lastIndex = index
		l.lastPercent = percent
		l.lastStage = stage
		l.lastEmitAt = now
	}
	return shouldEmit
}

func (s *riskStreamSummary) add(band riskSeverityBand) {
	if s == nil {
		return
	}
	switch band {
	case riskSeverityHigh:
		s.high++
	case riskSeverityMedium:
		s.med++
	case riskSeverityLow:
		s.low++
	}
}

func (s riskStreamSummary) total() int {
	return s.high + s.med + s.low
}

func classifyRiskSeverityBand(assessment riskanalysis.RiskAssessment) riskSeverityBand {
	level := strings.TrimSpace(assessment.RiskLevel)
	switch level {
	case riskanalysis.RiskLevelCritical, riskanalysis.RiskLevelHigh:
		return riskSeverityHigh
	case riskanalysis.RiskLevelMedium:
		return riskSeverityMedium
	case riskanalysis.RiskLevelLow:
		return riskSeverityLow
	case riskanalysis.RiskLevelPending, riskanalysis.RiskLevelSuspiciousOffline:
		return riskSeverityMedium
	}

	switch strings.ToLower(level) {
	case "critical", "high":
		return riskSeverityHigh
	case "medium":
		return riskSeverityMedium
	case "low":
		return riskSeverityLow
	}

	switch {
	case assessment.RiskScore > 80:
		return riskSeverityHigh
	case assessment.RiskScore > 50:
		return riskSeverityMedium
	case assessment.RiskScore > 20:
		return riskSeverityLow
	default:
		return riskSeverityNone
	}
}

func supportsANSIColorOutput(out io.Writer) bool {
	if out == nil {
		return false
	}
	fdWriter, ok := out.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	fd := fdWriter.Fd()
	if !terminalSupportsCursorMotion(fd) {
		return false
	}
	return enableProgressANSIMode(fd)
}

func riskSeverityLabel(band riskSeverityBand, colorEnabled bool) string {
	label := "[LOW]"
	color := "32" // green
	switch band {
	case riskSeverityHigh:
		label = "[HIGH]"
		color = "31" // red
	case riskSeverityMedium:
		label = "[MEDIUM]"
		color = "38;5;208" // orange
	case riskSeverityLow:
		label = "[LOW]"
		color = "32" // green
	}
	if !colorEnabled {
		return label
	}
	return "\x1b[" + color + "m" + label + "\x1b[0m"
}

func formatRiskStreamLine(result riskanalysis.AnalysisResult, band riskSeverityBand, colorEnabled bool) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	path := strings.TrimSpace(result.TargetPath)
	if path == "" {
		path = "<unknown>"
	}
	path = compactMiddle(path, 72)
	size := formatRiskFileSize(result.FileSize)
	sha256 := compactSHA256(result.Hashes.Sha256)
	if sha256 == "" {
		sha256 = "-"
	}
	line := fmt.Sprintf("[%s] %s path=%s | size=%s | sha256=%s", timestamp, riskSeverityLabel(band, colorEnabled), path, size, sha256)
	if rule := extractRiskRuleName(result); rule != "" {
		line += " | rule=" + compactTail(rule, 48)
	}
	return line
}

func compactSHA256(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return ""
	}
	if len(normalized) <= 24 {
		return normalized
	}
	return normalized[:12] + "..." + normalized[len(normalized)-8:]
}

func compactMiddle(value string, maxLen int) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" || maxLen <= 0 {
		return normalized
	}
	runes := []rune(normalized)
	if len(runes) <= maxLen || maxLen <= 8 {
		return normalized
	}
	head := int(float64(maxLen-3) * 0.6)
	if head < 3 {
		head = 3
	}
	tail := maxLen - 3 - head
	if tail < 2 {
		tail = 2
		head = maxLen - 3 - tail
	}
	return string(runes[:head]) + "..." + string(runes[len(runes)-tail:])
}

func compactTail(value string, maxLen int) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" || maxLen <= 0 {
		return normalized
	}
	runes := []rune(normalized)
	if len(runes) <= maxLen || maxLen <= 4 {
		return normalized
	}
	return string(runes[:maxLen-3]) + "..."
}

func formatRiskFileSize(size *int64) string {
	if size == nil || *size < 0 {
		return "-"
	}
	raw := float64(*size)
	units := []string{"B", "KB", "MB", "GB", "TB"}
	unit := 0
	for raw >= 1024 && unit < len(units)-1 {
		raw /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", *size, units[unit])
	}
	return fmt.Sprintf("%.1f %s", raw, units[unit])
}

func extractRiskRuleName(result riskanalysis.AnalysisResult) string {
	if result.LocalAnalysis != nil {
		for _, match := range result.LocalAnalysis.YaraResults {
			rule := strings.TrimSpace(match.RuleName)
			if rule != "" {
				return rule
			}
		}
	}
	if result.CloudAnalysis != nil {
		for _, label := range result.CloudAnalysis.ThreatLabels {
			normalized := strings.TrimSpace(label)
			if normalized != "" {
				return normalized
			}
		}
	}
	return ""
}

func printRiskProgressLine(progress *terminalProgress, line string) {
	if progress != nil {
		progress.PrintLine(line)
		return
	}
	if strings.TrimSpace(line) == "" {
		fmt.Fprintln(os.Stderr)
		return
	}
	fmt.Fprintln(os.Stderr, line)
}

func printRiskStreamSummary(progress *terminalProgress, summary riskanalysis.Summary) {
	if summary.Total == 0 {
		return
	}
	printRiskProgressLine(progress, "")
	printRiskProgressLine(progress, "Risk Summary:")
	printRiskProgressLine(progress, fmt.Sprintf("Total risky files: %d", summary.Total))
	if summary.Critical > 0 {
		printRiskProgressLine(progress, fmt.Sprintf("CRITICAL: %d", summary.Critical))
	}
	if summary.High > 0 {
		printRiskProgressLine(progress, fmt.Sprintf("HIGH: %d", summary.High))
	}
	if summary.Medium > 0 {
		printRiskProgressLine(progress, fmt.Sprintf("MEDIUM: %d", summary.Medium))
	}
	if summary.Low > 0 {
		printRiskProgressLine(progress, fmt.Sprintf("LOW: %d", summary.Low))
	}
	if summary.Pending > 0 {
		printRiskProgressLine(progress, fmt.Sprintf("PENDING: %d", summary.Pending))
	}
	if summary.SuspiciousOffline > 0 {
		printRiskProgressLine(progress, fmt.Sprintf("SUSPICIOUS_OFFLINE: %d", summary.SuspiciousOffline))
	}
}

func analyzeRiskResults(opts riskOptions, overrideRecords []riskanalysis.ScanRecord, progress *terminalProgress) ([]riskanalysis.AnalysisResult, error) {
	mode, err := resolveRiskMode(opts.Mode)
	if err != nil {
		return nil, err
	}
	records := overrideRecords
	if records == nil {
		records, err = resolveRiskScanRecords(opts)
		if err != nil {
			return nil, err
		}
	}
	if len(records) == 0 {
		return []riskanalysis.AnalysisResult{}, nil
	}

	currentHostname, _ := os.Hostname()

	var localMatcher riskanalysis.LocalMatcher
	if mode == riskanalysis.ModeLocalOnly || mode == riskanalysis.ModeFast || mode == riskanalysis.ModeSmart || mode == riskanalysis.ModeDeep {
		rules := opts.YaraRules
		if rules == "" {
			if envRules := os.Getenv("C_EYES_YARA_RULES"); envRules != "" {
				rules = envRules
			}
		}
		if rules == "" {
			rules = defaultRulesPath()
		}
		if rules == "" {
			if mode == riskanalysis.ModeLocalOnly {
				return nil, fmt.Errorf("no available YARA rules found")
			}
			fmt.Fprintln(os.Stderr, "Hint: no YARA rule provided, skipping local matching")
		}
		if rules != "" {
			engine, err := riskanalysis.NewYaraXEngine(riskanalysis.YaraXConfig{
				RulesPath:     rules,
				ReadChunkSize: opts.YaraReadChunk,
			})
			if err != nil {
				if mode == riskanalysis.ModeLocalOnly {
					return nil, fmt.Errorf("local YARA engine initialization failed: %w", err)
				}
				fmt.Fprintf(os.Stderr, "local YARA engine initialization failed: %v\n", err)
			} else {
				if warning := riskanalysis.YaraXEngineWarning(engine); warning != "" {
					if mode == riskanalysis.ModeLocalOnly {
						return nil, fmt.Errorf("local YARA engine warning: %s", warning)
					}
					fmt.Fprintf(os.Stderr, "local YARA engine warning: %s\n", warning)
				} else {
					localMatcher = &riskanalysis.YaraXMatcher{
						Engine:          engine,
						CurrentHostname: currentHostname,
					}
				}
			}
		}
	}

	var cloudClient riskanalysis.CloudClient
	if mode != riskanalysis.ModeLocalOnly {
		cfg, cfgPath, cfgErr := riskanalysis.LoadCloudConfig()
		if cfgErr != nil {
			if cfgPath != "" {
				return nil, fmt.Errorf("failed to load cloud config (%s): %w", cfgPath, cfgErr)
			}
			return nil, fmt.Errorf("failed to load cloud config: %w", cfgErr)
		}
		providers := []string{"virustotal", "hybrid_analysis", "malwarebazaar", "otx", "triage"}
		clients := make([]riskanalysis.CloudProviderClient, 0, len(providers))
		uploadPolicy := make(map[string]bool, len(providers))
		for _, provider := range providers {
			providerCfg := providerConfigFromFile(cfg, provider)
			uploadPolicy[provider] = providerCfg.UploadEnabledOrDefault(provider)
			apiKey := providerCfg.APIKey
			if apiKey == "" {
				apiKey = os.Getenv("C_EYES_CLOUD_API_KEY")
			}
			if apiKey == "" {
				apiKey = providerEnvFallback(provider)
			}
			if apiKey == "" {
				// All current hash/cloud providers require API keys.
				// Skipping empty-key providers avoids repeated no-op calls without changing verdict quality.
				fmt.Fprintf(os.Stderr, "cloud provider %s has no API key configured, skipping\n", provider)
				continue
			}

			baseURL := providerCfg.BaseURL
			proxyURL := providerCfg.ProxyURL
			if proxyURL == "" && cfg != nil && cfg.ProxyURL != "" {
				proxyURL = cfg.ProxyURL
			}

			rateLimit := 2 * time.Second
			if providerCfg.RateLimit != "" {
				if d, err := providerCfg.RateLimitDuration(); err == nil {
					rateLimit = d
				}
			}
			if opts.CloudUpload && providerCfg.UploadRateLimit != "" {
				if d, err := providerCfg.UploadRateLimitDuration(); err == nil {
					rateLimit = d
				}
			}

			timeout := 10 * time.Second
			if providerCfg.Timeout != "" {
				if d, err := providerCfg.TimeoutDuration(); err == nil {
					timeout = d
				}
			}

			cacheTTL := 10 * time.Minute
			if providerCfg.CacheTTL != "" {
				if d, err := providerCfg.CacheTTLDuration(); err == nil {
					cacheTTL = d
				}
			}

			var (
				client riskanalysis.CloudClient
				err    error
			)
			switch provider {
			case "virustotal":
				client, err = riskanalysis.NewVirusTotalClient(riskanalysis.VirusTotalConfig{
					APIKey:              apiKey,
					BaseURL:             baseURL,
					ProxyURL:            proxyURL,
					Timeout:             timeout,
					RateLimit:           rateLimit,
					CacheTTL:            cacheTTL,
					TokenBucketCapacity: 4,
					TokenBucketWindow:   time.Minute,
				})
			case "hybrid_analysis":
				client, err = riskanalysis.NewHybridAnalysisClient(riskanalysis.HybridAnalysisConfig{
					APIKey:    apiKey,
					BaseURL:   baseURL,
					ProxyURL:  proxyURL,
					Timeout:   timeout,
					RateLimit: rateLimit,
					CacheTTL:  cacheTTL,
				})
			case "malwarebazaar":
				client, err = riskanalysis.NewMalwareBazaarClient(riskanalysis.MalwareBazaarConfig{
					APIKey:    apiKey,
					BaseURL:   baseURL,
					ProxyURL:  proxyURL,
					Timeout:   timeout,
					RateLimit: rateLimit,
					CacheTTL:  cacheTTL,
				})
			case "otx":
				client, err = riskanalysis.NewOTXClient(riskanalysis.OTXConfig{
					APIKey:    apiKey,
					BaseURL:   baseURL,
					ProxyURL:  proxyURL,
					Timeout:   timeout,
					RateLimit: rateLimit,
					CacheTTL:  cacheTTL,
				})
			case "triage":
				client, err = riskanalysis.NewTriageClient(riskanalysis.TriageConfig{
					APIKey:    apiKey,
					BaseURL:   baseURL,
					ProxyURL:  proxyURL,
					Timeout:   timeout,
					RateLimit: rateLimit,
					CacheTTL:  cacheTTL,
				})
			default:
				continue
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "initialize cloud provider %s failed: %v\n", provider, err)
				continue
			}
			clients = append(clients, riskanalysis.CloudProviderClient{Name: provider, Client: client})
		}

		cloudClient = &riskanalysis.MultiCloudClient{
			Providers:    clients,
			UploadPolicy: uploadPolicy,
		}
	}

	policy, _, policyErr := riskanalysis.LoadWhitelistPolicy()
	if policyErr != nil {
		defaultPolicy := riskanalysis.DefaultWhitelistPolicy()
		policy = &defaultPolicy
	}
	_, projectWhitelistErr := applyProjectWhitelistPolicy(policy)
	if projectWhitelistErr != nil && progress != nil {
		progress.PrintLine(fmt.Sprintf("[WARN] risk analyze: project whitelist setup failed: %v", projectWhitelistErr))
	}
	hashRepo, _ := riskanalysis.NewAuthorityHashRepo(policy)
	whitelistEngine := riskanalysis.NewDefaultWhitelistEngine(policy, hashRepo, nil)

	analyzer := riskanalysis.Analyzer{
		Local:                    localMatcher,
		Cloud:                    cloudClient,
		Whitelist:                whitelistEngine,
		LocalWeight:              opts.LocalWeight,
		CloudWeight:              opts.CloudWeight,
		FastTimeout:              2 * time.Second,
		SmartTimeout:             10 * time.Second,
		DeepTimeout:              15 * time.Minute,
		CloudUploadEnabled:       opts.CloudUpload,
		CloudUploadConcurrency:   opts.CloudUploadConcurrency,
		CloudUploadWait:          opts.CloudUploadWait,
		CloudUploadSubmitTimeout: opts.CloudUploadSubmitTO,
		CloudUploadPollInterval:  opts.CloudUploadPollEvery,
		CloudUploadMaxSize:       opts.CloudUploadMaxSize,
		AnalysisMaxDuration:      opts.AnalysisMaxDuration,
	}
	colorEnabled := supportsANSIColorOutput(os.Stderr)
	progressLimiter := newRiskProgressUpdateLimiter(progress)
	if progress != nil {
		analyzer.OnDiagnostic = func(message string) {
			progress.PrintLine(fmt.Sprintf("risk analyze: %s", message))
		}
		analyzer.OnProgress = func(event riskanalysis.ProgressEvent) {
			if !progressLimiter.allow(event) {
				return
			}
			progress.Update(event.Index, event.Total, event.Stage)
		}
		analyzer.OnResult = func(result riskanalysis.AnalysisResult) {
			band := classifyRiskSeverityBand(result.RiskAssessment)
			if band == riskSeverityNone {
				return
			}
			progress.PrintLine(formatRiskStreamLine(result, band, colorEnabled))
		}
	}

	results, analyzeErr := analyzer.Analyze(context.Background(), records, mode)
	if analyzeErr != nil {
		return nil, analyzeErr
	}
	printRiskStreamSummary(progress, riskanalysis.BuildSummary(results))
	return results, nil
}

type outputWriteSet struct {
	json func(path string, payload any) error
	csv  func(path string, rows []map[string]any) error
	xlsx func(path string, rows []map[string]any) error
}

type permissionFallbackPrompt func(outputPath string, writeErr error, stdin io.Reader, stderr io.Writer) (bool, error)

var defaultPermissionFallbackPrompt permissionFallbackPrompt = func(outputPath string, writeErr error, stdin io.Reader, stderr io.Writer) (bool, error) {
	fmt.Fprintf(stderr, "[ERROR] Cannot write output file: %s\n", outputPath)
	fmt.Fprintf(stderr, "        Reason: %s\n", compactWriteErrorMessage(outputPath, writeErr))
	fmt.Fprint(stderr, "        Print scan results as JSON in this terminal? [y/N]: ")
	if stdin == nil {
		fmt.Fprintln(stderr)
		return false, nil
	}

	reader := bufio.NewReader(stdin)
	answer, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	normalized := strings.TrimSpace(strings.ToLower(answer))
	return normalized == "y" || normalized == "yes", nil
}

func compactWriteErrorMessage(outputPath string, writeErr error) string {
	if writeErr == nil {
		return "unknown error"
	}
	msg := strings.TrimSpace(writeErr.Error())
	prefix := "open " + outputPath + ": "
	if strings.HasPrefix(msg, prefix) {
		trimmed := strings.TrimSpace(msg[len(prefix):])
		if trimmed != "" {
			return trimmed
		}
	}
	return msg
}

func compactScanTargetErrorMessage(targetPath string, scanErr error) string {
	if scanErr == nil {
		return "unknown error"
	}

	msg := strings.TrimSpace(scanErr.Error())
	if targetPath == "" {
		return msg
	}

	prefixes := []string{
		"open " + targetPath + ": ",
		"stat " + targetPath + ": ",
		"lstat " + targetPath + ": ",
		"CreateFile " + targetPath + ": ",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(msg, prefix) {
			trimmed := strings.TrimSpace(msg[len(prefix):])
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return msg
}

func emitOutput(payload any, outputPath string) error {
	return emitOutputWithPrompt(payload, outputPath, outputWriteSet{}, os.Stdout, os.Stderr, os.Stdin, defaultPermissionFallbackPrompt)
}

func emitOutputWithWriteSet(payload any, outputPath string, writers outputWriteSet, stdout io.Writer, stderr io.Writer) error {
	return emitOutputWithPrompt(payload, outputPath, writers, stdout, stderr, os.Stdin, defaultPermissionFallbackPrompt)
}

func emitOutputWithPrompt(payload any, outputPath string, writers outputWriteSet, stdout io.Writer, stderr io.Writer, stdin io.Reader, prompt permissionFallbackPrompt) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	defaultCSVWriterUsed := writers.csv == nil
	if writers.json == nil {
		writers.json = writeJSONFile
	}
	if writers.csv == nil {
		writers.csv = writeCSVFile
	}
	if writers.xlsx == nil {
		writers.xlsx = writeXLSXFile
	}
	if prompt == nil {
		prompt = defaultPermissionFallbackPrompt
	}

	resolvedOutputPath, autoGenerated, err := resolveOutputPath(outputPath)
	if err != nil {
		return err
	}

	if strings.TrimSpace(resolvedOutputPath) == "" {
		return writeJSONToWriter(stdout, payload)
	}

	format, err := detectOutputFormat(resolvedOutputPath)
	if err != nil {
		return err
	}

	var writeErr error
	writtenPaths := []string{resolvedOutputPath}
	switch format {
	case "json":
		writeErr = writers.json(resolvedOutputPath, payload)
	case "csv":
		rows, err := payloadToRows(payload)
		if err != nil {
			return err
		}
		if shouldWriteUTF8BOMForBenchmarkFiles(payload) && defaultCSVWriterUsed {
			writeErr = writeCSVFileWithBOM(resolvedOutputPath, rows)
		} else {
			writeErr = writers.csv(resolvedOutputPath, rows)
		}
		if writeErr == nil {
			summaryPath, summaryErr := writeBenchmarkSummaryCSVSidecar(resolvedOutputPath, payload)
			if summaryErr != nil {
				return summaryErr
			}
			if strings.TrimSpace(summaryPath) != "" {
				writtenPaths = append(writtenPaths, summaryPath)
			}
		}
	case "xlsx":
		if summaryPayload, ok := payload.(riskanalysis.SummaryResult); ok {
			if err := writeRiskExcel(resolvedOutputPath, summaryPayload); err != nil {
				writeErr = err
				break
			}
			writtenPaths = []string{resolvedOutputPath}
			break
		}
		if summaryPayload, ok := payload.(*riskanalysis.SummaryResult); ok {
			if err := writeRiskExcel(resolvedOutputPath, *summaryPayload); err != nil {
				writeErr = err
				break
			}
			writtenPaths = []string{resolvedOutputPath}
			break
		}
		rows, err := payloadToRows(payload)
		if err != nil {
			return err
		}
		writtenPaths, writeErr = writeShardedXLSXFiles(resolvedOutputPath, rows, xlsxMaxRows-1, writers.xlsx)
		if writeErr == nil {
			if summaryErr := appendBenchmarkSummarySheetToXLSXFiles(writtenPaths, payload); summaryErr != nil {
				return summaryErr
			}
		}
	default:
		return fmt.Errorf("invalid argument: unsupported output format")
	}

	if writeErr != nil {
		if isPermissionDeniedError(writeErr) {
			allowJSONFallback, promptErr := prompt(resolvedOutputPath, writeErr, stdin, stderr)
			if promptErr != nil {
				return fmt.Errorf("output fallback prompt failed: %w", promptErr)
			}
			if allowJSONFallback {
				if err := writeJSONToWriter(stdout, payload); err != nil {
					return fmt.Errorf("output fallback failed: %w", err)
				}
				return nil
			}
		}
		return writeErr
	}

	emitGeneratedFileHints(stderr, writtenPaths, autoGenerated)
	return nil
}

func emitGeneratedFileHints(w io.Writer, writtenPaths []string, autoGenerated bool) {
	if w == nil {
		return
	}
	if !autoGenerated && len(writtenPaths) <= 1 {
		return
	}
	for _, path := range writtenPaths {
		fmt.Fprintf(w, "generated file: %s\n", filepath.Base(path))
	}
}

func writeJSONToWriter(w io.Writer, payload any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func isPermissionDeniedError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsPermission(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "access is denied")
}

func detectOutputFormat(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("invalid argument: output path cannot be empty")
	}
	ext := strings.ToLower(filepath.Ext(trimmed))
	switch ext {
	case ".json":
		return "json", nil
	case ".csv":
		return "csv", nil
	case ".xlsx":
		return "xlsx", nil
	default:
		return "", fmt.Errorf("invalid argument: -o only supports .json/.csv/.xlsx suffix")
	}
}

func resolveOutputPath(outputPath string) (string, bool, error) {
	trimmed := strings.TrimSpace(outputPath)
	if trimmed == "" {
		return "", false, nil
	}
	if trimmed != autoExcelOutputSentinel && trimmed != autoSBOMOutputSentinel {
		return trimmed, false, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", false, err
	}
	var next string
	if trimmed == autoSBOMOutputSentinel {
		next, err = nextAutoJSONOutputPath(cwd)
	} else {
		next, err = nextAutoExcelOutputPath(cwd)
	}
	if err != nil {
		return "", false, err
	}
	return next, true, nil
}

func nextAutoExcelOutputPath(dir string) (string, error) {
	resultPath := filepath.Join(dir, "result.xlsx")
	result1Path := filepath.Join(dir, "result1.xlsx")

	if fileExists(result1Path) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		maxIdx := 1
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(entry.Name()))
			matches := autoResultIndexPattern.FindStringSubmatch(name)
			if len(matches) != 2 {
				continue
			}
			idx, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}
			if idx > maxIdx {
				maxIdx = idx
			}
		}
		return filepath.Join(dir, fmt.Sprintf("result%d.xlsx", maxIdx+1)), nil
	}

	if fileExists(resultPath) {
		return result1Path, nil
	}
	return resultPath, nil
}

func nextAutoJSONOutputPath(dir string) (string, error) {
	resultPath := filepath.Join(dir, "result.json")
	result1Path := filepath.Join(dir, "result1.json")

	if fileExists(result1Path) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		maxIdx := 1
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(entry.Name()))
			matches := autoJSONResultIndexPattern.FindStringSubmatch(name)
			if len(matches) != 2 {
				continue
			}
			idx, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}
			if idx > maxIdx {
				maxIdx = idx
			}
		}
		return filepath.Join(dir, fmt.Sprintf("result%d.json", maxIdx+1)), nil
	}

	if fileExists(resultPath) {
		return result1Path, nil
	}
	return resultPath, nil
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func writeShardedXLSXFiles(path string, rows []map[string]any, rowsPerFile int, writer func(string, []map[string]any) error) ([]string, error) {
	if writer == nil {
		return nil, fmt.Errorf("xlsx writer is not configured")
	}
	if rowsPerFile <= 0 {
		return nil, fmt.Errorf("invalid xlsx rows-per-file limit: %d", rowsPerFile)
	}

	if len(rows) == 0 {
		if err := writer(path, rows); err != nil {
			return nil, err
		}
		return []string{path}, nil
	}

	totalParts := (len(rows) + rowsPerFile - 1) / rowsPerFile
	uniformPartNames := totalParts > 1
	writtenPaths := make([]string, 0, totalParts)
	for part, start := 1, 0; start < len(rows); part++ {
		end := start + rowsPerFile
		if end > len(rows) {
			end = len(rows)
		}
		partPath := xlsxShardPath(path, part, uniformPartNames)
		if err := writer(partPath, rows[start:end]); err != nil {
			return nil, err
		}
		writtenPaths = append(writtenPaths, partPath)
		start = end
	}
	return writtenPaths, nil
}

func xlsxShardPath(path string, part int, forcePartSuffix bool) string {
	if part <= 1 && !forcePartSuffix {
		return path
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	return fmt.Sprintf("%s_part%d%s", base, part, ext)
}

func writeJSONFile(path string, payload any) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	if shouldWriteUTF8BOMForBenchmarkFiles(payload) {
		if _, err := file.Write(utf8BOM); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func payloadToRows(payload any) ([]map[string]any, error) {
	if payload == nil {
		return nil, nil
	}

	switch v := payload.(type) {
	case scanAggregateResult:
		return append([]map[string]any{}, v.Rows...), nil
	case *scanAggregateResult:
		if v == nil {
			return nil, nil
		}
		return append([]map[string]any{}, v.Rows...), nil
	case []map[string]any:
		return append([]map[string]any{}, v...), nil
	case benchmark.ScanResult:
		return benchmarkRowsForDisplay(v.Rows), nil
	case *benchmark.ScanResult:
		if v == nil {
			return nil, nil
		}
		return benchmarkRowsForDisplay(v.Rows), nil
	}

	rv := reflect.ValueOf(payload)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, nil
		}
		rv = rv.Elem()
	}

	if rv.Kind() == reflect.Struct {
		if _, ok := payload.(riskanalysis.SummaryResult); ok {
			field := rv.FieldByName("Results")
			if field.IsValid() && field.Kind() == reflect.Slice {
				return anySliceToMapRows(field.Interface())
			}
		}
		if _, ok := payload.(*riskanalysis.SummaryResult); ok {
			field := rv.FieldByName("Results")
			if field.IsValid() && field.Kind() == reflect.Slice {
				return anySliceToMapRows(field.Interface())
			}
		}
		field := rv.FieldByName("Rows")
		if field.IsValid() && field.Kind() == reflect.Slice {
			return anySliceToMapRows(field.Interface())
		}
	}

	if rv.Kind() == reflect.Slice {
		return anySliceToMapRows(rv.Interface())
	}

	row, err := anyToMap(payload)
	if err != nil {
		return nil, err
	}
	return []map[string]any{row}, nil
}

func benchmarkRowsForDisplay(rows []benchmark.Row) []map[string]any {
	displayRows := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		display := map[string]any{
			"检查项编号": benchmarkDisplayCheckID(row.Template, row.CheckID),
			"检查项名称": row.CheckName,
			"分类":    strings.TrimSpace(row.Category),
			"基线要求":  row.Expected,
			"实际结果":  row.Actual,
			"判定结果":  benchmarkDisplayStatus(row.Status, row.StatusReason),
		}
		if severity := benchmarkDisplaySeverityForRow(row.Status, row.StatusReason, row.Severity); severity != "" {
			display["风险等级"] = severity
		}
		if recommendation := benchmarkDisplayRecommendation(row.Status, row.StatusReason, row.Recommendation); recommendation != "" {
			display["整改建议"] = recommendation
		}
		displayRows = append(displayRows, display)
	}
	return displayRows
}

func benchmarkDisplayCheckID(template string, raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	code := benchmarkTemplateCode(template)
	if code == "" {
		return trimmed
	}
	if isDigitsOnly(trimmed) {
		if parsed, err := strconv.Atoi(trimmed); err == nil {
			return fmt.Sprintf("%s-DISP-%03d", code, parsed)
		}
	}
	parts := strings.SplitN(trimmed, "-", 2)
	if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
		return fmt.Sprintf("%s-%s", code, strings.TrimSpace(parts[1]))
	}
	return trimmed
}

func benchmarkTemplateCode(template string) string {
	switch benchmarkNormalizeLowerTrim(template) {
	case "windows":
		return "WIN"
	case "linux":
		return "LNX"
	case "euleros":
		return "EUL"
	case "kylin":
		return "KYL"
	default:
		return ""
	}
}

func isDigitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func benchmarkNormalizeLowerTrim(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func benchmarkDisplayStatus(status string, statusReason string) string {
	switch benchmarkNormalizeLowerTrim(status) {
	case "pass":
		return "符合"
	case "fail":
		return "不符合"
	case "unknown":
		if benchmarkNormalizeLowerTrim(statusReason) == "informational_check" {
			return "信息项"
		}
		return "待确认"
	default:
		return strings.TrimSpace(status)
	}
}

func benchmarkDisplaySeverity(severity string) string {
	switch benchmarkNormalizeLowerTrim(severity) {
	case "critical", "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	case "info", "informational":
		return "提示"
	default:
		return strings.TrimSpace(severity)
	}
}

func benchmarkDisplaySeverityForRow(status string, statusReason string, severity string) string {
	if benchmarkNormalizeLowerTrim(status) != "fail" {
		return ""
	}
	return benchmarkDisplaySeverity(severity)
}

func benchmarkDisplayRecommendation(status string, statusReason string, recommendation string) string {
	if benchmarkNormalizeLowerTrim(status) != "fail" {
		return ""
	}
	return strings.TrimSpace(recommendation)
}

func writeCSVFile(path string, rows []map[string]any) error {
	return writeCSVFileInternal(path, rows, false)
}

func writeCSVFileWithBOM(path string, rows []map[string]any) error {
	return writeCSVFileInternal(path, rows, true)
}

func writeCSVFileInternal(path string, rows []map[string]any, writeBOM bool) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	if writeBOM {
		if _, err := file.Write(utf8BOM); err != nil {
			return err
		}
	}
	flatRows, headers := flattenRowsAndHeaders(rows)
	writer := csv.NewWriter(file)
	if err := writer.Write(headers); err != nil {
		return err
	}
	for _, flat := range flatRows {
		record := make([]string, len(headers))
		for i, h := range headers {
			record[i] = flat[h]
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func shouldWriteUTF8BOMForBenchmarkFiles(payload any) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	switch payload.(type) {
	case benchmark.ScanResult, *benchmark.ScanResult:
		return true
	default:
		return false
	}
}

func writeXLSXFile(path string, rows []map[string]any) error {
	file := excelize.NewFile()
	sheet := "results"
	file.SetSheetName(file.GetSheetName(0), sheet)

	flatRows, headers := flattenRowsAndHeaders(rows)
	if err := validateXLSXShape(len(flatRows), len(headers)); err != nil {
		return err
	}
	for i, h := range headers {
		cell, err := excelize.CoordinatesToCellName(i+1, 1)
		if err != nil {
			return fmt.Errorf("xlsx coordinate conversion failed at row=1 col=%d: %w", i+1, err)
		}
		if err := file.SetCellValue(sheet, cell, h); err != nil {
			return err
		}
	}
	for r, flat := range flatRows {
		for c, h := range headers {
			cell, err := excelize.CoordinatesToCellName(c+1, r+2)
			if err != nil {
				return fmt.Errorf("xlsx coordinate conversion failed at row=%d col=%d: %w", r+2, c+1, err)
			}
			if err := file.SetCellValue(sheet, cell, flat[h]); err != nil {
				return err
			}
		}
	}
	return file.SaveAs(path)
}

type benchmarkSummaryMetricRow struct {
	Metric  string
	Display string
}

func printBenchmarkSummary(progress *terminalProgress, result benchmark.ScanResult) {
	if progress == nil {
		return
	}
	progress.PrintLine("benchmark summary:")
	progress.PrintLine(fmt.Sprintf("template: %s", strings.TrimSpace(result.Template)))
	progress.PrintLine("")
	progress.PrintLine("counts")
	for _, row := range buildBenchmarkSummaryCLICountRows(result.Summary) {
		progress.PrintLine(fmt.Sprintf("  %-18s %s", row.Metric, row.Display))
	}
	progress.PrintLine("")
	progress.PrintLine("rate")
	for _, row := range buildBenchmarkSummaryCLIRateRows(result.Summary) {
		progress.PrintLine(fmt.Sprintf("  %-18s %s", row.Metric, row.Display))
	}
}

func extractBenchmarkSummary(payload any) (benchmark.Summary, bool) {
	switch typed := payload.(type) {
	case benchmark.ScanResult:
		return typed.Summary, true
	case *benchmark.ScanResult:
		if typed == nil {
			return benchmark.Summary{}, false
		}
		return typed.Summary, true
	default:
		return benchmark.Summary{}, false
	}
}

func buildBenchmarkSummaryMetricRows(summary benchmark.Summary, localized bool) []benchmarkSummaryMetricRow {
	metric := func(english, chinese string) string {
		if localized {
			return chinese
		}
		return english
	}
	rate := func(value float64) string {
		return fmt.Sprintf("%.2f%%", value*100)
	}
	return []benchmarkSummaryMetricRow{
		{Metric: metric("total", "总检查项数"), Display: strconv.Itoa(summary.Total)},
		{Metric: metric("pass", "符合项"), Display: strconv.Itoa(summary.Pass)},
		{Metric: metric("fail", "不符合项"), Display: strconv.Itoa(summary.Fail)},
		{Metric: metric("informational", "信息项"), Display: strconv.Itoa(summary.Informational)},
		{Metric: metric("pending", "待确认项"), Display: strconv.Itoa(summary.Pending)},
		{Metric: metric("evaluated", "可判定项"), Display: strconv.Itoa(summary.Evaluated)},
		{Metric: metric("compliance_rate", "合规率"), Display: rate(summary.ComplianceRate)},
		{Metric: metric("informational_rate", "信息项占比"), Display: rate(summary.InformationalRate)},
		{Metric: metric("pending_rate", "待确认项占比"), Display: rate(summary.PendingRate)},
	}
}

func writeBenchmarkSummaryCSVSidecar(csvPath string, payload any) (string, error) {
	summary, ok := extractBenchmarkSummary(payload)
	if !ok {
		return "", nil
	}
	summaryPath := strings.TrimSuffix(csvPath, filepath.Ext(csvPath)) + ".summary.csv"
	file, err := os.Create(summaryPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	if shouldWriteUTF8BOMForBenchmarkFiles(payload) {
		if _, err := file.Write(utf8BOM); err != nil {
			return "", err
		}
	}
	writer := csv.NewWriter(file)
	for _, row := range buildBenchmarkSummaryMetricRows(summary, true) {
		if err := writer.Write([]string{row.Metric, row.Display}); err != nil {
			return "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}
	return summaryPath, nil
}

func appendBenchmarkSummarySheetToXLSXFiles(paths []string, payload any) error {
	summary, ok := extractBenchmarkSummary(payload)
	if !ok {
		return nil
	}
	for _, path := range paths {
		if err := appendBenchmarkSummarySheet(path, summary); err != nil {
			return err
		}
	}
	return nil
}

func appendBenchmarkSummarySheet(path string, summary benchmark.Summary) error {
	file, err := excelize.OpenFile(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	const summarySheet = "summary"
	const resultsSheet = "results"
	for _, name := range file.GetSheetList() {
		if name == summarySheet {
			if err := file.DeleteSheet(summarySheet); err != nil {
				return err
			}
			break
		}
	}
	sheetIdx, err := file.NewSheet(summarySheet)
	if err != nil {
		return err
	}
	rows := buildBenchmarkSummaryMetricRows(summary, true)
	for i, row := range rows {
		r := i + 1
		if err := file.SetCellValue(summarySheet, fmt.Sprintf("A%d", r), row.Metric); err != nil {
			return err
		}
		if err := file.SetCellValue(summarySheet, fmt.Sprintf("B%d", r), row.Display); err != nil {
			return err
		}
	}
	if err := file.SetColWidth(summarySheet, "A", "A", 24); err != nil {
		return err
	}
	if err := file.SetColWidth(summarySheet, "B", "B", 16); err != nil {
		return err
	}
	activeSheetIdx := sheetIdx
	if resultsIdx, err := file.GetSheetIndex(resultsSheet); err == nil && resultsIdx >= 0 {
		activeSheetIdx = resultsIdx
	}
	file.SetActiveSheet(activeSheetIdx)
	return file.Save()
}
func validateXLSXShape(dataRows int, columns int) error {
	if columns > xlsxMaxColumns {
		return fmt.Errorf("xlsx output exceeds column limit (%d > %d); use -o <file>.csv or -o <file>.json", columns, xlsxMaxColumns)
	}
	totalRows := dataRows + 1 // include header
	if totalRows > xlsxMaxRows {
		return fmt.Errorf("xlsx output exceeds row limit (%d > %d); use -o <file>.csv or -o <file>.json", totalRows, xlsxMaxRows)
	}
	return nil
}

func collectHeaders(rows []map[string]any) []string {
	_, headers := flattenRowsAndHeaders(rows)
	return headers
}

func flattenRowsAndHeaders(rows []map[string]any) ([]map[string]string, []string) {
	headerSet := make(map[string]struct{})
	flatRows := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		flat := flattenRow(row)
		flatRows = append(flatRows, flat)
		for key := range flat {
			headerSet[key] = struct{}{}
		}
	}
	headers := make([]string, 0, len(headerSet))
	for key := range headerSet {
		headers = append(headers, key)
	}
	headers = orderDisplayHeaders(headers)
	return flatRows, headers
}

func orderDisplayHeaders(headers []string) []string {
	benchmarkOrder := []string{
		"检查项编号",
		"检查项名称",
		"分类",
		"基线要求",
		"实际结果",
		"判定结果",
		"风险等级",
		"整改建议",
	}
	generalOrder := []string{
		"displayIp",
		"hostname",
		"name",
		"moduleName",
		"path",
		"execPath",
		"target_path",
		"version",
		"status",
		"proto",
		"port",
		"bindIp",
		"pid",
		"uname",
		"gname",
	}
	orderIndex := make(map[string]int, len(benchmarkOrder))
	for i, key := range benchmarkOrder {
		orderIndex[key] = i
	}
	base := len(benchmarkOrder)
	for i, key := range generalOrder {
		if _, exists := orderIndex[key]; !exists {
			orderIndex[key] = base + i
		}
	}
	sort.Slice(headers, func(i, j int) bool {
		li, lok := orderIndex[headers[i]]
		lj, jok := orderIndex[headers[j]]
		switch {
		case lok && jok:
			return li < lj
		case lok:
			return true
		case jok:
			return false
		default:
			return headers[i] < headers[j]
		}
	})
	return headers
}

func flattenRow(row map[string]any) map[string]string {
	flat := map[string]string{}
	var walk func(prefix string, value any)
	walk = func(prefix string, value any) {
		if value == nil {
			flat[prefix] = ""
			return
		}
		switch typed := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				next := key
				if prefix != "" {
					next = prefix + "." + key
				}
				walk(next, typed[key])
			}
		case []any, []string, []int, []int64, []bool:
			bytes, _ := json.Marshal(typed)
			flat[prefix] = string(bytes)
		default:
			rv := reflect.ValueOf(value)
			switch rv.Kind() {
			case reflect.Slice, reflect.Array, reflect.Map, reflect.Struct:
				bytes, _ := json.Marshal(value)
				flat[prefix] = string(bytes)
			default:
				flat[prefix] = fmt.Sprint(value)
			}
		}
	}
	walk("", row)
	if _, ok := flat[""]; ok {
		flat["value"] = flat[""]
		delete(flat, "")
	}
	return flat
}

func anySliceToMapRows(values any) ([]map[string]any, error) {
	rv := reflect.ValueOf(values)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, fmt.Errorf("invalid argument")
	}
	if rv.Len() == 0 {
		return []map[string]any{}, nil
	}

	// Batch conversion keeps JSON tag semantics while avoiding per-row marshal/unmarshal.
	if bytes, err := json.Marshal(rv.Interface()); err == nil {
		var rows []map[string]any
		if err := json.Unmarshal(bytes, &rows); err == nil {
			return rows, nil
		}
	}

	// Compatibility fallback: preserve legacy per-item behavior for uncommon shapes.
	rows := make([]map[string]any, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		row, err := anyToMap(rv.Index(i).Interface())
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func anyToMap(value any) (map[string]any, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(bytes, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func dedupeRows(rows []map[string]any) []map[string]any {
	if len(rows) < 2 {
		return rows
	}
	seen := make(map[string]struct{}, len(rows))
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		bytes, err := json.Marshal(row)
		if err != nil {
			result = append(result, row)
			continue
		}
		key := string(bytes)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, row)
	}
	return result
}

func dedupeRiskRecords(records []riskanalysis.ScanRecord) []riskanalysis.ScanRecord {
	if len(records) < 2 {
		return records
	}
	seen := make(map[string]struct{}, len(records))
	result := make([]riskanalysis.ScanRecord, 0, len(records))
	for _, record := range records {
		bytes, err := json.Marshal(record.Raw)
		if err != nil {
			result = append(result, record)
			continue
		}
		key := string(bytes)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, record)
	}
	return result
}

func mapRowsToRiskRecords(rows []map[string]any, targetType string) []riskanalysis.ScanRecord {
	records := make([]riskanalysis.ScanRecord, 0, len(rows))
	for _, row := range rows {
		raw := copyMap(row)
		if targetType != "" {
			if _, ok := raw["target_type"]; !ok {
				raw["target_type"] = targetType
			}
		}
		records = append(records, riskanalysis.ScanRecord{Raw: raw})
	}
	return records
}

func mapRowsToRiskRecordsWithPathCandidates(rows []map[string]any, targetType string, candidateKeys []string) []riskanalysis.ScanRecord {
	if len(candidateKeys) == 0 {
		return mapRowsToRiskRecords(rows, targetType)
	}

	records := make([]riskanalysis.ScanRecord, 0, len(rows))
	for _, row := range rows {
		baseRaw := copyMap(row)
		if targetType != "" {
			if _, ok := baseRaw["target_type"]; !ok {
				baseRaw["target_type"] = targetType
			}
		}

		paths := collectCandidatePaths(baseRaw, candidateKeys)
		if len(paths) == 0 {
			records = append(records, riskanalysis.ScanRecord{Raw: baseRaw})
			continue
		}

		for _, path := range paths {
			raw := copyMap(baseRaw)
			raw["target_path"] = path
			records = append(records, riskanalysis.ScanRecord{Raw: raw})
		}
	}
	return records
}

func collectCandidatePaths(raw map[string]any, keys []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(keys))

	var appendPath func(value any)
	appendPath = func(value any) {
		switch typed := value.(type) {
		case string:
			path := strings.TrimSpace(typed)
			if path == "" {
				return
			}
			if _, ok := seen[path]; ok {
				return
			}
			seen[path] = struct{}{}
			out = append(out, path)
		case []string:
			for _, item := range typed {
				appendPath(item)
			}
		case []any:
			for _, item := range typed {
				appendPath(item)
			}
		}
	}

	appendPath(raw["target_path"])
	for _, key := range keys {
		appendPath(raw[key])
	}
	return out
}

func printHostscanModuleHelp(module string) error {
	switch module {
	case "account":
		return printFilteredModuleHelp(func() error {
			_, err := parseAccountScanFlags([]string{"-h"})
			return err
		})
	case "usergroup":
		return printFilteredModuleHelp(func() error {
			_, err := parseUserGroupScanFlags([]string{"-h"})
			return err
		})
	case "process":
		return printFilteredModuleHelp(func() error {
			_, err := parseProcessScanFlags([]string{"-h"})
			return err
		})
	case "port":
		return printFilteredModuleHelp(func() error {
			_, err := parsePortScanFlags([]string{"-h"})
			return err
		})
	case "startup":
		return printFilteredModuleHelp(func() error {
			_, err := parseStartupScanFlags([]string{"-h"})
			return err
		})
	case "scheduledtask":
		return printFilteredModuleHelp(func() error {
			_, err := parseScheduledTaskScanFlags([]string{"-h"})
			return err
		})
	case "environment":
		return printFilteredModuleHelp(func() error {
			_, err := parseEnvironmentScanFlags([]string{"-h"})
			return err
		})
	case "kernel":
		return printFilteredModuleHelp(func() error {
			_, err := parseKernelScanFlags([]string{"-h"})
			return err
		})
	case "database":
		return printFilteredModuleHelp(func() error {
			_, err := parseDatabaseScanFlags([]string{"-h"})
			return err
		})
	case "application":
		return printFilteredModuleHelp(func() error {
			_, err := parseWebApplicationScanFlags([]string{"-h"})
			return err
		})
	default:
		return fmt.Errorf("invalid argument: unknown hostscan module: %s", module)
	}
}

func buildBenchmarkSummaryCLICountRows(summary benchmark.Summary) []benchmarkSummaryMetricRow {
	return []benchmarkSummaryMetricRow{
		{Metric: "total_checks", Display: strconv.Itoa(summary.Total)},
		{Metric: "compliant", Display: strconv.Itoa(summary.Pass)},
		{Metric: "non_compliant", Display: strconv.Itoa(summary.Fail)},
		{Metric: "informational", Display: strconv.Itoa(summary.Informational)},
		{Metric: "pending", Display: strconv.Itoa(summary.Pending)},
	}
}

func buildBenchmarkSummaryCLIRateRows(summary benchmark.Summary) []benchmarkSummaryMetricRow {
	rate := func(value float64) string {
		return fmt.Sprintf("%.2f%%", value*100)
	}
	return []benchmarkSummaryMetricRow{
		{Metric: "compliance", Display: rate(summary.ComplianceRate)},
	}
}

func printHostscanRiskHelp(modules []string) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Risk options (available only when -r is enabled):")
	fmt.Fprintln(os.Stderr, "  -yara-rules <path>             YARA rule file path")
	fmt.Fprintln(os.Stderr, "  -analysis-max-duration <dur>   Total analysis time limit (0 means unlimited)")
	if hostscanHasModule(modules, "process") {
		fmt.Fprintln(os.Stderr, "  -process-memory                Collect process memory samples (process module only)")
	}
}

func printFilescanWebModuleHelp(module string) error {
	switch module {
	case "site":
		return printFilteredModuleHelp(func() error {
			_, err := parseWebSiteScanFlags([]string{"-h"})
			return err
		})
	case "framework":
		return printFilteredModuleHelp(func() error {
			_, err := parseWebFrameworkScanFlags([]string{"-h"})
			return err
		})
	case "jarpackage":
		return printFilteredModuleHelp(func() error {
			_, err := parseJarPackageScanFlags([]string{"-h"})
			return err
		})
	case "software":
		return printFilteredModuleHelp(func() error {
			_, err := parseSoftwareScanFlags([]string{"-h"})
			return err
		})
	default:
		return fmt.Errorf("invalid argument: unknown filescan module: %s", module)
	}
}

func printFilteredModuleHelp(printer func() error) error {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}

	os.Stderr = writer
	callErr := printer()
	_ = writer.Close()
	os.Stderr = originalStderr

	data, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		return readErr
	}

	cleaned := sanitizeModuleHelpText(string(data))
	if cleaned != "" {
		fmt.Fprint(os.Stderr, cleaned)
		if !strings.HasSuffix(cleaned, "\n") {
			fmt.Fprintln(os.Stderr)
		}
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Note: output is unified by global -o/--output; module-level -output/-excel/-json is not supported.")
	}

	return callErr
}

func sanitizeModuleHelpText(raw string) string {
	text := strings.ReplaceAll(raw, "[-output json|excel] [-excel out.xlsx]", "")
	lines := strings.Split(text, "\n")
	filtered := make([]string, 0, len(lines))
	skipDescLine := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if skipDescLine {
			skipDescLine = false
			if strings.HasPrefix(trimmed, "-") {
				// fall through when parser layout differs and current line is another flag.
			} else {
				continue
			}
		}

		if isLegacyModuleOutputHelpLine(trimmed) {
			skipDescLine = true
			continue
		}
		filtered = append(filtered, line)
	}

	return strings.TrimSpace(strings.Join(filtered, "\n"))
}

func isLegacyModuleOutputHelpLine(trimmed string) bool {
	switch {
	case strings.HasPrefix(trimmed, "-output"),
		strings.HasPrefix(trimmed, "-excel"),
		strings.HasPrefix(trimmed, "-json"),
		strings.HasPrefix(trimmed, "--output"),
		strings.HasPrefix(trimmed, "--excel"),
		strings.HasPrefix(trimmed, "--json"):
		return true
	default:
		return false
	}
}

func copyMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func rejectLegacyOutputFlags(args []string) error {
	for i := 0; i < len(args); i++ {
		name, _ := splitFlagToken(args[i])
		switch name {
		case "-output", "--output", "-excel", "--excel", "-json", "--json":
			return fmt.Errorf("invalid argument: module-level output flags are removed, use global -o <path>")
		}
	}
	return nil
}

type optionSpec struct {
	flag string
	desc string
}

var hostscanCustomOptionCatalog = map[string][]optionSpec{
	"account": {
		{"-gid", "Filter by GID"},
		{"-groups", "Filter by business group IDs"},
		{"-home", "Filter by home path"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-lastLoginFrom", "Filter by last login start time"},
		{"-lastLoginTo", "Filter by last login end time"},
		{"-name", "Filter by account name"},
		{"-status", "Filter by account status"},
		{"-uid", "Filter by UID"},
	},
	"usergroup": {
		{"-gid", "Filter by GID"},
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-name", "Filter by group name"},
	},
	"process": {
		{"-description", "Filter by process description"},
		{"-gname", "Filter by group name"},
		{"-hostname", "Filter by hostname"},
		{"-installedByPm", "Filter by package-manager installed flag"},
		{"-ip", "Filter by IP"},
		{"-name", "Filter by process name"},
		{"-packageName", "Filter by package name"},
		{"-packageVersions", "Filter by package versions"},
		{"-path", "Filter by executable path"},
		{"-pids", "Filter by process IDs"},
		{"-root", "Filter by root privilege flag"},
		{"-startArgs", "Filter by startup args"},
		{"-startTime", "Filter by startup time"},
		{"-state", "Filter by process state"},
		{"-tty", "Filter by tty"},
		{"-types", "Filter by process types"},
		{"-uname", "Filter by user name"},
		{"-versions", "Filter by process versions"},
	},
	"port": {
		{"-bindIp", "Filter by bind IP"},
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-mode", "Filter by scan mode"},
		{"-port", "Filter by port"},
		{"-processName", "Filter by process name"},
		{"-proto", "Filter by protocol"},
	},
	"startup": {
		{"-defaultOpen", "Filter by default-open flag"},
		{"-enable", "Filter by enabled flag"},
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-initLevel", "Filter by init level"},
		{"-ip", "Filter by IP"},
		{"-isXinetd", "Filter by xinetd flag"},
		{"-name", "Filter by startup name"},
		{"-publisher", "Filter by publisher"},
		{"-showName", "Filter by display name"},
		{"-startType", "Filter by start type"},
		{"-user", "Filter by user"},
	},
	"scheduledtask": {
		{"-conf", "Filter by config path"},
		{"-execPath", "Filter by executable path"},
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-taskTimeFrom", "Filter by task start time"},
		{"-taskTimeTo", "Filter by task end time"},
		{"-taskType", "Filter by task type"},
		{"-user", "Filter by user"},
	},
	"environment": {
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-key", "Filter by key"},
		{"-sysEnv", "Filter by system-env flag"},
		{"-user", "Filter by user"},
		{"-value", "Filter by value"},
	},
	"kernel": {
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-moduleName", "Filter by module name"},
		{"-path", "Filter by module path"},
		{"-version", "Filter by kernel version"},
	},
	"database": {
		{"-confPath", "Filter by config path"},
		{"-dataDir", "Filter by data directory"},
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-logPath", "Filter by log path"},
		{"-name", "Filter by database name"},
		{"-port", "Filter by port"},
		{"-versions", "Filter by versions"},
	},
	"application": {
		{"-appName", "Filter by app name"},
		{"-domainName", "Filter by domain name"},
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-rootPath", "Filter by root path"},
		{"-serverName", "Filter by server name"},
		{"-version", "Filter by version"},
		{"-webRoot", "Filter by web root"},
	},
}

var filescanCustomOptionCatalog = map[string][]optionSpec{
	"site": {
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-port", "Filter by site port"},
		{"-proto", "Filter by protocol"},
		{"-rootPath", "Filter by root path"},
		{"-type", "Filter by site type"},
	},
	"framework": {
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-name", "Filter by framework name"},
		{"-serverName", "Filter by server name"},
		{"-type", "Filter by framework type"},
		{"-version", "Filter by framework version"},
	},
	"jarpackage": {
		{"-executable", "Filter by executable flag"},
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-name", "Filter by package name"},
		{"-path", "Filter by path"},
		{"-type", "Filter by package type"},
		{"-version", "Filter by package version"},
	},
	"software": {
		{"-binPath", "Filter by binary/install path"},
		{"-configPath", "Filter by config path"},
		{"-groups", "Filter by business group IDs"},
		{"-hostname", "Filter by hostname"},
		{"-ip", "Filter by IP"},
		{"-name", "Filter by software name"},
		{"-version", "Filter by software version"},
	},
}

var hostscanMultiIntersectionOptions = []optionSpec{
	{"-hostname", "Filter by hostname (intersection option)"},
	{"-ip", "Filter by IP (intersection option)"},
}

var filescanMultiIntersectionOptions = []optionSpec{
	{"-groups", "Filter by business group IDs (intersection option)"},
	{"-hostname", "Filter by hostname (intersection option)"},
	{"-ip", "Filter by IP (intersection option)"},
}

var rootBannerLines = []string{
	"  ___      ___  _   _  ___  ___",
	" / __|___ / _ \\| | | |/ _ \\/ __|",
	"| (__|___|  __/| |_| |  __/\\__ \\",
	" \\___|    \\___| \\__, |\\___||___/",
	"                 __/ |",
	"                |___/",
}

func usage() {
	for _, line := range rootBannerLines {
		fmt.Fprintln(os.Stderr, line)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "NAME:")
	fmt.Fprintln(os.Stderr, "    c-eyes - Endpoint Security Detection Tool")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "    c-eyes [global options] command [command options] [arguments...]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "DESCRIPTION:")
	fmt.Fprintln(os.Stderr, "    Cyber Eye - Endpoint Security Detection Tool")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "COMMANDS:")
	fmt.Fprintln(os.Stderr, "    hostscan    host information module")
	fmt.Fprintln(os.Stderr, "    filescan    document information module")
	fmt.Fprintln(os.Stderr, "    benchmark   security baseline benchmark module")
	fmt.Fprintln(os.Stderr, "    sbom        software bill-of-materials collection module")
	fmt.Fprintln(os.Stderr, "    eventlog    host event-log collection module")
	fmt.Fprintln(os.Stderr, "    netscan     internal network asset discovery module")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "GLOBAL OPTIONS:")
	fmt.Fprintln(os.Stderr, "    -o, --output <path>    Output path (identified by extensions .json/.csv/.xlsx)")
	fmt.Fprintln(os.Stderr, "    -r, --riskanalyze      Enable risk analysis. For standalone source analysis, check: c-eyes -r -h")
	fmt.Fprintln(os.Stderr, "    -h, --help             Show help")
}

func hostscanUsage() {
	fmt.Fprintln(os.Stderr, "NAME:")
	fmt.Fprintln(os.Stderr, "    c-eyes hostscan - Run a hostscan task")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "    c-eyes hostscan [command options] [arguments...]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	fmt.Fprintln(os.Stderr, "    --custom <mode1>,<mode2>,...,<moden>    Specify the scan or analysis module (mutually exclusive with --all)")
	fmt.Fprintln(os.Stderr, "        mode(Information scanning supported modules): account,usergroup,process,port,startup,scheduledtask,environment,kernel,database,application")
	fmt.Fprintln(os.Stderr, "        mode(Risk analysis support module): process,startup,scheduledtask,kernel,database,application")
	fmt.Fprintln(os.Stderr, "        Supplement: The request filtering parameters for one or multiple modules can be viewed in this format: ./c-eyes hostscan --custom <mode> -h")
	fmt.Fprintln(os.Stderr, "    --all                                   Enable all scan or analysis modules (mutually exclusive with --custom)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OPTIONS(only -r enable can use):")
	fmt.Fprintln(os.Stderr, "    -yara-rules <path>               Yara rule path")
	fmt.Fprintln(os.Stderr, "    -analysis-max-duration <number>  Analysis duration limit (add units, such as 30s, 5m, 1h)")
	fmt.Fprintln(os.Stderr, "    -process-memory                  Enable collection of process memory samples (supported when using the process module)")
}

func filescanUsage() {
	fmt.Fprintln(os.Stderr, "NAME:")
	fmt.Fprintln(os.Stderr, "    c-eyes filescan - Run a filescan task")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "    c-eyes filescan [command options] [arguments...]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	fmt.Fprintln(os.Stderr, "    --custom <mode1>,<mode2>,...,<moden>    Specify the scan or analysis module (mutually exclusive with --all and --scan-mode)")
	fmt.Fprintln(os.Stderr, "        mode: site,framework,jarpackage,software")
	fmt.Fprintln(os.Stderr, "        Supplement: The request filtering parameters for one or multiple modules can be viewed in this format: ./c-eyes filescan --custom <mode> -h")
	fmt.Fprintln(os.Stderr, "    --all                                   Enable all scan or analysis modules (mutually exclusive with --custom and --scan-mode)")
	fmt.Fprintln(os.Stderr, "    --scan-mode                            Scan mode selection, optional mode: full / path <path> (mutually exclusive with --custom and --all)")
	fmt.Fprintln(os.Stderr, "    --smart                                Enable smart subset scanning (only valid with --scan-mode full|path)")
	fmt.Fprintln(os.Stderr, "    --max-targets <number>                Limit the number of scan targets")
	fmt.Fprintln(os.Stderr, "    (local scan concurrency is auto-tuned by CPU/memory)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OPTIONS(only -r enable can use):")
	fmt.Fprintln(os.Stderr, "    -yara-rules <path>               Yara rule path")
	fmt.Fprintln(os.Stderr, "    -analysis-max-duration <number>  Analysis duration limit (add units, such as 30s, 5m, 1h)")
	fmt.Fprintln(os.Stderr, "    -cloud-upload                    Enable file upload cloud analysis")
	fmt.Fprintln(os.Stderr, "    --risk-mode <mode>               Risk analysis mode: local_only / cloud_only / fast / smart / deep")
}

func benchmarkUsage() {
	fmt.Fprintln(os.Stderr, "NAME:")
	fmt.Fprintln(os.Stderr, "    c-eyes benchmark - Run a security baseline benchmark task")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "    c-eyes benchmark [command options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	fmt.Fprintln(os.Stderr, "    --template <name>                Template selection: auto|windows|linux|euleros|kylin (default: auto)")
	fmt.Fprintln(os.Stderr, "    --baseline-level <level>         Baseline level selection: 1|2|3|4 (default: 1)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "NOTE:")
	fmt.Fprintln(os.Stderr, "    benchmark is collection-only and does not support -r/--riskanalyze or risk options.")
	fmt.Fprintln(os.Stderr, "    benchmark requires administrator privilege on Windows.")
	fmt.Fprintln(os.Stderr, "    benchmark requires root privilege on Linux-family systems.")
	fmt.Fprintln(os.Stderr, "    benchmark uses global -o/--output for result path (.json/.csv/.xlsx).")
}

func sbomUsage() {
	fmt.Fprintln(os.Stderr, "NAME:")
	fmt.Fprintln(os.Stderr, "    c-eyes sbom - Run an SBOM collection task")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "    c-eyes sbom [command options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	fmt.Fprintln(os.Stderr, "    -p, --path <path>               SBOM scan root path")
	fmt.Fprintln(os.Stderr, "    --image-target <value>          SBOM scan image target")
	fmt.Fprintln(os.Stderr, "    --target-type <type>            SBOM image target type: auto|image|archive|oci-layout (default: auto)")
	fmt.Fprintln(os.Stderr, "    --format <name>                 SBOM output format: xspdx-json|spdx-json (default: xspdx-json)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "NOTE:")
	fmt.Fprintln(os.Stderr, "    sbom is collection-only and does not support -r/--riskanalyze or risk options.")
	fmt.Fprintln(os.Stderr, "    sbom requires exactly one target: -p/--path or --image-target.")
	fmt.Fprintln(os.Stderr, "    -p/--path and --image-target are mutually exclusive.")
	fmt.Fprintln(os.Stderr, "    --target-type can only be used with --image-target.")
	fmt.Fprintln(os.Stderr, "    sbom uses global -o/--output for file path; only .json output suffix is supported.")
	fmt.Fprintln(os.Stderr, "    without -o, sbom auto-generates result*.json in current directory.")
}

func eventlogUsage() {
	fmt.Fprintln(os.Stderr, "NAME:")
	fmt.Fprintln(os.Stderr, "    c-eyes eventlog - Run an eventlog collection task")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "    c-eyes eventlog [command options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	fmt.Fprintln(os.Stderr, "    -startTime <time>                Query start time (unix ms / RFC3339 / YYYY-MM-DD[ HH:MM:SS])")
	fmt.Fprintln(os.Stderr, "    -endTime <time>                  Query end time (default: now; unix ms / RFC3339 / YYYY-MM-DD[ HH:MM:SS])")
	fmt.Fprintln(os.Stderr, "    -last <duration>                 Query recent window (default: 24h, e.g. 30m/24h/7d)")
	fmt.Fprintln(os.Stderr, "    -maxLogs <number>                Maximum returned log rows (default: 0, unlimited)")
	fmt.Fprintln(os.Stderr, "    -sources <a,b,c>                 Sources filter: system/security/application/syslog/auth/audit/kern")
	fmt.Fprintln(os.Stderr, "    -eventTypes <a,b,c>              Event types: process/file/network/registry/account/service/login/system/policy")
	fmt.Fprintln(os.Stderr, "    -eventLevels <a,b,c>             Event levels: debug/info/notice/warn/error/critical/fatal")
	fmt.Fprintln(os.Stderr, "    -eventCodes <a,b,c>              Event code filters")
	fmt.Fprintln(os.Stderr, "    -eventActions <a,b,c>            Event action filters")
	fmt.Fprintln(os.Stderr, "    -result <a,b,c>                  Result filters: success/fail/unknown")
	fmt.Fprintln(os.Stderr, "    -processName <text>              Fuzzy process name/path filter")
	fmt.Fprintln(os.Stderr, "    -processId <number>              Exact process ID filter")
	fmt.Fprintln(os.Stderr, "    -username <text>                 Fuzzy username filter")
	fmt.Fprintln(os.Stderr, "    -targetPath <text>               Fuzzy target path filter")
	fmt.Fprintln(os.Stderr, "    -localIp <ip>                    Local IP filter")
	fmt.Fprintln(os.Stderr, "    -localPort <number>              Local port filter")
	fmt.Fprintln(os.Stderr, "    -remoteIp <ip>                   Remote IP filter")
	fmt.Fprintln(os.Stderr, "    -remotePort <number>             Remote port filter")
	fmt.Fprintln(os.Stderr, "    -protocols <a,b,c>               Protocol filters")
	fmt.Fprintln(os.Stderr, "    -keyword <text>                  Additional fuzzy keyword filter")
	fmt.Fprintln(os.Stderr, "    -sortBy <field>                  Sort by: timestamp/eventLevel/source/eventType/processName (default: timestamp)")
	fmt.Fprintln(os.Stderr, "    -sortOrder <asc|desc>            Sort order (default: desc)")
	fmt.Fprintln(os.Stderr, "    -includeRawContent               Include redacted/truncated raw payload")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "NOTE:")
	fmt.Fprintln(os.Stderr, "    eventlog is collection-only and does not support -r/--riskanalyze or risk options.")
	fmt.Fprintln(os.Stderr, "    eventlog always returns all matched rows in a single result set.")
}

func netscanUsage() {
	fmt.Fprintln(os.Stderr, "NAME:")
	fmt.Fprintln(os.Stderr, "    c-eyes netscan - Run an internal network discovery task")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "    c-eyes netscan [command options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "EXECUTE OPTIONS:")
	fmt.Fprintln(os.Stderr, "    -target <expr>                  Target expression: IP/CIDR/IPv4 range/list (comma-separated)")
	fmt.Fprintln(os.Stderr, "    -targetFile <path>              UTF-8 file path, one target expression per line (# comments supported)")
	fmt.Fprintln(os.Stderr, "    -scanMode <m1,m2,...>           Probe modes: A(ARP),ICP(ICMP-PING),ICA(ICMP-ADDRESSMASK),ICT(ICMP-TIMESTAMP),T(TCP-CONNECT),TS(TCP-SYN),U(UDP),N(NETBIOS),O(OXID) (default: A; with -reachableSegments and no explicit -scanMode: ICP,T)")
	fmt.Fprintln(os.Stderr, "    -ipv6                           Enable IPv6 probing where mode capability is available")
	fmt.Fprintln(os.Stderr, "    -reachableSegments              Enable opt-in routed reachable-segment discovery (bounded by existing safety caps)")
	fmt.Fprintln(os.Stderr, "    -exclude <expr>                 Exclude target expression (higher priority than target/targetFile)")
	fmt.Fprintln(os.Stderr, "    -tcpPorts <p1,p2,...>           TCP ports for T/TS (default: 22,80,135,139,443,445,3389)")
	fmt.Fprintln(os.Stderr, "    -udpPorts <p1,p2,...>           UDP ports for U (default: 53,137,161)")
	fmt.Fprintln(os.Stderr, "    -maxTargets <number>            Maximum resolved targets safety cap (default: 4096; with -reachableSegments and no explicit -maxTargets: 2048)")
	fmt.Fprintln(os.Stderr, "    -pps <number>                   Packet rate upper bound; adaptive tuning always enabled")
	fmt.Fprintln(os.Stderr, "    -workers <number>               Worker upper bound; adaptive tuning always enabled")
	fmt.Fprintln(os.Stderr, "    -timeoutMs <number>             Probe timeout per target in milliseconds")
	fmt.Fprintln(os.Stderr, "    -jitterMs <number>              Random probe delay range [0, jitterMs] milliseconds")
	fmt.Fprintln(os.Stderr, "    -managedSource <path>           Managed asset file path (.json/.csv/.xlsx), matched by ip+mac then ip")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "FILTER OPTIONS:")
	fmt.Fprintln(os.Stderr, "    -assetStatus <value>            managed/unmanaged/ignored")
	fmt.Fprintln(os.Stderr, "    -keyword <text>                 Fuzzy match on ip/mac/hostname")
	fmt.Fprintln(os.Stderr, "    -sortBy <field>                 lastSeen/firstSeen/ipAddress/assetStatus (default: lastSeen)")
	fmt.Fprintln(os.Stderr, "    -sortOrder <asc|desc>           Sort direction (default: desc)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "NOTE:")
	fmt.Fprintln(os.Stderr, "    netscan is collection-only and does not support -r/--riskanalyze or risk options.")
	fmt.Fprintln(os.Stderr, "    Reachable mode remains bounded; use -target/-targetFile for strict scan scope control.")
	fmt.Fprintln(os.Stderr, "    Mode privileges: ICP(ICMP-PING)/ICA(ICMP-ADDRESSMASK)/ICT(ICMP-TIMESTAMP) may require elevated privileges for raw ICMP sockets.")
	fmt.Fprintln(os.Stderr, "    Mode privileges: TS(TCP-SYN) may require elevated privileges on some systems; fallback behavior is reported in warnings.")
}

func riskUsage() {
	fmt.Fprintln(os.Stderr, "NAME:")
	fmt.Fprintln(os.Stderr, "    c-eyes -r - Designated analysis source for anomaly analysis")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "    c-eyes -r -input/-file/-dir/-pid/-pname (Analysis source must be specified, choose one of five)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	fmt.Fprintln(os.Stderr, "    -yara-rules <path>                        Yara rule path")
	fmt.Fprintln(os.Stderr, "    -analysis-max-duration <number>           Analysis duration limit (add units, such as 30s, 5m, 1h)")
	fmt.Fprintln(os.Stderr, "    -cloud-upload                             Enable file upload cloud analysis")
	fmt.Fprintln(os.Stderr, "    -process-memory                           Enable collection of process memory samples (only with -pid/-pname)")
	fmt.Fprintln(os.Stderr, "    --risk-mode <mode>                        Risk analysis mode: local_only / cloud_only / fast / smart / deep")
	fmt.Fprintln(os.Stderr, "    -input <scan.json/scan.csv/scan.xlsx>     Use existing scan result file as analysis source")
	fmt.Fprintln(os.Stderr, "    -file <path>                              Use a single file path as analysis source")
	fmt.Fprintln(os.Stderr, "    -dir <path>                               Use a directory path as analysis source")
	fmt.Fprintln(os.Stderr, "    -pid <pid>                                Use process PID as analysis source")
	fmt.Fprintln(os.Stderr, "    -pname <process_name>                     Use process name as analysis source")
}

func printHostscanCustomOptionsHelp(modules []string) {
	printCustomOptionsHelp(modules, hostscanCustomOptionCatalog, hostscanMultiIntersectionOptions)
}

func printFilescanCustomOptionsHelp(modules []string) {
	printCustomOptionsHelp(modules, filescanCustomOptionCatalog, filescanMultiIntersectionOptions)
}

func printCustomOptionsHelp(modules []string, catalog map[string][]optionSpec, multiIntersection []optionSpec) {
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	if len(modules) == 0 {
		fmt.Fprintln(os.Stderr, "    (no module selected)")
		return
	}

	if len(modules) == 1 {
		module := strings.ToLower(strings.TrimSpace(modules[0]))
		lines := catalog[module]
		if len(lines) == 0 {
			fmt.Fprintln(os.Stderr, "    (no options available)")
			return
		}
		printOptionSpecs(lines)
		return
	}

	printOptionSpecs(multiIntersection)
}

func printOptionSpecs(lines []optionSpec) {
	for _, line := range lines {
		fmt.Fprintf(os.Stderr, "    %-28s %s\n", line.flag, line.desc)
	}
}
func printHostscanModuleHelpLines(modules []string) {
	seen := make(map[string]struct{}, len(modules))
	for _, raw := range modules {
		module := strings.ToLower(strings.TrimSpace(raw))
		if module == "" {
			continue
		}
		if _, ok := seen[module]; ok {
			continue
		}
		seen[module] = struct{}{}
		fmt.Fprintf(os.Stderr, "    %-20s %s\n", module, hostscanModuleLabel(module))
	}
}

func hostscanModuleLabel(module string) string {
	switch module {
	case "account":
		return "account module"
	case "usergroup":
		return "usergroup module"
	case "process":
		return "process module"
	case "port":
		return "port module"
	case "startup":
		return "startup module"
	case "scheduledtask":
		return "scheduled-task module"
	case "environment":
		return "environment module"
	case "kernel":
		return "kernel module"
	case "database":
		return "database module"
	case "application":
		return "web-application module"
	default:
		return "module"
	}
}

func printOutputSettingHelp() {
	fmt.Fprintln(os.Stderr, "OUTPUT:")
	fmt.Fprintln(os.Stderr, "  -o, --output <path>      Output path (identified by extensions .json/.csv/.xlsx)")
}
