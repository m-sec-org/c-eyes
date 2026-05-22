package main

import (
	"bytes"
	"context"

	"encoding/json"

	"errors"

	"fmt"

	"io"
	"net/http"
	"net/http/httptest"

	"os"

	"path/filepath"

	"reflect"

	"runtime"

	"sort"

	"strings"

	"testing"

	"time"

	"edrsystem/internal/benchmark"
	"edrsystem/internal/eventlogscan"
	"edrsystem/internal/sbom"

	"edrsystem/internal/riskanalysis"

	"github.com/xuri/excelize/v2"
)

func TestParseGlobalCLIOptions(t *testing.T) {

	t.Parallel()

	opts, remaining, err := parseGlobalCLIOptions([]string{

		"hostscan",

		"--custom", "account",

		"-r",

		"--risk-mode", "local_only",

		"-o", "result.xlsx",
	})

	if err != nil {

		t.Fatalf("parseGlobalCLIOptions returned error: %v", err)

	}

	if !opts.RiskEnabled {

		t.Fatal("expected risk enabled")

	}

	if opts.RiskMode != "local_only" {

		t.Fatalf("expected risk mode local_only, got %q", opts.RiskMode)

	}

	if opts.OutputPath != "result.xlsx" {

		t.Fatalf("unexpected output path: %s", opts.OutputPath)

	}

	if len(remaining) != 3 {

		t.Fatalf("unexpected remaining args: %#v", remaining)

	}

}

func TestSanitizeModuleHelpTextRemovesLegacyOutputFlags(t *testing.T) {

	t.Parallel()

	raw := strings.Join([]string{

		"Usage:",

		"  c-eyes web-site-scan [options] [-output json|excel] [-excel out.xlsx]",

		"",

		"Options:",

		"  -excel string",

		"        Excel output file path (.xlsx)",

		"  -groups value",

		"        Filter by group IDs (comma-separated)",

		"  -output value",

		"        Output format (json or excel) (default json)",

		"",
	}, "\n")

	got := sanitizeModuleHelpText(raw)

	if strings.Contains(got, "-output") {

		t.Fatalf("expected sanitized help to remove -output, got: %s", got)

	}

	if strings.Contains(got, "-excel") {

		t.Fatalf("expected sanitized help to remove -excel, got: %s", got)

	}

	if !strings.Contains(got, "-groups value") {

		t.Fatalf("expected sanitized help to keep non-output flags, got: %s", got)

	}

}

func TestParseGlobalCLIOptionsOutputRequiresPath(t *testing.T) {

	t.Parallel()

	_, _, err := parseGlobalCLIOptions([]string{

		"hostscan",

		"-o",

		"-r",
	})

	if err == nil {

		t.Fatal("expected -o without path error")

	}

	if !strings.Contains(err.Error(), "-o/--output") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseGlobalCLIOptionsOutputEqualsRequiresPath(t *testing.T) {

	t.Parallel()

	_, _, err := parseGlobalCLIOptions([]string{

		"hostscan",

		"-o=",
	})

	if err == nil {

		t.Fatal("expected -o= without path error")

	}

	if !strings.Contains(err.Error(), "-o/--output") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseGlobalCLIOptionsDefaultAutoOutput(t *testing.T) {

	t.Parallel()

	opts, remaining, err := parseGlobalCLIOptions([]string{

		"filescan",
	})

	if err != nil {

		t.Fatalf("parseGlobalCLIOptions returned error: %v", err)

	}

	if opts.OutputPath != autoExcelOutputSentinel {

		t.Fatalf("expected auto excel output sentinel by default, got %q", opts.OutputPath)

	}

	if len(remaining) != 1 || remaining[0] != "filescan" {

		t.Fatalf("unexpected remaining args: %#v", remaining)

	}

}

func TestParseGlobalCLIOptionsRiskModeRequiresRiskEnabled(t *testing.T) {

	t.Parallel()

	_, _, err := parseGlobalCLIOptions([]string{

		"filescan",

		"--risk-mode", "local_only",
	})

	if err == nil {

		t.Fatal("expected --risk-mode without -r/--riskanalyze to be rejected")

	}

	if !strings.Contains(err.Error(), "-r/--riskanalyze") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestDetectOutputFormat(t *testing.T) {

	t.Parallel()

	format, err := detectOutputFormat("out.csv")

	if err != nil {

		t.Fatalf("detectOutputFormat returned error: %v", err)

	}

	if format != "csv" {

		t.Fatalf("expected csv, got %s", format)

	}

	if _, err := detectOutputFormat("out.txt"); err == nil {

		t.Fatal("expected invalid suffix error")

	}

}

func TestParseHostscanArgsMutualExclusion(t *testing.T) {

	t.Parallel()

	_, err := parseHostscanArgs([]string{"--custom", "account", "--all"})

	if err == nil {

		t.Fatal("expected mutual exclusion error")

	}

}

func TestParseHostscanArgsRequiresAllOrCustom(t *testing.T) {

	t.Parallel()

	_, err := parseHostscanArgs([]string{})

	if err == nil {

		t.Fatal("expected explicit module selection error")

	}

	if !strings.Contains(err.Error(), "requires either --all or --custom") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestApplyHostscanRiskModuleSelectionExplicitAllToRiskModules(t *testing.T) {

	t.Parallel()

	parsed, err := parseHostscanArgs([]string{"--all"})

	if err != nil {

		t.Fatalf("parseHostscanArgs returned error: %v", err)

	}

	adjusted, err := applyHostscanRiskModuleSelection(parsed, true)

	if err != nil {

		t.Fatalf("applyHostscanRiskModuleSelection returned error: %v", err)

	}

	if len(adjusted.Modules) != len(hostscanRiskModuleOrder) {

		t.Fatalf("expected %d risk modules, got %d", len(hostscanRiskModuleOrder), len(adjusted.Modules))

	}

	for i, want := range hostscanRiskModuleOrder {

		if adjusted.Modules[i] != want {

			t.Fatalf("unexpected risk module at %d: got %s want %s", i, adjusted.Modules[i], want)

		}

	}

}

func TestApplyHostscanRiskModuleSelectionAllowsRiskCustomModules(t *testing.T) {

	t.Parallel()

	parsed, err := parseHostscanArgs([]string{"--custom", "process,kernel"})

	if err != nil {

		t.Fatalf("parseHostscanArgs returned error: %v", err)

	}

	adjusted, err := applyHostscanRiskModuleSelection(parsed, true)

	if err != nil {

		t.Fatalf("applyHostscanRiskModuleSelection returned error: %v", err)

	}

	if len(adjusted.Modules) != 2 || adjusted.Modules[0] != "process" || adjusted.Modules[1] != "kernel" {

		t.Fatalf("expected risk custom modules to be unchanged, got %#v", adjusted.Modules)

	}

}

func TestApplyHostscanRiskModuleSelectionAllFlagToRiskModules(t *testing.T) {

	t.Parallel()

	parsed, err := parseHostscanArgs([]string{"--all"})

	if err != nil {

		t.Fatalf("parseHostscanArgs returned error: %v", err)

	}

	adjusted, err := applyHostscanRiskModuleSelection(parsed, true)

	if err != nil {

		t.Fatalf("applyHostscanRiskModuleSelection returned error: %v", err)

	}

	if len(adjusted.Modules) != len(hostscanRiskModuleOrder) {

		t.Fatalf("expected %d risk modules, got %d", len(hostscanRiskModuleOrder), len(adjusted.Modules))

	}

	for i, want := range hostscanRiskModuleOrder {

		if adjusted.Modules[i] != want {

			t.Fatalf("unexpected risk module at %d: got %s want %s", i, adjusted.Modules[i], want)

		}

	}

}

func TestApplyHostscanRiskModuleSelectionRejectsNonRiskCustomModules(t *testing.T) {

	t.Parallel()

	parsed, err := parseHostscanArgs([]string{"--custom", "account,process"})

	if err != nil {

		t.Fatalf("parseHostscanArgs returned error: %v", err)

	}

	_, err = applyHostscanRiskModuleSelection(parsed, true)

	if err == nil {

		t.Fatal("expected non-risk custom module error")

	}

	if !strings.Contains(err.Error(), "account") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseHostscanArgsMultiIntersectionValidation(t *testing.T) {

	t.Parallel()

	_, err := parseHostscanArgs([]string{"--custom", "account,process", "-hostname", "foo", "-uid", "1"})

	if err == nil {

		t.Fatal("expected non-intersection parameter error")

	}

}

func TestParseFilescanArgsConflict(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{"--custom", "site", "--scan-mode", "full"})

	if err == nil {

		t.Fatal("expected conflict error")

	}

}

func TestParseFilescanArgsRequiresAllOrCustomForWebMode(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{})

	if err == nil {

		t.Fatal("expected explicit module selection error")

	}

	if !strings.Contains(err.Error(), "requires one of --all, --custom, or --scan-mode") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseFilescanArgsAllSelectsAllWebModules(t *testing.T) {

	t.Parallel()

	parsed, err := parseFilescanArgs([]string{"--all"})

	if err != nil {

		t.Fatalf("parseFilescanArgs returned error: %v", err)

	}

	if parsed.IsLocalMode {

		t.Fatal("did not expect local mode")

	}

	if len(parsed.WebModules) != len(filescanWebModuleOrder) {

		t.Fatalf("expected %d web modules, got %d", len(filescanWebModuleOrder), len(parsed.WebModules))

	}

}

func TestParseFilescanArgsSupportsSoftwareModule(t *testing.T) {

	t.Parallel()

	parsed, err := parseFilescanArgs([]string{"--custom", "software"})

	if err != nil {

		t.Fatalf("parseFilescanArgs returned error: %v", err)

	}

	if parsed.IsLocalMode {

		t.Fatal("did not expect local mode")

	}

	if len(parsed.WebModules) != 1 || parsed.WebModules[0] != "software" {

		t.Fatalf("expected software module, got %#v", parsed.WebModules)

	}

}

func TestParseFilescanArgsSoftwareMultiModuleRejectsNonIntersectionParam(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{"--custom", "site,software", "-hostname", "node", "-name", "nginx"})

	if err == nil {

		t.Fatal("expected non-intersection error")

	}

	if !strings.Contains(err.Error(), "filescan multi-module mode") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseFilescanArgsLocalPathRequired(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{"--scan-mode", "path"})

	if err == nil {

		t.Fatal("expected path required error")

	}

}

func TestParseFilescanArgsLocalPathPositional(t *testing.T) {

	t.Parallel()

	parsed, err := parseFilescanArgs([]string{"--scan-mode", "path", "/tmp/sample"})

	if err != nil {

		t.Fatalf("parseFilescanArgs returned error: %v", err)

	}

	if !parsed.IsLocalMode {

		t.Fatal("expected local mode")

	}

	if parsed.LocalMode != "path" {

		t.Fatalf("expected mode path, got %q", parsed.LocalMode)

	}

	if parsed.LocalPath != "/tmp/sample" {

		t.Fatalf("expected local path /tmp/sample, got %q", parsed.LocalPath)

	}

}

func TestParseFilescanArgsSmartRequiresScanMode(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{"--smart"})

	if err == nil {

		t.Fatal("expected smart flag validation error")

	}

	if !strings.Contains(err.Error(), "--smart can only be used with --scan-mode full|path") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseFilescanArgsSmartWithWebModeRejected(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{"--all", "--smart"})

	if err == nil {

		t.Fatal("expected smart + web mode conflict")

	}

	if !strings.Contains(err.Error(), "--smart can only be used with --scan-mode full|path") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseFilescanArgsLegacySmartModeRejected(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{"--scan-mode", "smart"})

	if err == nil {

		t.Fatal("expected legacy smart mode rejected")

	}

	if !strings.Contains(err.Error(), "--scan-mode only supports full/path") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseFilescanArgsLocalFullSmart(t *testing.T) {

	t.Parallel()

	parsed, err := parseFilescanArgs([]string{"--scan-mode", "full", "--smart", "--max-targets", "10"})

	if err != nil {

		t.Fatalf("parseFilescanArgs returned error: %v", err)

	}

	if !parsed.IsLocalMode {

		t.Fatal("expected local mode")

	}

	if parsed.LocalMode != "full" {

		t.Fatalf("expected mode full, got %q", parsed.LocalMode)

	}

	if !parsed.LocalSmart {

		t.Fatal("expected LocalSmart=true")

	}

	if parsed.LocalMaxTarget != 10 {

		t.Fatalf("expected LocalMaxTarget=10, got %d", parsed.LocalMaxTarget)

	}

}

func TestParseFilescanArgsRejectScanPathFlag(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{"--scan-mode", "path", "--scan-path", "/tmp/sample"})

	if err == nil {

		t.Fatal("expected --scan-path rejected error")

	}

	if !strings.Contains(err.Error(), "--scan-path is no longer supported") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseFilescanArgsRejectWorkersFlag(t *testing.T) {

	t.Parallel()

	_, err := parseFilescanArgs([]string{"--scan-mode", "path", "/tmp/sample", "--workers", "4"})

	if err == nil {

		t.Fatal("expected --workers rejected error")

	}

	if !strings.Contains(err.Error(), "--workers is no longer supported") {

		t.Fatalf("unexpected error: %v", err)

	}

}

func TestParseChainedRiskOptionsHostscanConstraint(t *testing.T) {

	t.Parallel()

	if _, err := parseChainedRiskOptions(nil, "deep", true, false); err == nil {

		t.Fatal("expected hostscan mode constraint error")

	}

	if _, err := parseChainedRiskOptions(nil, "local_only", true, false); err == nil {

		t.Fatal("expected hostscan to reject explicit local_only risk mode")

	}

	opts, err := parseChainedRiskOptions(nil, "", true, false)

	if err != nil {

		t.Fatalf("parseChainedRiskOptions returned error: %v", err)

	}

	if opts.Mode != "local_only" {

		t.Fatalf("expected local_only, got %s", opts.Mode)

	}

}

func TestParseChainedRiskOptionsHostscanRejectsCloudUpload(t *testing.T) {

	t.Parallel()

	_, err := parseChainedRiskOptions([]string{"-cloud-upload"}, "", true, false)

	if err == nil {

		t.Fatal("expected hostscan cloud-upload constraint error")

	}

	if !strings.Contains(err.Error(), "-cloud-upload") {

		t.Fatalf("expected cloud-upload error, got %v", err)

	}

}

func TestParseChainedRiskOptionsHostscanRejectsProcessMemoryWithoutProcessModule(t *testing.T) {

	t.Parallel()

	_, err := parseChainedRiskOptions([]string{"-process-memory"}, "", true, false)

	if err == nil {

		t.Fatal("expected hostscan process-memory constraint error")

	}

	if !strings.Contains(err.Error(), "-process-memory") {

		t.Fatalf("expected process-memory error, got %v", err)

	}

}

func TestParseChainedRiskOptionsHostscanAllowsProcessMemoryWithProcessModule(t *testing.T) {

	t.Parallel()

	opts, err := parseChainedRiskOptions([]string{"-process-memory"}, "", true, true)

	if err != nil {

		t.Fatalf("parseChainedRiskOptions returned error: %v", err)

	}

	if !opts.ProcessMemory {

		t.Fatal("expected process-memory=true")

	}

	if opts.Mode != "local_only" {

		t.Fatalf("expected local_only, got %s", opts.Mode)

	}

}

func TestParseChainedRiskOptionsFilescanAllowsCloudUpload(t *testing.T) {

	t.Parallel()

	opts, err := parseChainedRiskOptions([]string{"-cloud-upload"}, "", false, false)

	if err != nil {

		t.Fatalf("parseChainedRiskOptions returned error: %v", err)

	}

	if !opts.CloudUpload {

		t.Fatal("expected cloud-upload=true for filescan chained risk")

	}

}

func TestDedupeRowsExactMatchOnly(t *testing.T) {

	t.Parallel()

	rows := []map[string]any{

		{"a": 1, "b": "x"},

		{"b": "x", "a": 1},

		{"a": 1, "b": "y"},
	}

	got := dedupeRows(rows)

	if len(got) != 2 {

		t.Fatalf("expected 2 rows after dedupe, got %d", len(got))

	}

}

func TestAnySliceToMapRowsBatchMatchesLegacy(t *testing.T) {

	t.Parallel()

	type nested struct {
		Name string `json:"name"`

		Flags []string `json:"flags,omitempty"`
	}

	type row struct {
		ID int `json:"id"`

		Name string `json:"name"`

		Meta nested `json:"meta"`

		Ptr *nested `json:"ptr,omitempty"`

		Labels []string `json:"labels"`

		Any map[string]any `json:"any"`

		When time.Time `json:"when"`
	}

	fixed := time.Date(2026, 4, 17, 8, 0, 0, 0, time.UTC)

	input := []row{

		{

			ID: 1,

			Name: "alpha",

			Meta: nested{Name: "m1", Flags: []string{"x", "y"}},

			Ptr: &nested{Name: "p1"},

			Labels: []string{"l1", "l2"},

			Any: map[string]any{"k": "v", "n": 1},

			When: fixed,
		},

		{

			ID: 2,

			Name: "beta",

			Meta: nested{Name: "m2"},

			Ptr: nil,

			Labels: []string{},

			Any: map[string]any{"k": "v2", "arr": []any{1, "x"}},

			When: fixed.Add(time.Minute),
		},
	}

	got, err := anySliceToMapRows(input)

	if err != nil {

		t.Fatalf("anySliceToMapRows returned error: %v", err)

	}

	want, err := legacyAnySliceToMapRows(input)

	if err != nil {

		t.Fatalf("legacyAnySliceToMapRows returned error: %v", err)

	}

	if !reflect.DeepEqual(got, want) {

		gotJSON, _ := json.Marshal(got)

		wantJSON, _ := json.Marshal(want)

		t.Fatalf("batch conversion mismatch\n got=%s\nwant=%s", string(gotJSON), string(wantJSON))

	}

	gotPtr, err := anySliceToMapRows(&input)

	if err != nil {

		t.Fatalf("anySliceToMapRows(pointer) returned error: %v", err)

	}

	wantPtr, err := legacyAnySliceToMapRows(&input)

	if err != nil {

		t.Fatalf("legacyAnySliceToMapRows(pointer) returned error: %v", err)

	}

	if !reflect.DeepEqual(gotPtr, wantPtr) {

		gotJSON, _ := json.Marshal(gotPtr)

		wantJSON, _ := json.Marshal(wantPtr)

		t.Fatalf("batch conversion(pointer) mismatch\n got=%s\nwant=%s", string(gotJSON), string(wantJSON))

	}

}

func TestFlattenRowsAndHeadersMatchesLegacyHeaderCollection(t *testing.T) {

	t.Parallel()

	rows := []map[string]any{

		{

			"simple": "v1",

			"nested": map[string]any{

				"k1": "x",

				"k2": 2,
			},
		},

		{

			"simple": "v2",

			"arr": []any{1, "a"},
		},
	}

	flatRows, headers := flattenRowsAndHeaders(rows)

	legacyHeaders := collectHeadersLegacy(rows)

	if !reflect.DeepEqual(headers, legacyHeaders) {

		t.Fatalf("headers mismatch: got=%v want=%v", headers, legacyHeaders)

	}

	if len(flatRows) != len(rows) {

		t.Fatalf("flat row size mismatch: got=%d want=%d", len(flatRows), len(rows))

	}

	for i := range rows {

		wantFlat := flattenRow(rows[i])

		if !reflect.DeepEqual(flatRows[i], wantFlat) {

			t.Fatalf("flat row mismatch at %d", i)

		}

	}

}

func TestBenchmarkRowsForDisplay(t *testing.T) {
	t.Parallel()

	rows := []benchmark.Row{
		{Host: "host-a", Template: "windows", CheckID: "W-1", CheckName: "测试项1", Category: "security", Expected: "期望值1", Actual: "展示值1", Status: "pass", Severity: "high", Recommendation: "整改建议1"},
		{Host: "host-a", Template: "windows", CheckID: "4", CheckName: "测试项2", Category: "account", Expected: "期望值2", Actual: "展示值2", Status: "unknown", StatusReason: "informational_check", Severity: "info", Recommendation: "整改建议2"},
		{Host: "host-a", Template: "windows", CheckID: "W-3", CheckName: "测试项3", Category: "account", Expected: "期望值3", Actual: "展示值3", Status: "fail", Severity: "low", Recommendation: "整改建议3"},
	}

	displayRows := benchmarkRowsForDisplay(rows)
	if len(displayRows) != 3 {
		t.Fatalf("expected 3 display rows, got %d", len(displayRows))
	}
	if got := displayRows[0]["检查项编号"]; got != "WIN-1" {
		t.Fatalf("expected WIN-1, got %#v", got)
	}
	if got := displayRows[1]["检查项编号"]; got != "WIN-DISP-004" {
		t.Fatalf("expected WIN-DISP-004, got %#v", got)
	}
	if got := displayRows[0]["判定结果"]; got != "符合" {
		t.Fatalf("expected pass display, got %#v", got)
	}
	if got := displayRows[0]["风险等级"]; got != nil {
		t.Fatalf("expected pass row severity hidden, got %#v", got)
	}
	if got := displayRows[0]["整改建议"]; got != nil {
		t.Fatalf("expected pass row recommendation hidden, got %#v", got)
	}
	if got := displayRows[1]["判定结果"]; got != "信息项" {
		t.Fatalf("expected informational display, got %#v", got)
	}
	if got := displayRows[1]["风险等级"]; got != nil {
		t.Fatalf("expected informational row severity hidden, got %#v", got)
	}
	if got := displayRows[1]["整改建议"]; got != nil {
		t.Fatalf("expected informational row recommendation hidden, got %#v", got)
	}
	if got := displayRows[2]["判定结果"]; got != "不符合" {
		t.Fatalf("expected fail display, got %#v", got)
	}
	if got := displayRows[2]["风险等级"]; got != "低" {
		t.Fatalf("expected fail row severity shown, got %#v", got)
	}
	if got := displayRows[2]["整改建议"]; got != "整改建议3" {
		t.Fatalf("expected fail recommendation shown, got %#v", got)
	}
	if _, ok := displayRows[0]["证据摘要"]; ok {
		t.Fatalf("expected evidence summary column omitted, got %#v", displayRows[0])
	}
}

func TestEmitOutputBenchmarkJSONUsesUTF8BOMOnWindows(t *testing.T) {
	t.Parallel()

	payload := benchmark.ScanResult{Template: "windows", Summary: benchmark.Summary{Total: 1}, Rows: []benchmark.Row{{Template: "windows", CheckID: "1", CheckName: "1", Status: "unknown", Actual: "Microsoft Windows 10 Test", Evidence: "Microsoft Windows 10 Test"}}}
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "benchmark.json")
	if err := emitOutput(payload, jsonPath); err != nil {
		t.Fatalf("emitOutput json returned error: %v", err)
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read benchmark json failed: %v", err)
	}
	if runtime.GOOS == "windows" {
		if !bytes.HasPrefix(data, utf8BOM) {
			t.Fatalf("expected UTF-8 BOM prefix for benchmark json on Windows")
		}
		data = bytes.TrimPrefix(data, utf8BOM)
	} else if bytes.HasPrefix(data, utf8BOM) {
		t.Fatalf("did not expect UTF-8 BOM prefix outside Windows")
	}
	var parsed benchmark.ScanResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("benchmark json unmarshal failed: %v", err)
	}
	if len(parsed.Rows) != 1 || parsed.Rows[0].Actual != "Microsoft Windows 10 Test" {
		t.Fatalf("unexpected benchmark json payload: %#v", parsed)
	}
}

func TestPrintBenchmarkSummaryToTerminal(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgressWithPin(&out, "benchmark", false)
	printBenchmarkSummary(progress, benchmark.ScanResult{Template: "linux", Summary: benchmark.Summary{Total: 4, Pass: 2, Fail: 0, Unknown: 2, Informational: 1, Pending: 1, Evaluated: 2, ComplianceRate: 1.0, UnknownRate: 0.5, InformationalRate: 0.25, PendingRate: 0.25}})
	got := out.String()
	for _, want := range []string{"benchmark summary:", "template: linux", "counts", "total_checks", "compliant", "non_compliant", "informational", "pending", "rate", "compliance", "100.00%"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in summary output, got: %s", want, got)
		}
	}
	for _, unwanted := range []string{"informational_or_pending", "metric           display", "coverage_rate", "evaluable_checks", "informational_rate", "pending_rate"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("did not expect %q in summary output: %s", unwanted, got)
		}
	}
}

func TestEmitOutputBenchmarkXLSXAddsSummarySheet(t *testing.T) {
	t.Parallel()

	payload := benchmark.ScanResult{Template: "linux", Summary: benchmark.Summary{Total: 4, Pass: 2, Fail: 1, Unknown: 1, Informational: 1, Pending: 0, Evaluated: 3, ComplianceRate: 2.0 / 3.0, UnknownRate: 0.25, InformationalRate: 0.25, PendingRate: 0}, Rows: []benchmark.Row{{Template: "linux", CheckID: "1", CheckName: "1", Category: "display", Status: "pass", Actual: "ok", Evidence: "ok", Command: "uname -a"}}}
	dir := t.TempDir()
	xlsxPath := filepath.Join(dir, "benchmark.xlsx")
	if err := emitOutput(payload, xlsxPath); err != nil {
		t.Fatalf("emitOutput xlsx returned error: %v", err)
	}
	file, err := excelize.OpenFile(xlsxPath)
	if err != nil {
		t.Fatalf("open xlsx failed: %v", err)
	}
	defer func() { _ = file.Close() }()
	if sheets := file.GetSheetList(); !containsString(sheets, "results") || !containsString(sheets, "summary") {
		t.Fatalf("expected results+summary sheets, got: %#v", sheets)
	}
	if metric, _ := file.GetCellValue("summary", "A5"); metric != "待确认项" {
		t.Fatalf("unexpected summary metric A5: %q", metric)
	}
	if display, _ := file.GetCellValue("summary", "B5"); display != "0" {
		t.Fatalf("unexpected summary display B5: %q", display)
	}
	if metric, _ := file.GetCellValue("summary", "A6"); metric != "可判定项" {
		t.Fatalf("unexpected summary metric A6: %q", metric)
	}
	if display, _ := file.GetCellValue("summary", "B6"); display != "3" {
		t.Fatalf("unexpected summary display B6: %q", display)
	}
	if metric, _ := file.GetCellValue("summary", "A7"); metric != "合规率" {
		t.Fatalf("unexpected summary metric A7: %q", metric)
	}
	if display, _ := file.GetCellValue("summary", "B7"); display != "66.67%" {
		t.Fatalf("unexpected summary display B7: %q", display)
	}
	if metric, _ := file.GetCellValue("summary", "A8"); metric != "信息项占比" {
		t.Fatalf("unexpected summary metric A8: %q", metric)
	}
	if display, _ := file.GetCellValue("summary", "B8"); display != "25.00%" {
		t.Fatalf("unexpected summary display B8: %q", display)
	}
	if metric, _ := file.GetCellValue("summary", "A9"); metric != "待确认项占比" {
		t.Fatalf("unexpected summary metric A9: %q", metric)
	}
	if display, _ := file.GetCellValue("summary", "B9"); display != "0.00%" {
		t.Fatalf("unexpected summary display B9: %q", display)
	}
	if activeSheetName := file.GetSheetName(file.GetActiveSheetIndex()); activeSheetName != "results" {
		t.Fatalf("expected active sheet to be results, got: %q", activeSheetName)
	}
}

func TestWriteRiskExcelAddsSummarySheet(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "risk.xlsx")
	payload := riskanalysis.SummaryResult{
		Summary: riskanalysis.Summary{
			Total:             4,
			Critical:          1,
			High:              1,
			Pending:           1,
			SuspiciousOffline: 1,
		},
		Results: []riskanalysis.AnalysisResult{
			{ScanID: "a", RiskAssessment: riskanalysis.RiskAssessment{RiskLevel: riskanalysis.RiskLevelCritical}},
		},
	}
	if err := writeRiskExcel(path, payload); err != nil {
		t.Fatalf("writeRiskExcel returned error: %v", err)
	}

	file, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("open xlsx failed: %v", err)
	}
	defer func() { _ = file.Close() }()

	if sheets := file.GetSheetList(); !containsString(sheets, "risk_analysis") || !containsString(sheets, "summary") {
		t.Fatalf("expected risk_analysis+summary sheets, got: %#v", sheets)
	}
	if got, _ := file.GetCellValue("summary", "A1"); got != "总计" {
		t.Fatalf("unexpected summary A1: %q", got)
	}
	if got, _ := file.GetCellValue("summary", "B1"); got != "4" {
		t.Fatalf("unexpected summary B1: %q", got)
	}
}

func TestWriteRiskExcelUsesPrioritizedHeaderOrder(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "risk-order.xlsx")
	payload := riskanalysis.SummaryResult{
		Summary: riskanalysis.Summary{Total: 1, High: 1},
		Results: []riskanalysis.AnalysisResult{
			{
				TargetPath: "C:\\sample.exe",
				Hashes: riskanalysis.Hashes{
					Sha256: "abc",
				},
				RiskAssessment: riskanalysis.RiskAssessment{
					AnalysisMode: riskanalysis.ModeSmart,
					RiskScore:    88,
					RiskLevel:    riskanalysis.RiskLevelHigh,
				},
			},
		},
	}

	if err := writeRiskExcel(path, payload); err != nil {
		t.Fatalf("writeRiskExcel returned error: %v", err)
	}

	file, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("open xlsx failed: %v", err)
	}
	defer func() { _ = file.Close() }()

	want := []string{
		"target_path",
		"risk_assessment.risk_level",
		"risk_assessment.risk_score",
		"risk_assessment.analysis_mode",
		"target_type",
	}
	for i, header := range want {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		got, _ := file.GetCellValue("risk_analysis", cell)
		if got != header {
			t.Fatalf("unexpected header at %s: got %q want %q", cell, got, header)
		}
	}
}

func TestEmitOutputRiskSummaryResultXLSXUsesRiskSheets(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "risk-emit.xlsx")
	payload := riskanalysis.SummaryResult{
		Summary: riskanalysis.Summary{
			Total:    2,
			Critical: 1,
			High:     1,
		},
		Results: []riskanalysis.AnalysisResult{
			{ScanID: "a", RiskAssessment: riskanalysis.RiskAssessment{RiskLevel: riskanalysis.RiskLevelCritical}},
			{ScanID: "b", RiskAssessment: riskanalysis.RiskAssessment{RiskLevel: riskanalysis.RiskLevelHigh}},
		},
	}

	if err := emitOutput(payload, path); err != nil {
		t.Fatalf("emitOutput returned error: %v", err)
	}

	file, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("open xlsx failed: %v", err)
	}
	defer func() { _ = file.Close() }()

	if sheets := file.GetSheetList(); !containsString(sheets, "risk_analysis") || !containsString(sheets, "summary") {
		t.Fatalf("expected risk_analysis+summary sheets, got: %#v", sheets)
	}
}

func TestEmitOutputNonBenchmarkCSVDoesNotWriteSummarySidecar(t *testing.T) {
	t.Parallel()

	payload := scanAggregateResult{Total: 1, Rows: []map[string]any{{"module": "process", "name": "cmd.exe"}}}
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "hostscan.csv")
	if err := emitOutput(payload, csvPath); err != nil {
		t.Fatalf("emitOutput csv returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hostscan.summary.csv")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no summary sidecar for non-benchmark csv, err=%v", err)
	}
}

func TestOrderDisplayHeadersPrioritizesCommonOperationalFields(t *testing.T) {
	t.Parallel()

	headers := []string{
		"zeta",
		"status",
		"name",
		"hostname",
		"path",
		"displayIp",
		"version",
	}

	got := orderDisplayHeaders(headers)
	wantPrefix := []string{"displayIp", "hostname", "name", "path", "version", "status"}
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Fatalf("unexpected header at %d: got %q want %q (full=%#v)", i, got[i], want, got)
		}
	}
}
func TestEmitOutputPermissionDeniedFallsBackToStdoutJSON(t *testing.T) {

	t.Parallel()

	payload := scanAggregateResult{

		Total: 1,

		Rows: []map[string]any{

			{"module": "process", "name": "cmd.exe"},
		},
	}

	var stdout bytes.Buffer

	var stderr bytes.Buffer

	promptCalled := false

	err := emitOutputWithPrompt(payload, "result.xlsx", outputWriteSet{

		json: func(path string, payload any) error { return nil },

		csv: func(path string, rows []map[string]any) error { return nil },

		xlsx: func(path string, rows []map[string]any) error { return os.ErrPermission },
	}, &stdout, &stderr, strings.NewReader("y\n"), func(outputPath string, writeErr error, stdin io.Reader, stderr io.Writer) (bool, error) {

		promptCalled = true

		return true, nil

	})

	if err != nil {

		t.Fatalf("expected fallback success, got error: %v", err)

	}

	if !promptCalled {

		t.Fatal("expected permission fallback prompt to be called")

	}

	stdoutStr := stdout.String()

	if !strings.Contains(stdoutStr, "\"total\": 1") || !strings.Contains(stdoutStr, "\"rows\"") {

		t.Fatalf("expected fallback JSON in stdout, got: %s", stdoutStr)

	}

}

func TestEmitOutputPermissionDeniedPromptDeclineReturnsError(t *testing.T) {

	t.Parallel()

	payload := scanAggregateResult{

		Total: 1,

		Rows: []map[string]any{

			{"module": "process", "name": "cmd.exe"},
		},
	}

	var stdout bytes.Buffer

	var stderr bytes.Buffer

	err := emitOutputWithPrompt(payload, "result.xlsx", outputWriteSet{

		json: func(path string, payload any) error { return nil },

		csv: func(path string, rows []map[string]any) error { return nil },

		xlsx: func(path string, rows []map[string]any) error { return os.ErrPermission },
	}, &stdout, &stderr, strings.NewReader("n\n"), func(outputPath string, writeErr error, stdin io.Reader, stderr io.Writer) (bool, error) {

		return false, nil

	})

	if err == nil {

		t.Fatal("expected permission error when user declines fallback")

	}

	if stdout.Len() != 0 {

		t.Fatalf("expected no stdout fallback output, got: %s", stdout.String())

	}

}

func TestEmitOutputNonPermissionErrorDoesNotFallback(t *testing.T) {

	t.Parallel()

	payload := scanAggregateResult{

		Total: 1,

		Rows: []map[string]any{

			{"module": "process", "name": "cmd.exe"},
		},
	}

	var stdout bytes.Buffer

	var stderr bytes.Buffer

	writeErr := errors.New("disk full")

	err := emitOutputWithPrompt(payload, "result.xlsx", outputWriteSet{

		json: func(path string, payload any) error { return nil },

		csv: func(path string, rows []map[string]any) error { return nil },

		xlsx: func(path string, rows []map[string]any) error { return writeErr },
	}, &stdout, &stderr, strings.NewReader("y\n"), func(outputPath string, writeErr error, stdin io.Reader, stderr io.Writer) (bool, error) {

		return true, nil

	})

	if err == nil {

		t.Fatal("expected non-permission error to be returned")

	}

	if !strings.Contains(err.Error(), "disk full") {

		t.Fatalf("expected disk full error, got: %v", err)

	}

	if stdout.Len() != 0 {

		t.Fatalf("expected no stdout fallback output, got: %s", stdout.String())

	}

}

func TestWriteShardedXLSXFilesSplitsRowsAndNamesParts(t *testing.T) {

	t.Parallel()

	rows := []map[string]any{

		{"id": 1},

		{"id": 2},

		{"id": 3},

		{"id": 4},

		{"id": 5},
	}

	basePath := filepath.Join(t.TempDir(), "result.xlsx")

	calledPaths := make([]string, 0)

	calledSizes := make([]int, 0)

	paths, err := writeShardedXLSXFiles(basePath, rows, 2, func(path string, partRows []map[string]any) error {

		calledPaths = append(calledPaths, path)

		calledSizes = append(calledSizes, len(partRows))

		return nil

	})

	if err != nil {

		t.Fatalf("writeShardedXLSXFiles returned error: %v", err)

	}

	wantPaths := []string{

		filepath.Join(filepath.Dir(basePath), "result_part1.xlsx"),

		filepath.Join(filepath.Dir(basePath), "result_part2.xlsx"),

		filepath.Join(filepath.Dir(basePath), "result_part3.xlsx"),
	}

	wantSizes := []int{2, 2, 1}

	if !reflect.DeepEqual(paths, wantPaths) {

		t.Fatalf("unexpected written paths: got=%v want=%v", paths, wantPaths)

	}

	if !reflect.DeepEqual(calledPaths, wantPaths) {

		t.Fatalf("unexpected writer called paths: got=%v want=%v", calledPaths, wantPaths)

	}

	if !reflect.DeepEqual(calledSizes, wantSizes) {

		t.Fatalf("unexpected shard sizes: got=%v want=%v", calledSizes, wantSizes)

	}

}

func TestWriteShardedXLSXFilesSinglePartKeepsOriginalName(t *testing.T) {

	t.Parallel()

	rows := []map[string]any{

		{"id": 1},

		{"id": 2},
	}

	basePath := filepath.Join(t.TempDir(), "result.xlsx")

	calledPaths := make([]string, 0)

	paths, err := writeShardedXLSXFiles(basePath, rows, 10, func(path string, partRows []map[string]any) error {

		calledPaths = append(calledPaths, path)

		return nil

	})

	if err != nil {

		t.Fatalf("writeShardedXLSXFiles returned error: %v", err)

	}

	wantPaths := []string{basePath}

	if !reflect.DeepEqual(paths, wantPaths) {

		t.Fatalf("unexpected written paths: got=%v want=%v", paths, wantPaths)

	}

	if !reflect.DeepEqual(calledPaths, wantPaths) {

		t.Fatalf("unexpected writer called paths: got=%v want=%v", calledPaths, wantPaths)

	}

}

func TestEmitGeneratedFileHintsForShardedOutput(t *testing.T) {

	t.Parallel()

	paths := []string{"result_part1.xlsx", "result_part2.xlsx"}

	var stderr bytes.Buffer

	emitGeneratedFileHints(&stderr, paths, false)

	out := stderr.String()

	if !strings.Contains(out, "generated file: result_part1.xlsx") {

		t.Fatalf("expected first generated file hint, got: %s", out)

	}

	if !strings.Contains(out, "generated file: result_part2.xlsx") {

		t.Fatalf("expected second generated file hint, got: %s", out)

	}

}

func TestValidateXLSXShapeLimits(t *testing.T) {

	t.Parallel()

	if err := validateXLSXShape(xlsxMaxRows-1, xlsxMaxColumns); err != nil {

		t.Fatalf("expected limits to pass, got: %v", err)

	}

	if err := validateXLSXShape(xlsxMaxRows, 1); err == nil || !strings.Contains(err.Error(), "row limit") {

		t.Fatalf("expected row limit error, got: %v", err)

	}

	if err := validateXLSXShape(1, xlsxMaxColumns+1); err == nil || !strings.Contains(err.Error(), "column limit") {

		t.Fatalf("expected column limit error, got: %v", err)

	}

}

func TestCompactWriteErrorMessageTrimsDuplicatedOpenPrefix(t *testing.T) {

	t.Parallel()

	path := `D:\tmp\result.xlsx`

	err := fmt.Errorf("open %s: Access is denied.", path)

	got := compactWriteErrorMessage(path, err)

	if got != "Access is denied." {

		t.Fatalf("expected trimmed message, got %q", got)

	}

}

func TestCompactWriteErrorMessageFallsBackToRawError(t *testing.T) {

	t.Parallel()

	err := errors.New("disk full")

	got := compactWriteErrorMessage(`D:\tmp\result.xlsx`, err)

	if got != "disk full" {

		t.Fatalf("expected raw message fallback, got %q", got)

	}

}

func TestCompactScanTargetErrorMessageTrimsOpenPrefix(t *testing.T) {

	t.Parallel()

	path := `D:\secure\secret.dll`

	err := fmt.Errorf("open %s: Access is denied.", path)

	got := compactScanTargetErrorMessage(path, err)

	if got != "Access is denied." {

		t.Fatalf("expected trimmed message, got %q", got)

	}

}

func TestCompactScanTargetErrorMessageFallsBackToRaw(t *testing.T) {

	t.Parallel()

	err := errors.New("input/output timeout")

	got := compactScanTargetErrorMessage(`D:\secure\secret.dll`, err)

	if got != "input/output timeout" {

		t.Fatalf("expected raw message fallback, got %q", got)

	}

}

func TestExecuteHostscanSkipsFailedModuleAndContinues(t *testing.T) {

	t.Parallel()

	parsed := hostscanParseResult{

		Modules: []string{"invalid-hostscan-module"},

		MultiMode: false,

		ModuleArgs: nil,
	}

	var progressOut bytes.Buffer

	result, records, err := executeHostscan(parsed, false, 0, newTerminalProgress(&progressOut, "hostscan"))

	if err != nil {

		t.Fatalf("expected nil error for module failure, got: %v", err)

	}

	if result.Total != 0 || len(result.Rows) != 0 {

		t.Fatalf("expected empty aggregated result, got total=%d rows=%d", result.Total, len(result.Rows))

	}

	if len(records) != 0 {

		t.Fatalf("expected no risk records, got %d", len(records))

	}

	output := progressOut.String()

	if !strings.Contains(output, "[WARN] hostscan module invalid-hostscan-module failed:") {

		t.Fatalf("expected failed-module log line, got: %s", output)

	}

	if !strings.Contains(output, "[WARN] hostscan skipped 1 failed module(s)") {

		t.Fatalf("expected skipped warning line, got: %s", output)

	}

}

func TestExecuteFilescanWebModeSkipsFailedModuleAndContinues(t *testing.T) {

	t.Parallel()

	parsed := filescanParseResult{

		WebModules: []string{"invalid-filescan-module"},

		ModuleArgs: nil,
	}

	var progressOut bytes.Buffer

	result, records, err := executeFilescanWebMode(parsed, newTerminalProgress(&progressOut, "filescan"))

	if err != nil {

		t.Fatalf("expected nil error for module failure, got: %v", err)

	}

	if result.Total != 0 || len(result.Rows) != 0 {

		t.Fatalf("expected empty aggregated result, got total=%d rows=%d", result.Total, len(result.Rows))

	}

	if len(records) != 0 {

		t.Fatalf("expected no risk records, got %d", len(records))

	}

	output := progressOut.String()

	if !strings.Contains(output, "[WARN] filescan module invalid-filescan-module failed:") {

		t.Fatalf("expected failed-module log line, got: %s", output)

	}

	if !strings.Contains(output, "[WARN] filescan skipped 1 failed module(s)") {

		t.Fatalf("expected skipped warning line, got: %s", output)

	}

}

func TestMapRowsToRiskRecordsWithPathCandidates(t *testing.T) {

	t.Parallel()

	rows := []map[string]any{

		{

			"hostname": "node-a",

			"execPath": "/usr/bin/python3",

			"conf": "/etc/crontab",
		},
	}

	records := mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"execPath", "conf"})

	if len(records) != 2 {

		t.Fatalf("expected 2 records, got %d", len(records))

	}

	got := map[string]bool{}

	for _, record := range records {

		if record.Raw["target_type"] != "file" {

			t.Fatalf("expected target_type=file, got %#v", record.Raw["target_type"])

		}

		path, _ := record.Raw["target_path"].(string)

		got[path] = true

	}

	if !got["/usr/bin/python3"] || !got["/etc/crontab"] {

		t.Fatalf("unexpected target paths: %#v", got)

	}

}

func TestMapRowsToRiskRecordsWithPathCandidatesFallback(t *testing.T) {

	t.Parallel()

	rows := []map[string]any{

		{"hostname": "node-a", "name": "service-a"},
	}

	records := mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"execPath"})

	if len(records) != 1 {

		t.Fatalf("expected 1 record, got %d", len(records))

	}

	if records[0].Raw["target_type"] != "file" {

		t.Fatalf("expected target_type=file, got %#v", records[0].Raw["target_type"])

	}

	if _, ok := records[0].Raw["target_path"]; ok {

		t.Fatalf("expected no target_path, got %#v", records[0].Raw["target_path"])

	}

}

func TestMapRowsToRiskRecordsWithSoftwarePathCandidates(t *testing.T) {

	t.Parallel()

	rows := []map[string]any{

		{

			"name": "nginx",

			"binPath": "/usr/sbin/nginx",

			"configPath": "/etc/nginx/nginx.conf",
		},
	}

	records := mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"binPath", "configPath"})

	if len(records) != 2 {

		t.Fatalf("expected 2 records, got %d", len(records))

	}

	got := map[string]bool{}

	for _, record := range records {

		if record.Raw["target_type"] != "file" {

			t.Fatalf("expected target_type=file, got %#v", record.Raw["target_type"])

		}

		path, _ := record.Raw["target_path"].(string)

		got[path] = true

	}

	if !got["/usr/sbin/nginx"] || !got["/etc/nginx/nginx.conf"] {

		t.Fatalf("unexpected target paths: %#v", got)

	}

}

func TestAnalyzeRiskResultsEmptyOverrideRecords(t *testing.T) {

	t.Parallel()

	results, err := analyzeRiskResults(riskOptions{Mode: "local_only"}, []riskanalysis.ScanRecord{}, nil)

	if err != nil {

		t.Fatalf("analyzeRiskResults returned error: %v", err)

	}

	if len(results) != 0 {

		t.Fatalf("expected empty results, got %d", len(results))

	}

}

func TestRiskSummaryResultJSONShape(t *testing.T) {

	t.Parallel()

	payload := riskanalysis.SummaryResult{
		Summary: riskanalysis.Summary{
			Total:    2,
			Critical: 1,
			High:     1,
		},
		Results: []riskanalysis.AnalysisResult{
			{ScanID: "a", RiskAssessment: riskanalysis.RiskAssessment{RiskLevel: riskanalysis.RiskLevelCritical}},
			{ScanID: "b", RiskAssessment: riskanalysis.RiskAssessment{RiskLevel: riskanalysis.RiskLevelHigh}},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if _, ok := doc["summary"]; !ok {
		t.Fatalf("expected summary field in payload: %s", string(data))
	}
	if _, ok := doc["results"]; !ok {
		t.Fatalf("expected results field in payload: %s", string(data))
	}
}

func TestClassifyRiskSeverityBand(t *testing.T) {

	t.Parallel()

	cases := []struct {
		name string

		in riskanalysis.RiskAssessment

		want riskSeverityBand
	}{

		{

			name: "critical is high",

			in: riskanalysis.RiskAssessment{

				RiskLevel: riskanalysis.RiskLevelCritical,
			},

			want: riskSeverityHigh,
		},

		{

			name: "medium level",

			in: riskanalysis.RiskAssessment{

				RiskLevel: riskanalysis.RiskLevelMedium,
			},

			want: riskSeverityMedium,
		},

		{

			name: "low level",

			in: riskanalysis.RiskAssessment{

				RiskLevel: riskanalysis.RiskLevelLow,
			},

			want: riskSeverityLow,
		},

		{

			name: "fallback by score",

			in: riskanalysis.RiskAssessment{

				RiskLevel: "unknown",

				RiskScore: 88,
			},

			want: riskSeverityHigh,
		},

		{

			name: "none by score",

			in: riskanalysis.RiskAssessment{

				RiskLevel: "unknown",

				RiskScore: 10,
			},

			want: riskSeverityNone,
		},
	}

	for _, tc := range cases {

		tc := tc

		t.Run(tc.name, func(t *testing.T) {

			t.Parallel()

			if got := classifyRiskSeverityBand(tc.in); got != tc.want {

				t.Fatalf("expected %v, got %v", tc.want, got)

			}

		})

	}

}

func TestFormatRiskStreamLineIncludesBasicInfo(t *testing.T) {

	t.Parallel()

	size := int64(2048)

	result := riskanalysis.AnalysisResult{

		TargetPath: "C:\\test\\a.exe",

		FileSize: &size,

		Hashes: riskanalysis.Hashes{

			Sha256: "abc123",
		},

		LocalAnalysis: &riskanalysis.LocalAnalysis{

			YaraResults: []riskanalysis.YaraRuleMatch{{RuleName: "Test.Rule"}},
		},
	}

	line := formatRiskStreamLine(result, riskSeverityHigh, false)

	if !strings.Contains(line, "[HIGH]") {

		t.Fatalf("expected high label, got %q", line)

	}

	if !strings.Contains(line, "path=C:\\test\\a.exe") {

		t.Fatalf("expected path, got %q", line)

	}

	if !strings.Contains(line, "size=2.0 KB") {

		t.Fatalf("expected formatted size, got %q", line)

	}

	if !strings.Contains(line, "sha256=abc123") {

		t.Fatalf("expected sha256, got %q", line)

	}

	if !strings.Contains(line, "rule=Test.Rule") {

		t.Fatalf("expected rule, got %q", line)

	}

}

func TestPrintRiskStreamSummaryIncludesExtendedCategories(t *testing.T) {

	t.Parallel()

	var out bytes.Buffer
	progress := newTerminalProgressWithPin(&out, "risk", false)
	printRiskStreamSummary(progress, riskanalysis.Summary{
		Total:             5,
		Critical:          1,
		High:              1,
		Low:               1,
		Pending:           1,
		SuspiciousOffline: 1,
	})
	got := out.String()
	for _, want := range []string{"Risk Summary:", "Total risky files: 5", "CRITICAL: 1", "HIGH: 1", "LOW: 1", "PENDING: 1", "SUSPICIOUS_OFFLINE: 1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in summary output, got: %s", want, got)
		}
	}
}

func TestStandaloneRiskCLIStreamsRiskFindingsAndPreservesJSONOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"query_status":"ok","data":[{"sha256_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"trojan.webshell","tags":["webshell"]}]}`)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "cloud.json")
	inputPath := filepath.Join(tempDir, "risk-input.json")
	outputPath := filepath.Join(t.TempDir(), "risk-output.json")
	config := fmt.Sprintf(`{"providers":{"malwarebazaar":{"api_key":"test-key","base_url":"%s"}}}`, server.URL)
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {

		t.Fatalf("write cloud config: %v", err)
	}
	input := `[{"target_type":"file","target_path":"C:/tmp/bad.exe","hashes":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]`
	if err := os.WriteFile(inputPath, []byte(input), 0o644); err != nil {

		t.Fatalf("write input json: %v", err)
	}
	t.Setenv("C_EYES_CLOUD_CONFIG", configPath)

	code, stderr := runUnifiedCLIWithCapturedStderr(t, []string{"-r", "-risk-mode", "cloud_only", "-o", outputPath, "-input", inputPath})
	if code != 0 {

		t.Fatalf("expected exit code 0, got %d, stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "[HIGH]") {

		t.Fatalf("expected streamed high-risk line in stderr, got: %s", stderr)
	}
	if !strings.Contains(stderr, "path=C:/tmp/bad.exe") {

		t.Fatalf("expected streamed target path in stderr, got: %s", stderr)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {

		t.Fatalf("read output json: %v", err)
	}
	var payload []riskanalysis.AnalysisResult
	if err := json.Unmarshal(data, &payload); err != nil {

		t.Fatalf("unmarshal output json: %v, payload=%s", err, string(data))
	}
	if len(payload) != 1 {

		t.Fatalf("expected 1 result, got %d", len(payload))
	}
	level := payload[0].RiskAssessment.RiskLevel
	if level != riskanalysis.RiskLevelHigh && level != riskanalysis.RiskLevelCritical {

		t.Fatalf("expected high or critical risk level, got %s", level)
	}
}

func TestCompactSHA256(t *testing.T) {

	t.Parallel()

	full := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	got := compactSHA256(full)

	if got != "0123456789ab...89abcdef" {

		t.Fatalf("unexpected compact hash: %q", got)

	}

}

func TestCompactMiddleTruncatesLongPath(t *testing.T) {

	t.Parallel()

	value := "C:\\very\\long\\path\\to\\something\\binary\\that\\is\\too\\long\\sample.exe"

	got := compactMiddle(value, 36)

	if len([]rune(got)) > 36 {

		t.Fatalf("expected compact length <= 36, got %d (%q)", len([]rune(got)), got)

	}

	if !strings.Contains(got, "...") {

		t.Fatalf("expected compact marker, got %q", got)

	}

}

func TestNextAutoExcelOutputPathEmptyDir(t *testing.T) {

	t.Parallel()

	dir := t.TempDir()

	got, err := nextAutoExcelOutputPath(dir)

	if err != nil {

		t.Fatalf("nextAutoExcelOutputPath returned error: %v", err)

	}

	want := filepath.Join(dir, "result.xlsx")

	if got != want {

		t.Fatalf("expected %q, got %q", want, got)

	}

}

func TestNextAutoExcelOutputPathWithResultOnly(t *testing.T) {

	t.Parallel()

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "result.xlsx"), []byte("x"), 0o600); err != nil {

		t.Fatalf("write result.xlsx: %v", err)

	}

	got, err := nextAutoExcelOutputPath(dir)

	if err != nil {

		t.Fatalf("nextAutoExcelOutputPath returned error: %v", err)

	}

	want := filepath.Join(dir, "result1.xlsx")

	if got != want {

		t.Fatalf("expected %q, got %q", want, got)

	}

}

func TestNextAutoExcelOutputPathWithResultOneUsesMaxPlusOne(t *testing.T) {

	t.Parallel()

	dir := t.TempDir()

	seed := []string{"result.xlsx", "result1.xlsx", "result2.xlsx", "result9.xlsx"}

	for _, name := range seed {

		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {

			t.Fatalf("write %s: %v", name, err)

		}

	}

	got, err := nextAutoExcelOutputPath(dir)

	if err != nil {

		t.Fatalf("nextAutoExcelOutputPath returned error: %v", err)

	}

	want := filepath.Join(dir, "result10.xlsx")

	if got != want {

		t.Fatalf("expected %q, got %q", want, got)

	}

}

func TestNextAutoJSONOutputPathEmptyDir(t *testing.T) {

	t.Parallel()

	dir := t.TempDir()

	got, err := nextAutoJSONOutputPath(dir)

	if err != nil {

		t.Fatalf("nextAutoJSONOutputPath returned error: %v", err)

	}

	want := filepath.Join(dir, "result.json")

	if got != want {

		t.Fatalf("expected %q, got %q", want, got)

	}

}

func TestNextAutoJSONOutputPathWithResultOnly(t *testing.T) {

	t.Parallel()

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "result.json"), []byte("x"), 0o600); err != nil {

		t.Fatalf("write result.json: %v", err)

	}

	got, err := nextAutoJSONOutputPath(dir)

	if err != nil {

		t.Fatalf("nextAutoJSONOutputPath returned error: %v", err)

	}

	want := filepath.Join(dir, "result1.json")

	if got != want {

		t.Fatalf("expected %q, got %q", want, got)

	}

}

func TestNextAutoJSONOutputPathWithResultOneUsesMaxPlusOne(t *testing.T) {

	t.Parallel()

	dir := t.TempDir()

	seed := []string{"result.json", "result1.json", "result2.json", "result9.json"}

	for _, name := range seed {

		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {

			t.Fatalf("write %s: %v", name, err)

		}

	}

	got, err := nextAutoJSONOutputPath(dir)

	if err != nil {

		t.Fatalf("nextAutoJSONOutputPath returned error: %v", err)

	}

	want := filepath.Join(dir, "result10.json")

	if got != want {

		t.Fatalf("expected %q, got %q", want, got)

	}

}

func TestResolveOutputPathAutoSBOMSentinel(t *testing.T) {

	dir := t.TempDir()

	orig, err := os.Getwd()

	if err != nil {

		t.Fatalf("Getwd failed: %v", err)

	}

	if err := os.Chdir(dir); err != nil {

		t.Fatalf("chdir temp dir failed: %v", err)

	}

	defer func() {

		_ = os.Chdir(orig)

	}()

	resolved, autoGenerated, err := resolveOutputPath(autoSBOMOutputSentinel)

	if err != nil {

		t.Fatalf("resolveOutputPath returned error: %v", err)

	}

	if !autoGenerated {

		t.Fatal("expected autoGenerated=true for sbom sentinel")

	}

	want := filepath.Join(dir, "result.json")

	if resolved != want {

		t.Fatalf("expected %q, got %q", want, resolved)

	}

}

func TestParseEventlogArgsAcceptsMaxLogs(t *testing.T) {

	t.Parallel()

	parsed, err := parseEventlogArgs([]string{"-last", "7d", "-maxLogs", "25"})

	if err != nil {

		t.Fatalf("parseEventlogArgs returned error: %v", err)

	}

	if parsed.Params.MaxLogs != 25 {

		t.Fatalf("expected maxLogs=25, got %d", parsed.Params.MaxLogs)

	}

}

func TestParseEventlogArgsRejectsNegativeMaxLogs(t *testing.T) {

	t.Parallel()

	_, err := parseEventlogArgs([]string{"-last", "7d", "-maxLogs", "-1"})

	if err == nil || !strings.Contains(err.Error(), "maxLogs must be >= 0") {

		t.Fatalf("expected maxLogs validation error, got: %v", err)

	}

}

func TestRunUnifiedCLIEventlogShowsProgress(t *testing.T) {

	originalExport := eventlogExportFunc

	eventlogExportFunc = func(_ context.Context, params eventlogscan.QueryParams) (*eventlogscan.ExportResult, error) {

		if params.Progress == nil {

			t.Fatal("expected eventlog progress callback to be wired")

		}

		params.Progress(0, 2, "collect_events")

		params.Progress(1, 2, "collect_system")

		params.Progress(2, 2, "complete")

		spoolDir := t.TempDir()
		rowsPath := filepath.Join(spoolDir, "rows.jsonl")
		row := eventlogscan.EventRow{
			LogID:          "a",
			Timestamp:      1,
			Source:         "system",
			EventType:      "system",
			EventLevel:     "info",
			EventCode:      "1",
			EventAction:    "start",
			Result:         "success",
			OSType:         "linux",
			InternalIPList: []string{},
			ExternalIPList: []string{},
		}
		rowBytes, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("marshal row failed: %v", err)
		}
		if err := os.WriteFile(rowsPath, append(rowBytes, '\n'), 0o600); err != nil {
			t.Fatalf("write rows file failed: %v", err)
		}

		return &eventlogscan.ExportResult{
			Total:    1,
			RowsPath: rowsPath,
			SpoolDir: spoolDir,
		}, nil

	}

	t.Cleanup(func() {

		eventlogExportFunc = originalExport

	})

	outputPath := filepath.Join(t.TempDir(), "eventlog.json")

	code, stderr := runUnifiedCLIWithCapturedStderr(t, []string{"-o", outputPath, "eventlog", "-last", "7d"})

	if code != 0 {

		t.Fatalf("expected exit code 0, got %d, stderr=%s", code, stderr)

	}

	if !strings.Contains(stderr, "eventlog [") {

		t.Fatalf("expected eventlog progress output, got: %s", stderr)

	}

	if !strings.Contains(stderr, "collect_system") {

		t.Fatalf("expected eventlog progress stage in stderr, got: %s", stderr)

	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read eventlog json failed: %v", err)
	}
	if !strings.Contains(string(data), "\"rows\"") || !strings.Contains(string(data), "\"total\": 1") {
		t.Fatalf("unexpected eventlog json output: %s", string(data))
	}

}

func TestRunUnifiedCLIEventlogCSVAndXLSXOutput(t *testing.T) {
	originalExport := eventlogExportFunc
	eventlogExportFunc = func(_ context.Context, _ eventlogscan.QueryParams) (*eventlogscan.ExportResult, error) {
		spoolDir := t.TempDir()
		rowsPath := filepath.Join(spoolDir, "rows.jsonl")
		rows := []eventlogscan.EventRow{
			{LogID: "a", Timestamp: 2, Source: "system", EventType: "system", EventLevel: "info", EventCode: "1", EventAction: "start", Result: "success", OSType: "linux", InternalIPList: []string{}, ExternalIPList: []string{}},
			{LogID: "b", Timestamp: 1, Source: "system", EventType: "system", EventLevel: "warn", EventCode: "2", EventAction: "stop", Result: "fail", OSType: "linux", InternalIPList: []string{}, ExternalIPList: []string{}},
		}
		var data []byte
		for _, row := range rows {
			rowBytes, err := json.Marshal(row)
			if err != nil {
				t.Fatalf("marshal row failed: %v", err)
			}
			data = append(data, rowBytes...)
			data = append(data, '\n')
		}
		if err := os.WriteFile(rowsPath, data, 0o600); err != nil {
			t.Fatalf("write rows file failed: %v", err)
		}
		return &eventlogscan.ExportResult{Total: len(rows), RowsPath: rowsPath, SpoolDir: spoolDir}, nil
	}
	t.Cleanup(func() { eventlogExportFunc = originalExport })

	csvPath := filepath.Join(t.TempDir(), "eventlog.csv")
	code, stderr := runUnifiedCLIWithCapturedStderr(t, []string{"-o", csvPath, "eventlog", "-last", "7d"})
	if code != 0 {
		t.Fatalf("expected csv exit code 0, got %d, stderr=%s", code, stderr)
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("read csv failed: %v", err)
	}
	if !strings.Contains(string(csvData), "logId") || !strings.Contains(string(csvData), "timestamp") {
		t.Fatalf("unexpected csv content: %s", string(csvData))
	}

	xlsxPath := filepath.Join(t.TempDir(), "eventlog.xlsx")
	code, stderr = runUnifiedCLIWithCapturedStderr(t, []string{"-o", xlsxPath, "eventlog", "-last", "7d"})
	if code != 0 {
		t.Fatalf("expected xlsx exit code 0, got %d, stderr=%s", code, stderr)
	}
	if _, err := os.Stat(xlsxPath); err != nil {
		t.Fatalf("expected xlsx file exists: %v", err)
	}
}

func TestParseSBOMArgsRequiresExactlyOneTarget(t *testing.T) {

	t.Parallel()

	_, err := parseSBOMArgs([]string{"--format", "xspdx-json"})
	if err == nil {
		t.Fatal("expected missing target error")
	}
	if !strings.Contains(err.Error(), "exactly one target") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSBOMArgsRejectsMultipleTargets(t *testing.T) {

	t.Parallel()

	_, err := parseSBOMArgs([]string{"-p", "demo", "--image-target", "nginx:1.27"})
	if err == nil {
		t.Fatal("expected mutually exclusive target error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSBOMArgsAcceptsImageTarget(t *testing.T) {

	t.Parallel()

	parsed, err := parseSBOMArgs([]string{"--image-target", "image.tar"})
	if err != nil {
		t.Fatalf("parseSBOMArgs returned error: %v", err)
	}
	if parsed.ImageTarget != "image.tar" {
		t.Fatalf("unexpected image target: %#v", parsed)
	}
	if parsed.Path != "" {
		t.Fatalf("expected only image target set, got %#v", parsed)
	}
	if parsed.TargetType != sbom.TargetTypeAuto {
		t.Fatalf("expected auto target type, got %#v", parsed)
	}
}

func TestParseSBOMArgsAcceptsLegacyImageArchiveTarget(t *testing.T) {

	t.Parallel()

	parsed, err := parseSBOMArgs([]string{"--image-archive", "image.tar"})
	if err != nil {
		t.Fatalf("parseSBOMArgs returned error: %v", err)
	}
	if parsed.ImageTarget != "image.tar" {
		t.Fatalf("unexpected image archive target: %#v", parsed)
	}
	if parsed.TargetType != sbom.TargetTypeArchive {
		t.Fatalf("expected archive target type, got %#v", parsed)
	}
}

func TestParseSBOMArgsAcceptsLegacyOCILayoutTarget(t *testing.T) {

	t.Parallel()

	parsed, err := parseSBOMArgs([]string{"--oci-layout", "layout-dir"})
	if err != nil {
		t.Fatalf("parseSBOMArgs returned error: %v", err)
	}
	if parsed.ImageTarget != "layout-dir" {
		t.Fatalf("unexpected OCI layout target: %#v", parsed)
	}
	if parsed.TargetType != sbom.TargetTypeOCILayout {
		t.Fatalf("expected OCI layout target type, got %#v", parsed)
	}
}

func TestParseSBOMArgsAcceptsLegacyImageReferenceTarget(t *testing.T) {

	t.Parallel()

	parsed, err := parseSBOMArgs([]string{"--image", "nginx:1.27"})
	if err != nil {
		t.Fatalf("parseSBOMArgs returned error: %v", err)
	}
	if parsed.ImageTarget != "nginx:1.27" {
		t.Fatalf("unexpected image target: %#v", parsed)
	}
	if parsed.TargetType != sbom.TargetTypeImage {
		t.Fatalf("expected image target type, got %#v", parsed)
	}
}

func TestParseSBOMArgsRejectsTargetTypeWithPath(t *testing.T) {

	t.Parallel()

	_, err := parseSBOMArgs([]string{"-p", "demo", "--target-type", "archive"})
	if err == nil {
		t.Fatal("expected path and target-type conflict")
	}
	if !strings.Contains(err.Error(), "cannot be used with -p/--path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSBOMArgsRejectsStandaloneTargetType(t *testing.T) {

	t.Parallel()

	_, err := parseSBOMArgs([]string{"--target-type", "image"})
	if err == nil {
		t.Fatal("expected target-type requires image-target error")
	}
	if !strings.Contains(err.Error(), "requires --image-target") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSBOMArgsAcceptsExplicitTargetType(t *testing.T) {

	t.Parallel()

	parsed, err := parseSBOMArgs([]string{"--image-target", "layout-dir", "--target-type", "oci-layout"})
	if err != nil {
		t.Fatalf("parseSBOMArgs returned error: %v", err)
	}
	if parsed.ImageTarget != "layout-dir" || parsed.TargetType != sbom.TargetTypeOCILayout {
		t.Fatalf("unexpected parsed target: %#v", parsed)
	}
}

func TestResolveModuleWorkerLimitHonorsEnv(t *testing.T) {

	t.Setenv("C_EYES_MODULE_WORKERS", "3")

	if got := resolveModuleWorkerLimit(10); got != 3 {

		t.Fatalf("expected env worker limit 3, got %d", got)

	}

}

func TestResolveModuleWorkerLimitClampsToModuleCount(t *testing.T) {

	t.Setenv("C_EYES_MODULE_WORKERS", "8")

	if got := resolveModuleWorkerLimit(2); got != 2 {

		t.Fatalf("expected clamp to module count 2, got %d", got)

	}

}

func TestResolveModuleWorkerProfileForcedWorkersDisablesAdaptive(t *testing.T) {

	t.Setenv("C_EYES_MODULE_WORKERS", "3")

	profile := resolveModuleWorkerProfile(10)

	if profile.min != 3 || profile.initial != 3 || profile.max != 3 {

		t.Fatalf("unexpected fixed profile: %+v", profile)

	}

	if profile.adaptive {

		t.Fatal("expected adaptive=false when fixed workers are forced")

	}

}

func TestResolveModuleWorkerProfileDisableAdaptiveEnv(t *testing.T) {

	t.Setenv("C_EYES_MODULE_DISABLE_ADAPTIVE", "true")

	profile := resolveModuleWorkerProfile(6)

	if profile.adaptive {

		t.Fatal("expected adaptive disabled by env")

	}

	if profile.max < profile.initial || profile.initial < profile.min {

		t.Fatalf("invalid profile bounds: %+v", profile)

	}

}

func TestDecideNextModuleWorkerLimit(t *testing.T) {

	profile := moduleWorkerProfile{

		min: 1,

		max: 6,

		cpuHigh: 0.90,

		cpuLow: 0.60,

		memHighBytes: moduleMiBToBytes(2048),

		memLowBytes: moduleMiBToBytes(512),
	}

	up := decideNextModuleWorkerLimit(2, 20, moduleRuntimeStats{

		cpuUtilization: 0.20,

		cpuValid: true,

		memoryBytes: moduleMiBToBytes(256),
	}, profile)

	if up != 3 {

		t.Fatalf("expected scale up to 3, got %d", up)

	}

	down := decideNextModuleWorkerLimit(4, 20, moduleRuntimeStats{

		cpuUtilization: 0.95,

		cpuValid: true,

		memoryBytes: moduleMiBToBytes(256),
	}, profile)

	if down != 3 {

		t.Fatalf("expected scale down to 3 on high cpu, got %d", down)

	}

	memDown := decideNextModuleWorkerLimit(3, 20, moduleRuntimeStats{

		cpuUtilization: 0.10,

		cpuValid: true,

		memoryBytes: moduleMiBToBytes(2500),
	}, profile)

	if memDown != 2 {

		t.Fatalf("expected scale down to 2 on high memory, got %d", memDown)

	}

}

func legacyAnySliceToMapRows(values any) ([]map[string]any, error) {

	rv := reflect.ValueOf(values)

	for rv.Kind() == reflect.Pointer {

		if rv.IsNil() {

			return nil, nil

		}

		rv = rv.Elem()

	}

	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {

		return nil, nil

	}

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

func collectHeadersLegacy(rows []map[string]any) []string {

	headerSet := make(map[string]struct{})

	for _, row := range rows {

		flat := flattenRow(row)

		for key := range flat {

			headerSet[key] = struct{}{}

		}

	}

	headers := make([]string, 0, len(headerSet))

	for key := range headerSet {

		headers = append(headers, key)

	}

	sort.Strings(headers)

	return headers

}

func runUnifiedCLIWithCapturedStderr(t *testing.T, args []string) (int, string) {

	t.Helper()

	originalStderr := os.Stderr

	reader, writer, err := os.Pipe()

	if err != nil {

		t.Fatalf("os.Pipe error: %v", err)

	}

	os.Stderr = writer

	outputC := make(chan string, 1)

	go func() {

		data, _ := io.ReadAll(reader)

		outputC <- string(data)

	}()

	code := runUnifiedCLI(args)

	_ = writer.Close()

	output := <-outputC

	_ = reader.Close()

	os.Stderr = originalStderr

	return code, output

}

func containsString(values []string, want string) bool {

	for _, value := range values {

		if value == want {

			return true

		}

	}

	return false

}

func fileSizeOrZero(info os.FileInfo) int64 {

	if info == nil {

		return 0

	}

	return info.Size()

}
