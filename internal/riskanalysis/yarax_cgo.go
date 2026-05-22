//go:build yarax && cgo

package riskanalysis

/*
#cgo windows CFLAGS: -I${SRCDIR}/../../third_party/yara-x-dist/include
#cgo windows LDFLAGS: -L${SRCDIR}/../../third_party/yara-x-dist/lib -lyara_x_capi
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <yara_x.h>

#ifdef _WIN32
#define CGO_EXPORT __declspec(dllexport)
#else
#define CGO_EXPORT
#endif

extern CGO_EXPORT void goYaraXOnMatchingRule(struct YRX_RULE* rule, void* user_data);
static void yarax_on_matching_rule(const struct YRX_RULE* rule, void* user_data) {
    goYaraXOnMatchingRule((struct YRX_RULE*)rule, user_data);
}

extern CGO_EXPORT void goYaraXOnTag(char* tag, void* user_data);
static void yarax_on_tag(const char* tag, void* user_data) {
    goYaraXOnTag((char*)tag, user_data);
}

extern CGO_EXPORT void goYaraXOnMetadata(struct YRX_METADATA* metadata, void* user_data);
static void yarax_on_metadata(const struct YRX_METADATA* metadata, void* user_data) {
    goYaraXOnMetadata((struct YRX_METADATA*)metadata, user_data);
}

extern CGO_EXPORT void goYaraXOnPattern(struct YRX_PATTERN* pattern, void* user_data);
static void yarax_on_pattern(const struct YRX_PATTERN* pattern, void* user_data) {
    goYaraXOnPattern((struct YRX_PATTERN*)pattern, user_data);
}

extern CGO_EXPORT void goYaraXOnMatch(struct YRX_MATCH* match, void* user_data);
static void yarax_on_match(const struct YRX_MATCH* match, void* user_data) {
    goYaraXOnMatch((struct YRX_MATCH*)match, user_data);
}

static int64_t yarax_metadata_i64(const struct YRX_METADATA* metadata) {
    return metadata->value.i64;
}

static double yarax_metadata_f64(const struct YRX_METADATA* metadata) {
    return metadata->value.f64;
}

static bool yarax_metadata_bool(const struct YRX_METADATA* metadata) {
    return metadata->value.boolean;
}

static const char* yarax_metadata_string(const struct YRX_METADATA* metadata) {
    return metadata->value.string;
}

static enum YRX_RESULT yarax_scanner_on_matching_rule(struct YRX_SCANNER *scanner, void *user_data) {
    return yrx_scanner_on_matching_rule(scanner, yarax_on_matching_rule, user_data);
}

static enum YRX_RESULT yarax_rule_iter_tags(const struct YRX_RULE *rule, void *user_data) {
    return yrx_rule_iter_tags(rule, yarax_on_tag, user_data);
}

static enum YRX_RESULT yarax_rule_iter_metadata(const struct YRX_RULE *rule, void *user_data) {
    return yrx_rule_iter_metadata(rule, yarax_on_metadata, user_data);
}

static enum YRX_RESULT yarax_rule_iter_patterns(const struct YRX_RULE *rule, void *user_data) {
    return yrx_rule_iter_patterns(rule, yarax_on_pattern, user_data);
}

static enum YRX_RESULT yarax_pattern_iter_matches(const struct YRX_PATTERN *pattern, void *user_data) {
    return yrx_pattern_iter_matches(pattern, yarax_on_match, user_data);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/cgo"
	"sort"
	"strings"
	"unsafe"
)

// YaraXConfig describes local rule settings.
type YaraXConfig struct {
	RulesPath     string
	ReadChunkSize int
}

type yaraXEngine struct {
	rulesPath     string
	rules         *C.struct_YRX_RULES
	readChunkSize int
}

const maxMatchedStrings = 20

// NewYaraXEngine compiles rules and returns a ready-to-scan YARA-X engine.
func NewYaraXEngine(config YaraXConfig) (YaraXEngine, error) {
	if config.RulesPath == "" {
		return nil, fmt.Errorf("yara-x rules path is required")
	}

	ruleFiles, includeDirs, err := collectRuleSources(config.RulesPath)
	if err != nil {
		return nil, err
	}

	compiler, err := createCompiler()
	if err != nil {
		return nil, err
	}
	defer C.yrx_compiler_destroy(compiler)

	for _, dir := range includeDirs {
		cDir := C.CString(dir)
		res := C.yrx_compiler_add_include_dir(compiler, cDir)
		C.free(unsafe.Pointer(cDir))
		if err := yrxResult(res); err != nil {
			return nil, fmt.Errorf("yara-x add include dir %s: %w", dir, err)
		}
	}

	for _, file := range ruleFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		if len(content) == 0 {
			continue
		}
		cSrc := C.CString(string(content))
		cOrigin := C.CString(file)
		res := C.yrx_compiler_add_source_with_origin(compiler, cSrc, cOrigin)
		C.free(unsafe.Pointer(cSrc))
		C.free(unsafe.Pointer(cOrigin))
		if err := yrxResult(res); err != nil {
			return nil, fmt.Errorf("yara-x add source %s: %w", file, err)
		}
	}

	rules := C.yrx_compiler_build(compiler)
	if rules == nil {
		if details := compilerErrorsJSON(compiler); details != "" {
			return nil, fmt.Errorf("yara-x compile failed: %s", details)
		}
		return nil, fmt.Errorf("yara-x compile failed: %s", lastError())
	}

	return &yaraXEngine{
		rulesPath:     config.RulesPath,
		rules:         rules,
		readChunkSize: normalizeReadChunkSize(config.ReadChunkSize),
	}, nil
}

func (e *yaraXEngine) MatchFile(ctx context.Context, path string) ([]YaraRuleMatch, error) {
	if e == nil || e.rules == nil {
		return nil, fmt.Errorf("yara-x engine is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := readFileChunked(path, e.readChunkSize)
	if err != nil {
		return nil, err
	}
	return e.scanBytes(ctx, data)
}

func (e *yaraXEngine) MatchBytes(ctx context.Context, data []byte) ([]YaraRuleMatch, error) {
	if e == nil || e.rules == nil {
		return nil, fmt.Errorf("yara-x engine is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return e.scanBytes(ctx, data)
}

func (e *yaraXEngine) scanBytes(ctx context.Context, data []byte) ([]YaraRuleMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	scanner, err := createScanner(e.rules)
	if err != nil {
		return nil, err
	}
	defer C.yrx_scanner_destroy(scanner)

	collector := &matchCollector{maxStrings: maxMatchedStrings}
	handle := cgo.NewHandle(collector)
	userData := newUserData(handle)
	defer func() {
		C.free(userData)
		handle.Delete()
	}()

	if err := yrxResult(C.yarax_scanner_on_matching_rule(scanner, userData)); err != nil {
		return nil, err
	}

	var dataPtr *C.uint8_t
	if len(data) > 0 {
		dataPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	if err := yrxResult(C.yrx_scanner_scan(scanner, dataPtr, C.size_t(len(data)))); err != nil {
		return nil, err
	}

	return collector.matches, nil
}

func readFileChunked(path string, readChunkSize int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	readChunkSize = normalizeReadChunkSize(readChunkSize)
	chunk := make([]byte, readChunkSize)

	data := make([]byte, 0)
	if stat, err := file.Stat(); err == nil {
		if size := stat.Size(); size > 0 && size <= int64(^uint(0)>>1) {
			data = make([]byte, 0, int(size))
		}
	}

	for {
		n, readErr := file.Read(chunk)
		if n > 0 {
			data = append(data, chunk[:n]...)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	return data, nil
}

func normalizeReadChunkSize(size int) int {
	if size <= 0 {
		return DefaultYaraReadChunkSize
	}
	return size
}

func createCompiler() (*C.struct_YRX_COMPILER, error) {
	var compiler *C.struct_YRX_COMPILER
	if err := yrxResult(C.yrx_compiler_create(0, &compiler)); err != nil {
		return nil, err
	}
	if compiler == nil {
		return nil, errors.New("yara-x compiler creation failed")
	}
	return compiler, nil
}

func createScanner(rules *C.struct_YRX_RULES) (*C.struct_YRX_SCANNER, error) {
	var scanner *C.struct_YRX_SCANNER
	if err := yrxResult(C.yrx_scanner_create(rules, &scanner)); err != nil {
		return nil, err
	}
	if scanner == nil {
		return nil, errors.New("yara-x scanner creation failed")
	}
	return scanner, nil
}

func collectRuleSources(path string) ([]string, []string, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !stat.IsDir() {
		return []string{path}, []string{filepath.Dir(path)}, nil
	}

	var files []string
	root := filepath.Clean(path)
	err = filepath.WalkDir(root, func(current string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".yar", ".yara", ".yr":
			files = append(files, current)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("no yara rules found under %s", root)
	}
	sort.Strings(files)
	return files, []string{root}, nil
}

func compilerErrorsJSON(compiler *C.struct_YRX_COMPILER) string {
	var buf *C.struct_YRX_BUFFER
	if err := yrxResult(C.yrx_compiler_errors_json(compiler, &buf)); err != nil || buf == nil {
		return ""
	}
	defer C.yrx_buffer_destroy(buf)
	if buf.data == nil || buf.length == 0 {
		return ""
	}
	return string(C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.length)))
}

func yrxResult(result C.enum_YRX_RESULT) error {
	if result == C.YRX_SUCCESS {
		return nil
	}
	msg := lastError()
	if msg == "" {
		return fmt.Errorf("yara-x error: %d", int(result))
	}
	return errors.New(msg)
}

func lastError() string {
	msg := C.yrx_last_error()
	if msg == nil {
		return ""
	}
	return C.GoString(msg)
}

func newUserData(handle cgo.Handle) unsafe.Pointer {
	ptr := C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0))))
	*(*C.uintptr_t)(ptr) = C.uintptr_t(handle)
	return ptr
}

func handleFromUserData(userData unsafe.Pointer) (cgo.Handle, bool) {
	if userData == nil {
		return cgo.Handle(0), false
	}
	return cgo.Handle(*(*C.uintptr_t)(userData)), true
}

type matchCollector struct {
	matches    []YaraRuleMatch
	maxStrings int
}

//export goYaraXOnMatchingRule
func goYaraXOnMatchingRule(rule *C.struct_YRX_RULE, userData unsafe.Pointer) {
	handle, ok := handleFromUserData(userData)
	if !ok {
		return
	}
	collector, ok := handle.Value().(*matchCollector)
	if !ok || collector == nil {
		return
	}

	ruleName := ruleIdentifier(rule)
	tags := ruleTags(rule)
	severity := ruleSeverity(rule)
	if severity <= 0 {
		severity = fallbackSeverity(ruleName, tags)
	}

	match := YaraRuleMatch{
		RuleName:  ruleName,
		Namespace: ruleNamespace(rule),
		Tags:      tags,
		Severity:  severity,
	}
	if collector.maxStrings > 0 {
		match.MatchedStrings = ruleMatchedStrings(rule, collector.maxStrings)
	}
	collector.matches = append(collector.matches, match)
}

func ruleIdentifier(rule *C.struct_YRX_RULE) string {
	var ident *C.uint8_t
	var length C.size_t
	if err := yrxResult(C.yrx_rule_identifier(rule, (**C.uint8_t)(unsafe.Pointer(&ident)), &length)); err != nil {
		return ""
	}
	return bytesToString(unsafe.Pointer(ident), length)
}

func ruleNamespace(rule *C.struct_YRX_RULE) string {
	var ns *C.uint8_t
	var length C.size_t
	if err := yrxResult(C.yrx_rule_namespace(rule, (**C.uint8_t)(unsafe.Pointer(&ns)), &length)); err != nil {
		return ""
	}
	return bytesToString(unsafe.Pointer(ns), length)
}

func ruleTags(rule *C.struct_YRX_RULE) []string {
	collector := &tagCollector{}
	handle := cgo.NewHandle(collector)
	userData := newUserData(handle)
	defer func() {
		C.free(userData)
		handle.Delete()
	}()

	_ = yrxResult(C.yarax_rule_iter_tags(rule, userData))
	return collector.tags
}

type tagCollector struct {
	tags []string
}

//export goYaraXOnTag
func goYaraXOnTag(tag *C.char, userData unsafe.Pointer) {
	handle, ok := handleFromUserData(userData)
	if !ok {
		return
	}
	collector, ok := handle.Value().(*tagCollector)
	if !ok || collector == nil {
		return
	}
	if tag == nil {
		return
	}
	collector.tags = append(collector.tags, C.GoString(tag))
}

func ruleSeverity(rule *C.struct_YRX_RULE) int {
	collector := &severityCollector{}
	handle := cgo.NewHandle(collector)
	userData := newUserData(handle)
	defer func() {
		C.free(userData)
		handle.Delete()
	}()

	_ = yrxResult(C.yarax_rule_iter_metadata(rule, userData))
	if collector.found {
		return collector.value
	}
	return 0
}

type severityCollector struct {
	value int
	found bool
}

//export goYaraXOnMetadata
func goYaraXOnMetadata(metadata *C.struct_YRX_METADATA, userData unsafe.Pointer) {
	handle, ok := handleFromUserData(userData)
	if !ok {
		return
	}
	collector, ok := handle.Value().(*severityCollector)
	if !ok || collector == nil || metadata == nil {
		return
	}
	if metadata.identifier == nil {
		return
	}
	key := strings.ToLower(C.GoString(metadata.identifier))
	if key != "severity" {
		return
	}

	value, ok := metadataValueToInt(metadata)
	if !ok {
		return
	}
	if value < 0 {
		value = 0
	}
	if value > 100 {
		value = 100
	}
	collector.value = value
	collector.found = true
}

func metadataValueToInt(metadata *C.struct_YRX_METADATA) (int, bool) {
	switch metadata.value_type {
	case C.YRX_I64:
		return int(C.yarax_metadata_i64(metadata)), true
	case C.YRX_F64:
		return int(C.yarax_metadata_f64(metadata)), true
	case C.YRX_BOOLEAN:
		if C.yarax_metadata_bool(metadata) {
			return 1, true
		}
		return 0, true
	case C.YRX_STRING:
		str := C.yarax_metadata_string(metadata)
		if str == nil {
			return 0, false
		}
		parsed, err := parseInt(C.GoString(str))
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func parseInt(val string) (int, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0, fmt.Errorf("empty")
	}
	var out int
	for _, r := range val {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-digit")
		}
		out = out*10 + int(r-'0')
	}
	return out, nil
}

func ruleMatchedStrings(rule *C.struct_YRX_RULE, max int) []string {
	collector := &patternCollector{max: max}
	handle := cgo.NewHandle(collector)
	userData := newUserData(handle)
	defer func() {
		C.free(userData)
		handle.Delete()
	}()

	_ = yrxResult(C.yarax_rule_iter_patterns(rule, userData))
	return collector.matches
}

type patternCollector struct {
	matches []string
	max     int
}

//export goYaraXOnPattern
func goYaraXOnPattern(pattern *C.struct_YRX_PATTERN, userData unsafe.Pointer) {
	handle, ok := handleFromUserData(userData)
	if !ok {
		return
	}
	collector, ok := handle.Value().(*patternCollector)
	if !ok || collector == nil || pattern == nil {
		return
	}
	if collector.max > 0 && len(collector.matches) >= collector.max {
		return
	}

	patternID := patternIdentifier(pattern)
	matchCollector := &matchStringCollector{
		matches: &collector.matches,
		max:     collector.max,
		pattern: patternID,
	}
	mHandle := cgo.NewHandle(matchCollector)
	mUser := newUserData(mHandle)
	defer func() {
		C.free(mUser)
		mHandle.Delete()
	}()

	_ = yrxResult(C.yarax_pattern_iter_matches(pattern, mUser))
}

func patternIdentifier(pattern *C.struct_YRX_PATTERN) string {
	var ident *C.uint8_t
	var length C.size_t
	if err := yrxResult(C.yrx_pattern_identifier(pattern, (**C.uint8_t)(unsafe.Pointer(&ident)), &length)); err != nil {
		return ""
	}
	return bytesToString(unsafe.Pointer(ident), length)
}

type matchStringCollector struct {
	matches *[]string
	max     int
	pattern string
}

//export goYaraXOnMatch
func goYaraXOnMatch(match *C.struct_YRX_MATCH, userData unsafe.Pointer) {
	handle, ok := handleFromUserData(userData)
	if !ok {
		return
	}
	collector, ok := handle.Value().(*matchStringCollector)
	if !ok || collector == nil || match == nil || collector.matches == nil {
		return
	}
	if collector.max > 0 && len(*collector.matches) >= collector.max {
		return
	}

	entry := fmt.Sprintf("%s@%d:%d", collector.pattern, int(match.offset), int(match.length))
	*collector.matches = append(*collector.matches, entry)
}

func bytesToString(ptr unsafe.Pointer, length C.size_t) string {
	if ptr == nil || length == 0 {
		return ""
	}
	return string(C.GoBytes(ptr, C.int(length)))
}
