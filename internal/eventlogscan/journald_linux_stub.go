//go:build linux && !cgo

package eventlogscan

import "context"

func collectJournaldEvents(_ context.Context, _ QueryParams, _ rawEventSink) (bool, error) {
	return false, nil
}
