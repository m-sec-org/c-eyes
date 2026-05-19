//go:build linux && !cgo

package eventlogscan

import "context"

func collectJournaldEvents(_ context.Context, _ QueryParams) ([]rawEvent, bool, error) {
	return nil, false, nil
}
