//go:build !windows && !linux

package eventlogscan

import (
	"context"
	"fmt"
)

func collectPlatformEvents(ctx context.Context, params QueryParams, _ rawEventSink) error {
	_ = ctx
	_ = params
	return fmt.Errorf("eventlog collection is not supported on this operating system")
}
