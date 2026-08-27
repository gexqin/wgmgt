// Package humanize renders durations and byte counts for humans.
package humanize

import (
	"fmt"
	"time"
)

// Duration renders "5m", "3h5m", "2d4h"-style ages; negative means "never".
func Duration(d time.Duration) string {
	switch {
	case d < 0:
		return "never"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

// Since treats the zero timestamp as "never" (negative duration).
func Since(t time.Time) time.Duration {
	if t.IsZero() {
		return -1
	}
	return time.Since(t)
}

// Bytes renders "512B", "1.4KB", "2.1MB", "5.0GB".
func Bytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%dB", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.1fGB", float64(b)/(1024*1024*1024))
	}
}
