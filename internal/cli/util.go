package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// prompt asks a question with a default over a terminal. Non-terminal stdin
// (scripts, pipes) just gets the default.
func prompt(label, def string) string {
	if !isTerminal(os.Stdin) {
		return def
	}
	fmt.Printf("%s [%s]: ", label, def)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return def
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// humanDuration renders "5m", "3h5m", "2d4h"-style ages.
func humanDuration(d time.Duration) string {
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

// timeSince treats the zero timestamp as "never".
func timeSince(t time.Time) time.Duration {
	if t.IsZero() {
		return -1
	}
	return time.Since(t)
}

func humanBytes(b int64) string {
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
