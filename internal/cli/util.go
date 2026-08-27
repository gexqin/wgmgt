package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
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

// confirm asks a yes/no question over a terminal. Non-terminal stdin
// (scripts, pipes) just gets the default.
func confirm(label string, def bool) bool {
	if !isTerminal(os.Stdin) {
		return def
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Printf("%s %s: ", label, hint)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return def
	}
}
