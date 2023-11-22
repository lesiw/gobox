package apps

import (
	"io"
	"strings"
)

type IOs struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

type prettyError interface {
	Error() string
	Pretty() string
}

type stringlist []string

func (s *stringlist) String() string {
	return "[" + strings.Join(*s, ", ") + "]"
}

func (s *stringlist) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func prettyPrintError(w io.Writer, err error) {
	if pe, ok := err.(prettyError); ok {
		io.WriteString(w, pe.Pretty())
		io.WriteString(w, "\n")
	} else {
		io.WriteString(w, err.Error())
	}
}

type strset map[string]bool

func stringset(s ...string) strset {
	m := make(strset)
	for _, k := range s {
		m[k] = true
	}
	return m
}

func firstrune(s string) rune {
	for _, r := range s {
		return r
	}
	return 0
}

func lastrune(s string) (r rune) {
	for _, rr := range s {
		r = rr
	}
	return
}

func runealpha(r rune) bool {
	return 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z'
}

func stringalpha(s string) bool {
	for _, c := range s {
		if !runealpha(c) {
			return false
		}
	}
	return true
}
