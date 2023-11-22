package apps

import (
	"fmt"
	"regexp"
	"strings"
)

type (
	lexer struct {
		input    []rune
		pos      int
		patterns []matcher
		tokens   []*token
	}
	lexError struct {
		reason string
		row    int
		col    int
		lexer  *lexer
	}
	matcher interface {
		Match(l *lexer) *token
	}
	token struct {
		pos  int
		name string
		kind string
		row  int
		col  int
		len  int
	}
	tokenError struct {
		reason string
		token  *token
		lexer  *lexer
		jump   bool
	}
	rePattern struct {
		kind string
		re   *regexp.Regexp
	}
	fnPattern struct {
		kind string
		fn   func(*lexer) *token
	}
	stPattern struct {
		kind string
		st   []string
	}
)

func (l *lexer) next() rune {
	if l.pos+1 > len(l.input)-1 {
		return 0
	}
	l.pos++
	return l.input[l.pos]
}

func (l *lexer) peek(n int) rune {
	i := l.pos + n
	if i < 0 || i > len(l.input)-1 {
		return 0
	}
	return l.input[i]
}

func (l *lexer) tpeek(n int) *token {
	i := len(l.tokens) - 1 + n
	if i < 0 || i > len(l.tokens)-1 {
		return &token{}
	}
	return l.tokens[i]
}

func (l *lexer) rowcol() (row int, col int) {
	for i := 0; i < l.pos; i++ {
		col++
		if l.input[i] == '\n' {
			row++
			col = 0
		}
	}
	return row, col
}

func (l *lexer) line(row int) string {
	ret := new(strings.Builder)
	seekrow := 0
	offset := 0
	for {
		if offset > len(l.input)-1 {
			return ""
		}
		if l.input[offset] == '\n' {
			seekrow++
			offset++
		}
		if seekrow >= row {
			break
		}
		offset++
	}

	for ; offset < len(l.input) && l.input[offset] != '\n'; offset++ {
		ret.WriteRune(l.input[offset])
	}

	return ret.String()
}

func (l *lexer) lex(s string) ([]*token, error) {
	l.input = []rune(s)
	var tok *token
	var count int
	for l.pos < len(l.input) {
		if l.peek(0) == ' ' || l.peek(0) == '\t' {
			l.next()
			continue
		} else if l.peek(0) == '\\' && l.peek(1) == '\n' {
			l.next()
			l.next()
			continue
		}
		tok = nil
		for _, p := range l.patterns {
			t := p.Match(l)
			if t != nil && (tok == nil || t.len > tok.len) {
				tok = t
			}
		}
		if tok == nil {
			row, col := l.rowcol()
			return []*token{}, l.newLexError(row, col, "bad token")
		}
		tok.pos = count
		l.tokens = append(l.tokens, tok)
		count++
		l.pos += tok.len
	}
	return l.tokens, nil
}

func (l *lexer) newLexError(row int, col int, format string, a ...any) *lexError {
	return &lexError{
		reason: fmt.Sprintf(format, a...),
		row:    row,
		col:    col,
		lexer:  l,
	}
}

func (e *lexError) Error() string {
	return e.reason
}

func (e *lexError) Pretty() string {
	prefix := fmt.Sprintf("line %d: ", e.row+1)
	line := e.lexer.line(e.row)
	offset := len(prefix)
	for i, c := range line {
		if i >= e.col {
			break
		} else if c == '\t' {
			offset += 8
		} else {
			offset++
		}
	}
	return prefix + line + "\n" + strings.Repeat(" ", offset) + "^ " + e.reason
}

func (l *lexer) newJumpError(tok *token) *tokenError {
	return &tokenError{token: tok, lexer: l, jump: true}
}

func (l *lexer) newTokenError(tok *token) *tokenError {
	return &tokenError{token: tok, lexer: l}
}

func (l *lexer) newTokenErrorf(tok *token, format string, a ...any) *tokenError {
	return &tokenError{
		token:  tok,
		lexer:  l,
		reason: fmt.Sprintf(format, a...),
	}
}

func (e *tokenError) Error() string {
	return e.reason
}

func (e *tokenError) Reason() string {
	if e.reason == "" {
		switch e.token.kind {
		case "":
			e.reason = "bad EOF"
		case "\n":
			e.reason = "bad newline"
		default:
			e.reason = fmt.Sprintf("bad %s", e.token.kind)
		}
	}
	return e.reason
}

func (e *tokenError) Pretty() string {
	row := e.token.row
	col := e.token.col
	if e.token.kind == "" && len(e.lexer.tokens) > 1 {
		tok := e.lexer.tokens[len(e.lexer.tokens)-1]
		row = tok.row
		col = tok.col + tok.len + 1
	}
	prefix := fmt.Sprintf("line %d: ", row+1)
	line := e.lexer.line(row)
	offset := len(prefix)
	for i, c := range line {
		if i >= col {
			break
		} else if c == '\t' {
			offset += 8
		} else {
			offset++
		}
	}
	return prefix + line + "\n" + strings.Repeat(" ", offset) +
		strings.Repeat("^", max(e.token.len, 1)) + " " + e.Reason()
}

func rePat(name string, re *regexp.Regexp) *rePattern {
	return &rePattern{kind: name, re: re}
}

func fnPat(name string, fn func(*lexer) *token) *fnPattern {
	return &fnPattern{kind: name, fn: fn}
}

func dlPat(kind string, delimiter rune) *fnPattern {
	return &fnPattern{kind: kind, fn: func(l *lexer) *token {
		if l.peek(0) != delimiter {
			return nil
		}

		pos := l.pos
		name := strings.Builder{}
		row, col := l.rowcol()
		defer func() { l.pos = pos }()
		for {
			c := l.next()
			if c == 0 {
				return nil
			} else if c == '\\' {
				// TODO: cleanup
				n := l.next()
				if n == delimiter {
					name.WriteRune(delimiter)
				} else {
					name.WriteRune(c)
					name.WriteRune(n)
				}
				continue
			} else if c == delimiter {
				break
			}
			name.WriteRune(c)
		}

		t := &token{kind: kind, row: row, col: col, name: name.String(),
			len: l.pos - pos + 1}
		return t
	}}
}

func stPat(name string, st ...string) *stPattern {
	return &stPattern{kind: name, st: st}
}

func (p *rePattern) Match(l *lexer) *token {
	match := p.re.FindStringSubmatch(string(l.input[l.pos:]))
	if match == nil {
		return nil
	}

	var name string
	if len(match) > 1 {
		name = match[1]
	} else {
		name = match[0]
	}

	row, col := l.rowcol()
	t := &token{name: name, kind: p.kind, row: row, col: col, len: len(name)}
	return t
}

func (p *fnPattern) Match(l *lexer) *token {
	return p.fn(l)
}

func (p *stPattern) Match(l *lexer) *token {
	st := p.st
	if len(p.st) == 0 {
		st = []string{p.kind}
	}
	var tok *token
	for _, s := range st {
		if tok != nil && len(s) < tok.len {
			continue
		}
		if l.pos+len(s) > len(l.input) {
			continue
		}
		if string(l.input[l.pos:l.pos+len(s)]) == s {
			row, col := l.rowcol()
			tok = &token{name: s, kind: p.kind, row: row, col: col, len: len(s)}
		}
	}
	return tok
}
