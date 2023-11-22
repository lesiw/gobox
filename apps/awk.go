package apps

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type awkp struct {
	ios *IOs

	lexer  *lexer
	tokens []*token
	pos    int

	files   map[string]io.ReadWriteCloser
	streams map[string]io.ReadWriteCloser // TODO: will this work for pipes?

	inputfiles []string
	reader     *filesReader

	erefn       strset
	endstmt     strset
	endexpr     strset
	endexprlist strset
	endprint    strset

	stmts map[string]awkeval
	exprs []awkeval

	fntok  []*token
	frames []*awkframe

	begins   []*token
	ends     []*token
	items    []*awkitem
	symbols  map[string]*awkcell
	fields   []*awkcell
	builtins map[string]awkbuiltin
}

type awkcell struct {
	prog       *awkp
	numval     *float64
	strval     string
	arrval     *awkmap
	fnval      *awkfn
	assignable bool
	onassign   func() error
	name       string
	next       *awkcell
}

type awkfn struct {
	params []*token
	block  *token
}

type awkframe struct {
	symbols map[string]*awkcell
}

type awkitem struct {
	token *token
	in    bool
}

type awkeval func(bool, strset) (*awkcell, error)
type awkbuiltin func([]*awkcell) (*awkcell, error)

var awkUsage = `usage: awk [-v VAR=VAL...] [-F SEP] [-f PROGRAM_FILE | PROGRAM] [FILE...]

A pattern scanning and processing language.
`

func Awk(argv []string, ios *IOs) int {
	// TODO: validate shebang support
	var (
		err       error
		prog      string
		flags     = flag.NewFlagSet("awk", flag.ContinueOnError)
		sep       = flags.String("F", "", "Field separator")
		progfiles = &stringlist{}
		vars      = &stringlist{}
	)
	flags.Var(progfiles, "f", "Path to awk program")
	flags.Var(vars, "v", "Set variable")
	flags.SetOutput(ios.Err)
	flags.Usage = func() { fmt.Fprintln(flags.Output(), awkUsage); flags.PrintDefaults() }

	if err = flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	p := newAwkP(ios)
	if len(argv) < 1 {
		return 0
	}

	if *sep != "" {
		p.sym("FS").setString(*sep)
	}
	for _, f := range *progfiles {
		txt, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(ios.Err, "bad file: %s\n", f)
			return 1
		}
		prog += string(txt)
	}
	if prog == "" && flags.NArg() > 0 {
		prog = argv[0]
	} else {
		p.inputfiles = flags.Args()
	}
	for _, v := range *vars {
		varval := strings.SplitN(v, "=", 2)
		if len(varval) != 2 {
			fmt.Fprintf(ios.Err, "bad variable, must be VAR=VAL: %s\n", v)
			return 1
		}
		p.sym(varval[0]).setString(varval[1])
	}

	if prog == "" {
		flags.Usage()
		return 0
	}
	if p.tokens, err = p.lexer.lex(prog); err != nil {
		prettyPrintError(ios.Err, err)
		return 1
	}
	if err := p.parse(); err != nil {
		prettyPrintError(ios.Err, err)
		return 1
	}
	if _, err := p.exec(true); err != nil {
		prettyPrintError(ios.Err, err)
		return 1
	}
	return 0
}

func (p *awkp) bool(b bool) *awkcell {
	var n float64
	if b {
		n = 1
	}
	return &awkcell{numval: &n, prog: p}
}

func (p *awkp) num(n float64) *awkcell {
	return &awkcell{numval: &n, prog: p}
}

func (p *awkp) string(s string) *awkcell {
	return &awkcell{strval: s, prog: p}
}

func (c *awkcell) num() float64 {
	if c.numval != nil {
		return *c.numval
	}
	if c.strval == "" {
		return 0
	}
	numval, err := strconv.ParseFloat(c.strval, 64)
	if err != nil {
		return 0
	}
	c.numval = &numval
	return *c.numval
}

func (c *awkcell) setNum(n float64) {
	c.numval = &n
	c.strval = ""
}

func (c *awkcell) string() string {
	if c.strval != "" {
		return c.strval
	}
	if c.numval == nil {
		return ""
	}
	format := c.prog.sym("CONVFMT").string()
	if _, frac := math.Modf(*c.numval); frac == 0 {
		format = "%.30g"
	}
	s, err := c.prog.sprintf(format, []*awkcell{c})
	if err != nil {
		return ""
	}
	return s
}

func (c *awkcell) setString(s string) {
	c.strval = s
	c.numval = nil
}

func (c *awkcell) isString() bool {
	return c.numval == nil
}

func (c *awkcell) bool() bool {
	if c.numval != nil {
		return c.num() != 0
	} else {
		return c.string() != ""
	}
}

func (c *awkcell) setBool(b bool) {
	if b {
		c.setNum(1)
	} else {
		c.setNum(0)
	}
}

func (c *awkcell) arr(k string) *awkcell {
	if c.arrval == nil {
		c.arrval = &awkmap{}
	}
	val := c.arrval.get(k)
	if val == nil {
		c.arrval.set(k, &awkcell{prog: c.prog, assignable: true})
	}
	return c.arrval.get(k)
}

func (c *awkcell) inArr(k string) *awkcell {
	if c.arrval == nil {
		c.arrval = &awkmap{}
	}
	val := c.arrval.get(k)
	return c.prog.bool(val != nil)
}

func (c *awkcell) setArr(k string, v *awkcell) {
	if c.arrval == nil {
		c.arrval = &awkmap{}
	}
	c.arrval.set(k, v)
}

func (c *awkcell) delArr(k string) {
	if c.arrval == nil {
		c.arrval = &awkmap{}
	}
	c.arrval.del(k)
}

func (c *awkcell) fn() *awkfn {
	if c.fnval == nil {
		c.fnval = &awkfn{}
	}
	return c.fnval
}

func (c *awkcell) setFn(f *awkfn) {
	c.fnval = f
}

func (c *awkcell) setCell(o *awkcell) {
	if o.numval != nil {
		c.setNum(*o.numval)
	} else if o.strval != "" {
		c.setString(o.strval)
	}
	if o.arrval != nil {
		c.arrval = o.arrval
	}
	if o.fnval != nil {
		c.fnval = o.fnval
	}
}

func newAwkP(ios *IOs) *awkp {
	p := &awkp{
		ios:         ios,
		symbols:     make(map[string]*awkcell),
		erefn:       stringset("gsub", "match", "split", "sub"),
		endstmt:     stringset("", ";", "\n"),
		endexpr:     stringset("", "}", ";", ",", "\n"),
		endexprlist: stringset("", "{", "}", ";", "\n"),
		endprint:    stringset("", "}", ";", ",", "\n", ">", ">>", "|"),
	}
	// NOTE: according to POSIX, index/length/match/substr must count characters, not bytes
	p.builtins = map[string]awkbuiltin{
		"length":  p.fnlength,
		"gsub":    p.fngsub,
		"int":     p.fnint,
		"sprintf": p.fnsprintf,
		"substr":  p.fnsubstr,
	}

	// '/' is ambiguous (start of ere or division operator); lex it based on the previous token.
	ere := fnPat("ere", func(l *lexer) *token {
		switch l.tpeek(0).kind {
		case ")", "name", "number":
			return nil
		default:
			return dlPat("ere", '/').Match(l)
		}
	})
	// TODO: add cmPat to match and skip comments
	patterns := []matcher{
		dlPat("string", '"'), ere, stPat("begin", "BEGIN"), stPat("end", "END"),
		stPat("break"), stPat("continue"), stPat("delete"), stPat("do"), stPat("else"),
		stPat("exit"), stPat("for"), stPat("function"), stPat("if"), stPat("in"),
		stPat("next"), stPat("printf"), stPat("print"), stPat("return"), stPat("while"),
		stPat("getline"), stPat("builtin_func", "atan2", "cos", "sin", "exp", "log", "sqrt",
			"int", "rand", "srand", "gsub", "index", "length", "match", "split",
			"sprintf", "sub", "substr", "tolower", "toupper", "close", "system"),
		rePat("func_name", regexp.MustCompile(`(^[a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)),
		stPat("+="), stPat("-="), stPat("*="), stPat("/="), stPat("%="), stPat("^="),
		stPat("||"), stPat("&&"), stPat("=="), stPat("<="), stPat(">="), stPat("!="),
		stPat("++"), stPat("--"), stPat(">>"), stPat("{"), stPat("}"), stPat("("),
		stPat(")"), stPat("["), stPat("]"), stPat(","), stPat(";"), stPat("\n"), stPat("+"),
		stPat("-"), stPat("*"), stPat(`/`), stPat("%"), stPat("^"), stPat("!"), stPat(">"),
		stPat("<"), stPat("|"), stPat("?"), stPat(":"), stPat("~"), stPat("$"), stPat("="),
		rePat("name", regexp.MustCompile("^[a-zA-Z_][a-zA-Z0-9_]*")),
		rePat("number", regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?`)),
	}
	p.lexer = &lexer{patterns: patterns}

	p.stmts = map[string]awkeval{
		"break":    p.jumpstmt,
		"continue": p.jumpstmt,
		// "do": p.dostmt, // NOTE: is this posix/busybox?
		"delete": p.deletestmt,
		// "exit": p.exitstmt, // NOTE: this must run END actions
		"for": p.forstmt, // NOTE: two fors in awk
		// "getline": p.getlinestmt, // NOTE: not expr | getline; also note, must return int
		"if":     p.ifstmt,
		"next":   p.jumpstmt,
		"print":  p.printstmt,
		"printf": p.printfstmt,
		"return": p.returnstmt,
		"while":  p.whilestmt,
	}

	exprFns := []func(awkeval, bool, strset) (val *awkcell, err error){
		p.assign, p.cond, p.or, p.and, p.inarray, p.ere, p.comp, p.concat, p.add,
		p.multiply, p.unary, p.exp, p.prefixop, p.postfixop, p.fieldref, p.group, p.val,
	}
	p.exprs = make([]awkeval, len(exprFns)+1)
	p.exprs[len(exprFns)] = nil
	for i := len(exprFns) - 1; i >= 0; i-- {
		p.exprs[i] = func(i int) awkeval {
			return func(exec bool, stop strset) (*awkcell, error) {
				return exprFns[i](p.exprs[i+1], exec, stop)
			}
		}(i)
	}

	p.sym("CONVFMT").setString("%.6g")
	p.sym("FS").setString(" ")
	p.sym("OFMT").setString("%.6g")
	p.sym("OFS").setString(" ")
	p.sym("ORS").setString("\n")
	p.sym("RS").setString("\n")
	p.sym("SUBSEP").setString("\034")

	return p
}

func (p *awkp) field(i int) *awkcell {
	if i > len(p.fields)-1 {
		p.fields = append(p.fields, make([]*awkcell, i-len(p.fields)+1)...)
	}
	if p.fields[i] == nil {
		p.fields[i] = &awkcell{prog: p, assignable: true}
		if i == 0 {
			p.fields[i].onassign = p.rtof
		} else {
			p.fields[i].onassign = p.ftor
		}
	}
	return p.fields[i]
}

func (p *awkp) rtof() error {
	p.fields = p.fields[:1]
	var i int
	if p.sym("FS").string() == " " {
		var r rune
		i++
		var field = new(strings.Builder)
		for _, r = range p.fields[0].string() {
			if r == ' ' || r == '\t' || r == '\n' {
				if field.Len() > 0 {
					p.field(i).setString(field.String())
					i++
					field.Reset()
				}
				continue
			}
			field.WriteRune(r)
		}
		if field.Len() > 0 {
			p.field(i).setString(field.String())
		}
	} else {
		re, err := regexp.CompilePOSIX(p.sym("FS").string())
		if err != nil {
			return fmt.Errorf("FS: bad regex: %w", err)
		}
		var f string
		for i, f = range re.Split(p.fields[0].string(), -1) {
			p.field(i + 1).setString(f)
		}
		i++
	}
	p.sym("NF").setNum(float64(i))
	return nil
}

func (p *awkp) ftor() error {
	p.field(0).setString(p.join(p.fields[1:], p.sym("FS").string()))
	return nil
}

func (p *awkp) sym(s string) *awkcell {
	if len(p.frames) > 0 {
		tab := p.frames[len(p.frames)-1].symbols
		if val, ok := tab[s]; ok {
			return val
		}
		if val, ok := p.symbols[s]; ok {
			return val
		}
		val := &awkcell{prog: p, assignable: true}
		tab[s] = val
		return val
	} else {
		if val, ok := p.symbols[s]; ok {
			return val
		}
		val := &awkcell{prog: p, assignable: true}
		p.symbols[s] = val
		return val
	}
}

func (p *awkp) file(name string) io.ReadWriteCloser {
	if p.files == nil {
		p.files = make(map[string]io.ReadWriteCloser)
	}
	return p.files[name]
}

func (p *awkp) stream(name string) io.ReadWriteCloser {
	if p.streams == nil {
		p.streams = make(map[string]io.ReadWriteCloser)
	}
	return p.streams[name]
}

func (p *awkp) implicitmatch() bool {
	return len(p.fntok) == 0 || !p.erefn[p.fntok[len(p.fntok)-1].name]
}

func (p *awkp) multiArr(a *awkcell, k ...string) *awkcell {
	return a.arr(strings.Join(k, p.sym("SUBSEP").string()))
}

func (p *awkp) peek(n int) *token {
	if p.pos+n < 0 || p.pos+n > len(p.tokens)-1 {
		return &token{}
	}
	return p.tokens[p.pos+n]
}

func (p *awkp) match(kind ...string) bool {
	pos := p.pos
	defer func() { p.pos = pos }()

	for _, k := range kind {
		if k == "expr" {
			if _, err := p.expr(false, p.endexpr); err != nil {
				return false
			}
		} else if k == "exprlist" {
			if _, err := p.exprlist(false, p.endexprlist); err != nil {
				return false
			}
		} else if p.next().kind != k {
			return false
		}
	}
	pos = p.pos
	return true
}

func (p *awkp) matchany(kind ...string) bool {
	for _, k := range kind {
		if p.match(k) {
			return true
		}
	}
	return false
}

func (p *awkp) mustmatch(kind ...string) error {
	for _, k := range kind {
		if !p.match(k) {
			return p.lexer.newTokenErrorf(p.peek(0), "want %s, got %s",
				k, p.peek(0).kind)
		}
	}
	return nil
}

func (p *awkp) mustmatchany(kind ...string) error {
	for _, k := range kind {
		if p.match(k) {
			return nil
		}
	}
	return p.lexer.newTokenErrorf(p.peek(0), "want one of (%s), got %s",
		strings.Join(kind, ", "), p.peek(0).kind)
}

func (p *awkp) next() *token {
	if p.pos > len(p.tokens)-1 {
		return &token{pos: -1}
	}
	p.pos++
	return p.tokens[p.pos-1]
}

func (p *awkp) unescapeEre(c *awkcell) string {
	return c.string() // TODO
}

func (p *awkp) unescapeStr(s string) (string, error) {
	// TODO: validate against https://pubs.opengroup.org/onlinepubs/9699919799/utilities/awk.html#tab42
	runes := []rune(s)
	ret := new(strings.Builder)
	for i := 0; i < len(runes); i++ {
		if runes[i] != '\\' || i >= len(runes)-1 {
			ret.WriteRune(runes[i])
			continue
		}
		i++
		switch runes[i] {
		case 'b':
			ret.WriteRune('\b')
		case 't':
			ret.WriteRune('\t')
		case 'n':
			ret.WriteRune('\n')
		case 'f':
			ret.WriteRune('\f')
		case 'r':
			ret.WriteRune('\r')
		case 'e':
			ret.WriteRune('\033')
		case '\\':
			ret.WriteRune('\\')
		default:
			return "", fmt.Errorf("bad escape: \\%c", runes[i])
		}
	}
	return ret.String(), nil
}

func (p *awkp) join(vals []*awkcell, by string) string {
	var s strings.Builder
	for i, v := range vals {
		if i > 0 {
			s.WriteString(by)
		}
		s.WriteString(v.string())
	}
	return s.String()
}

func (p *awkp) parse() error {
	var depth int
	for {
		switch p.next().kind {
		case "\n":
			continue
		case "{":
			if depth == 0 {
				p.items = append(p.items, &awkitem{p.peek(-1), false})
			}
			depth++
		case "}":
			if depth < 0 {
				return p.lexer.newTokenError(p.peek(0))
			}
			depth--
		case "begin":
			if depth != 0 {
				return p.lexer.newTokenError(p.peek(0))
			}
			if err := p.mustmatch("{"); err != nil {
				return err
			}
			p.begins = append(p.begins, p.peek(0))
			depth++
		case "end":
			if depth != 0 {
				return p.lexer.newTokenError(p.peek(0))
			}
			if err := p.mustmatch("{"); err != nil {
				return err
			}
			p.ends = append(p.ends, p.peek(0))
			depth++
		case "function":
			if depth != 0 {
				return p.lexer.newTokenError(p.peek(0))
			}
			name := p.peek(0)
			if !(name.kind == "func_name" || name.kind == "name") {
				return p.lexer.newTokenErrorf(name, "bad function name")
			}
			p.next()
			params, err := p.toklistp()
			if err != nil {
				return err
			}
			if err := p.mustmatch("{"); err != nil {
				return err
			}
			p.sym(name.name).setFn(&awkfn{params: params, block: p.next()})
			depth++
		case "":
			return nil
		default:
			if depth != 0 {
				continue
			}
			p.items = append(p.items, &awkitem{p.peek(-1), false})
		}
	block:
		for {
			switch p.next().kind {
			case "{":
				depth++
			case "}":
				depth--
				if depth == 0 {
					break block
				} else if depth < 0 {
					return p.lexer.newTokenError(p.peek(0))
				}
			case "":
				break block
			}
		}
	}
}

func (p *awkp) exec(exec bool) (val *awkcell, err error) {
	// TODO: add defer to run p.exit, if err.token.kind == "exit"
	// TODO: add defer to close open files
	for _, begin := range p.begins {
		p.pos = begin.pos
		if val, err = p.evalblock(exec); err != nil {
			return
		}
	}
	if len(p.items) == 0 && len(p.ends) == 0 {
		return
	}
	if val, err = p.itemloop(exec); err != nil {
		return
	}
	return p.exit(0, exec)
}

func (p *awkp) itemloop(exec bool) (val *awkcell, err error) {
	if !exec {
		return
	}
	for {
		_, err = p.getline(nil)
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return
		}

		p.sym("NR").setNum(p.sym("NR").num() + 1)
		if p.sym("FILENAME").string() != p.reader.Filename() {
			p.sym("FILENAME").setString(p.reader.Filename())
			p.sym("FNR").setNum(0)
		}
		p.sym("FNR").setNum(p.sym("FNR").num() + 1)

		var vals []*awkcell
		for _, item := range p.items {
			// TODO: move this to some evalitem function
			p.pos = item.token.pos
			vals, err = p.exprlist(true, p.endexprlist)
			// FIXME: move tokenError checks to evalblock below
			var terr *tokenError
			switch {
			case err == nil:
				break
			case errors.As(err, &terr) && terr.jump && terr.token.kind == "next":
				continue
			default:
				return
			}
			switch len(vals) {
			case 0:
				// Implicit match.
			case 1:
				if !vals[0].bool() {
					continue
				}
			case 2:
				if item.in && vals[1].bool() {
					item.in = false
				} else if !item.in && vals[0].bool() {
					item.in = true
				} else if !item.in {
					continue
				}
			default:
				err = p.lexer.newTokenErrorf(item.token,
					"bad expr count: want 0-2, got %d", len(vals))
				return
			}
			if p.match("{") {
				if val, err = p.evalblock(true); val != nil || err != nil {
					return
				}
			} else {
				fmt.Fprintf(p.ios.Out, p.fields[0].string())
				fmt.Fprintf(p.ios.Out, p.sym("ORS").string())
			}
		}
	}
	return
}

func (p *awkp) getline(set *awkcell) (val *awkcell, err error) {
	if err = p.setupreader(); err != nil {
		return
	}
	var r rune
	var record strings.Builder
	for {
		r, _, err = p.reader.ReadRune()
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return
		}
		// TODO: handle blank RS
		if firstrune(p.sym("RS").string()) == r {
			break
		}
		record.WriteRune(r)
	}
	if record.String() == "" {
		err = io.EOF
		return
	}
	if set == nil {
		set = p.field(0)
	}
	set.setString(record.String())
	if set.onassign != nil {
		if err = set.onassign(); err != nil {
			return
		}
	}
	return // TODO: return (-1, 0, 1)
}

func (p *awkp) setupreader() error {
	if p.reader != nil {
		return nil
	}
	p.reader = &filesReader{}
	for _, f := range p.inputfiles {
		if f == "-" {
			p.reader.readers = append(p.reader.readers, &fileReader{
				"-", bufio.NewReader(p.ios.In),
			})
		} else {
			file, err := os.Open(f)
			if err != nil {
				return fmt.Errorf("bad file '%s': %s", f, err)
			}
			p.reader.readers = append(p.reader.readers, &fileReader{
				f, bufio.NewReader(file),
			})
		}
	}
	if len(p.reader.readers) < 1 {
		p.reader.readers = []*fileReader{{"-", bufio.NewReader(p.ios.In)}}
	}
	return nil
}

func (p *awkp) exit(code int, exec bool) (val *awkcell, err error) {
	for _, end := range p.ends {
		p.pos = end.pos
		if val, err = p.evalblock(true); err != nil {
			return
		}
	}
	return
}

func (p *awkp) evalblock(exec bool) (val *awkcell, err error) {
	for {
		if p.match("}") {
			return
		} else if p.match("\n") {
			continue
		} else if val, err = p.evalstmt(exec, p.endstmt); err != nil {
			return
		}
	}
}

func (p *awkp) evalstmt(exec bool, stop strset) (val *awkcell, err error) {
	for stop[p.peek(0).kind] {
		p.next()
	}
	if p.match("") {
		err = p.lexer.newTokenError(p.peek(-1))
	} else if p.match("{") {
		val, err = p.evalblock(exec)
	} else if _, ok := p.stmts[p.peek(0).kind]; ok {
		val, err = p.stmts[p.next().kind](exec, stop)
	} else {
		_, err = p.expr(exec, p.endexpr)
		// TODO: look ahead to see if | is next, if so, pass val into next statement
		// do we need to do > and >> too, or is that only for print(f)?
	}
	// FIXME: should validate at least one of these is present
	// (except in cases where })?
	// terminated statement?
	for stop[p.peek(0).kind] {
		p.next()
	}
	return
}

func (p *awkp) toklistp() (vals []*token, err error) {
	if err = p.mustmatch("("); err != nil {
		return
	}
	for {
		switch p.next().kind {
		case "name":
			for _, tok := range vals {
				if tok.name == p.peek(-1).name {
					err = p.lexer.newTokenErrorf(p.peek(-1),
						"bad parameter: duplicate")
					return
				}
			}
			vals = append(vals, p.peek(-1))
			if !p.match(",") && p.peek(0).name != ")" {
				err = p.lexer.newTokenError(p.peek(0))
				return
			}
		case ")":
			return
		default:
			err = p.lexer.newTokenError(p.peek(-1))
			return
		}
	}
}

func (p *awkp) jumpstmt(exec bool, stop strset) (*awkcell, error) {
	if !exec {
		return nil, nil
	}
	return nil, p.lexer.newJumpError(p.peek(-1))
}

func (p *awkp) deletestmt(exec bool, stop strset) (val *awkcell, err error) {
	if err = p.mustmatch("name"); err != nil {
		return
	}
	arr := p.peek(-1).name
	if err = p.mustmatch("["); err != nil {
		return
	}
	var vals []*awkcell
	vals, err = p.exprlist(exec, p.endexpr)
	if err != nil {
		return
	}
	if err = p.mustmatch("]"); err != nil {
		return
	}
	if !exec {
		return
	}
	p.sym(arr).delArr(p.join(vals, p.sym("SUBSEP").string()))
	return
}

func (p *awkp) printstmt(exec bool, stop strset) (val *awkcell, err error) {
	parens := p.match("(") // Optional.
	var args []*awkcell
	args, err = p.exprlist(exec, p.endprint)
	if err != nil {
		return
	}
	if len(args) == 0 {
		args = []*awkcell{p.field(0)}
	}
	var s string
	if exec {
		s = p.join(args, p.sym("OFS").string()) + p.sym("ORS").string()
	}
	if err = p.output(exec, s); err != nil {
		return
	}
	if parens {
		err = p.mustmatch(")")
	}
	return
}

func (p *awkp) printfstmt(exec bool, stop strset) (val *awkcell, err error) {
	parens := p.match("(") // Optional.
	var args []*awkcell
	args, err = p.exprlist(exec, p.endprint)
	if err != nil {
		return
	}
	if exec && len(args) == 0 {
		args = []*awkcell{p.fields[0]}
	}
	var fmtd string
	if exec {
		// TODO: Handle OFMT
		fmtd, err = p.sprintf(args[0].string(), args[1:])
		if err != nil {
			return
		}
	}
	if err = p.output(exec, fmtd); err != nil {
		return
	}
	if parens {
		err = p.mustmatch(")")
	}
	return
}

func (p *awkp) output(exec bool, s string) (err error) {
	// TODO: add "|" support
	var file io.Writer
	if p.matchany(">", ">>", "|") {
		tok := p.peek(-1)
		op := tok.kind
		var val *awkcell
		if val, err = p.expr(exec, p.endexpr); err != nil {
			return
		}
		file = p.file(val.string())
		if exec && file == nil {
			var flag int
			if op == ">" {
				flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			} else if op == ">>" {
				flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
			}
			// FIXME: replace with proxyfs
			file, err = os.OpenFile(val.string(), flag, 0644)
			if err != nil {
				return p.lexer.newTokenErrorf(tok, "bad file '%s': %s",
					val.string(), err)
			}
			p.files[val.string()] = file.(io.ReadWriteCloser)
		}
	} else {
		file = p.ios.Out
	}
	if !exec {
		return
	}
	fmt.Fprint(file, s)
	return
}

func (p *awkp) returnstmt(exec bool, stop strset) (val *awkcell, err error) {
	tok := p.peek(-1)
	val, err = p.expr(exec, p.endexpr)
	if err != nil {
		return
	}
	if !exec {
		return
	}
	err = p.lexer.newJumpError(tok)
	return
}

func (p *awkp) sprintf(fmtstr string, a []*awkcell) (string, error) {
	var result strings.Builder
	var ai int
	format := []rune(fmtstr)
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			result.WriteRune(format[i])
			continue
		}
		if format[i+1] == '%' {
			result.WriteRune('%')
			i++
			continue
		}
		if ai >= len(a) {
			return "", fmt.Errorf("not enough arguments")
		}
		strt := i
		for {
			i++
			if i >= len(format) {
				return "", fmt.Errorf("bad verb: %s", string(format[strt:i+1]))
			}
			if runealpha(format[i]) {
				break
			}
		}
		verbslice := format[strt : i+1]
		kind := verbslice[len(verbslice)-1]
		verb := string(verbslice)
		switch kind {
		case 'c', 's':
			result.WriteString(fmt.Sprintf(verb, a[ai].string()))
		case 'd', 'i', 'o', 'x', 'X':
			result.WriteString(fmt.Sprintf(verb, int(a[ai].num())))
		case 'a', 'A', 'f', 'e', 'E', 'g', 'G':
			result.WriteString(fmt.Sprintf(verb, a[ai].num()))
		default:
			return "", fmt.Errorf("bad verb: %s", string(format[strt:i+1]))
		}
		ai++
	}

	return result.String(), nil
}

func (p *awkp) forstmt(exec bool, stop strset) (*awkcell, error) {
	pos := p.pos
	if p.match("(", "name", "in", "name", ")") {
		p.pos = pos
		return p.forstmtarr(exec, stop)
	} else {
		return p.forstmtc(exec, stop)
	}
}

func (p *awkp) forstmtarr(exec bool, stop strset) (val *awkcell, err error) {
	p.next()                        // "("
	loopval := p.sym(p.next().name) // "name"
	p.next()                        // "in"
	arrval := p.sym(p.next().name)  // "name"
	p.next()                        // ")"
	pos := p.pos
	for i := range arrval.arrval.contents {
		for c := arrval.arrval.contents[i]; c != nil; c = c.next {
			p.pos = pos
			loopval.setString(c.name)
			if val, err = p.evalstmt(exec, p.endstmt); err != nil {
				return
			}
		}
	}
	return
}

func (p *awkp) forstmtc(exec bool, stop strset) (val *awkcell, err error) {
	var stoploop bool
	firstiter := true
	pos := p.pos
	for {
		p.pos = pos
		if err = p.mustmatch("("); err != nil {
			return
		}
		if !p.match(";") {
			val, err = p.evalstmt(exec && firstiter, p.endexpr)
			if err != nil {
				return
			}
		}
		condpos := p.pos
		if !p.match(";") {
			if _, err = p.expr(false, p.endexpr); err != nil {
				return
			}
			if err = p.mustmatch(";"); err != nil {
				return
			}
		}
		val, err = p.evalstmt(exec && !firstiter && !stoploop, p.endexpr)
		if err != nil {
			return
		}
		stmtpos := p.pos
		p.pos = condpos
		if !p.match(";") {
			val, err = p.expr(exec, p.endexpr)
			if err != nil {
				return
			}
			if exec && !val.bool() {
				stoploop = true
			}
			if err = p.mustmatch(";"); err != nil {
				return
			}
		}
		p.pos = stmtpos
		if err = p.mustmatch(")"); err != nil {
			return
		}
		if val, err = p.evalstmt(exec && !stoploop, p.endstmt); err != nil {
			return
		}
		if stoploop || !exec {
			return
		}
		firstiter = false
	}
}

func (p *awkp) ifstmt(exec bool, stop strset) (val *awkcell, err error) {
	var v *awkcell
	ifval, err := p.exprp(exec, stop)
	if err != nil {
		return
	}
	for {
		val, err = p.evalstmt(exec && ifval.bool(), p.endstmt)
		if err != nil {
			return
		}
		if exec && ifval.bool() {
			exec = false
		}
		if !p.match("else") {
			return
		} else if p.match("if") {
			v, err = p.exprp(exec, p.endexpr)
			if err != nil {
				return
			}
			if exec {
				ifval = v
			}
		} else {
			val, err = p.evalstmt(exec, p.endstmt)
			if err != nil {
				return
			}
			return
		}
	}
}

func (p *awkp) whilestmt(exec bool, stop strset) (val *awkcell, err error) {
	start := p.pos
	var whileval *awkcell
	for {
		p.pos = start
		if whileval, err = p.exprp(exec, p.endexpr); err != nil {
			return
		}
		if err = p.mustmatch("{"); err != nil {
			return
		}
		val, err = p.evalblock(exec && whileval.bool())
		if val != nil {
			return
		}
		var terr *tokenError
		switch {
		case err == nil:
			break
		case errors.As(err, &terr) && terr.jump && terr.token.kind == "break":
			err = nil
			exec = false
			continue
		case errors.As(err, &terr) && terr.jump && terr.token.kind == "continue":
			err = nil
			continue
		default:
			return
		}
		if !exec || !whileval.bool() {
			break
		}
	}
	return
}

func (p *awkp) expr(exec bool, stop strset) (*awkcell, error) {
	return p.exprs[0](exec, stop)
}

func (p *awkp) exprp(exec bool, stop strset) (val *awkcell, err error) {
	if err = p.mustmatch("("); err != nil {
		return
	}
	if val, err = p.expr(exec, stop); err != nil {
		return
	}
	err = p.mustmatch(")")
	return
}

func (p *awkp) exprlist(exec bool, stop strset) (vals []*awkcell, err error) {
	var val *awkcell
	// TODO: skip newlines if present
	for !stop[p.peek(0).kind] {
		val, err = p.expr(exec, stop)
		if err != nil {
			return
		}
		if val != nil {
			vals = append(vals, val)
		}
		if !p.match(",") {
			return
		}
	}
	return
}

func (p *awkp) exprlistp(exec bool, stop strset) (vals []*awkcell, err error) {
	if err = p.mustmatch("("); err != nil {
		return
	}
	if vals, err = p.exprlist(exec, stop); err != nil {
		return
	}
	err = p.mustmatch(")")
	return
}

func (p *awkp) assign(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	if !p.matchany("=", "-=", "+=", "*=", "/=", "%=", "^=") {
		return
	}
	if exec && !val.assignable {
		err = p.lexer.newTokenErrorf(p.peek(-1), "bad variable")
		return
	}
	op := p.peek(-1)

	rval, err := p.assign(next, exec, stop) // Right associative.
	if err != nil {
		return
	}

	if !exec {
		return
	}
	switch op.kind {
	case "=":
		val.setCell(rval)
	case "-=":
		val.setNum(val.num() - rval.num())
	case "+=":
		val.setNum(val.num() + rval.num())
	case "*=":
		val.setNum(val.num() * rval.num())
	case "/=":
		if rval.num() == 0 {
			err = p.lexer.newTokenErrorf(op, "bad divisor (0)")
			return
		}
		val.setNum(val.num() / rval.num())
	case "%=":
		val.setNum(math.Mod(val.num(), rval.num()))
	case "^=":
		val.setNum(math.Pow(val.num(), rval.num()))
	}
	if val.onassign != nil {
		if err = val.onassign(); err != nil {
			return
		}
	}
	return
}

func (p *awkp) cond(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	if !p.match("?") {
		return
	}

	var tval, fval *awkcell
	if tval, err = p.expr(exec && val.bool(), stop); err != nil {
		return
	}
	if err = p.mustmatch(":"); err != nil {
		return
	}
	if fval, err = p.expr(exec && !val.bool(), stop); err != nil {
		return
	}
	if val.bool() {
		val = tval
	} else {
		val = fval
	}
	return
}

func (p *awkp) or(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	var rval *awkcell
	for p.match("||") {
		rval, err = next(exec, stop) // Left associative.
		if err != nil {
			return
		}
		if !exec {
			continue
		}
		val = p.bool(val.bool() || rval.bool())
	}
	return
}

func (p *awkp) and(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	var rval *awkcell
	for p.match("&&") {
		if exec && !val.bool() {
			exec = false // Short circuit.
		}
		rval, err = next(exec, stop) // Left associative.
		if err != nil {
			return
		}
		if !exec {
			continue
		}
		val = p.bool(rval.bool())
	}
	return
}

func (p *awkp) inarray(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	var arr *awkcell
	var idx string
	pos := p.pos

	if p.match("(", "exprlist", ")", "in") {
		var vals []*awkcell
		p.pos = pos + 1
		vals, err = p.exprlist(exec, stop)
		if err != nil {
			return
		}
		if exec {
			idx = p.join(vals, p.sym("SUBSEP").string())
		}
	} else {
		val, err = next(exec, stop) // Left associative.
		if err != nil || !p.match("in") {
			return
		}
		idx = val.string()
	}

	if !exec {
		return
	}
	return arr.inArr(idx), nil
}

func (p *awkp) ere(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	var rval *awkcell
	var m bool
	if p.peek(0).kind == "ere" && p.implicitmatch() {
		m = true
		val = p.field(0)
	} else {
		val, err = next(exec, stop)
		if err != nil {
			return
		}

		if p.match("~") {
			m = true
		} else if p.match("!", "~") {
			m = false
		} else {
			return
		}
	}
	for {
		if p.peek(0).kind == "ere" {
			rval = p.string(p.next().name)
		} else {
			rval, err = next(exec, stop)
			if err != nil {
				return
			}
		}
		var re *regexp.Regexp
		re, err = regexp.CompilePOSIX(p.unescapeEre(rval))
		if err != nil {
			return nil, p.lexer.newTokenErrorf(p.peek(0), "bad regex: %s", err)
		}

		if !exec {
			continue
		}
		r := re.MatchString(val.string())
		if m {
			val = p.bool(r)
		} else {
			val = p.bool(!r)
		}

		if p.match("~") {
			m = true
		} else if p.match("!", "~") {
			m = false
		} else {
			return
		}
	}
}

func (p *awkp) comp(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	var op string
	var rval *awkcell
	for !stop[p.peek(0).kind] && p.matchany("<", "<=", "==", "!=", ">=", ">") {
		op = p.peek(-1).kind
		rval, err = next(exec, stop)
		if err != nil {
			return
		}
		if !exec {
			continue
		}
		strcmp := val.numval == nil && rval.numval == nil
		switch op {
		case "<":
			if strcmp {
				val = p.bool(val.string() < rval.string())
			} else {
				val = p.bool(val.num() < rval.num())
			}
		case "<=":
			if strcmp {
				val = p.bool(val.string() <= rval.string())
			} else {
				val = p.bool(val.num() <= rval.num())
			}
		case "==":
			if strcmp {
				val = p.bool(val.string() == rval.string())
			} else {
				val = p.bool(val.num() == rval.num())
			}
		case "!=":
			if strcmp {
				val = p.bool(val.string() != rval.string())
			} else {
				val = p.bool(val.num() != rval.num())
			}
		case ">=":
			if strcmp {
				val = p.bool(val.string() >= rval.string())
			} else {
				val = p.bool(val.num() >= rval.num())
			}
		case ">":
			if strcmp {
				val = p.bool(val.string() > rval.string())
			} else {
				val = p.bool(val.num() > rval.num())
			}
		}
	}
	return
}

func (p *awkp) concat(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	for {
		pos := p.pos
		_, exprerr := next(false, stop)
		p.pos = pos
		if exprerr != nil {
			return // Invalid expression.
		}

		var rval *awkcell
		rval, err = next(exec, stop) // Left associative, always matches.
		if err != nil {
			return
		}
		if !exec {
			return
		}
		val = p.string(val.string() + rval.string())
	}
}

func (p *awkp) add(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	var op string
	var rval *awkcell
	for p.matchany("+", "-") {
		op = p.peek(-1).kind
		rval, err = next(exec, stop)
		if err != nil {
			return
		}
		if !exec {
			continue
		}
		switch op {
		case "+":
			val = p.num(val.num() + rval.num())
		case "-":
			val = p.num(val.num() - rval.num())
		}
	}
	return
}

func (p *awkp) multiply(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	var op *token
	var rval *awkcell
	for p.matchany("*", "/", "%") {
		op = p.peek(-1)
		rval, err = next(exec, stop)
		if err != nil {
			return
		}
		if !exec {
			continue
		}
		switch op.kind {
		case "*":
			val = p.num(val.num() * rval.num())
		case "/":
			if rval.num() == 0 {
				return nil, p.lexer.newTokenErrorf(op, "bad divisor (0)")
			}
			val = p.num(val.num() / rval.num())
		case "%":
			val = p.num(math.Mod(val.num(), rval.num()))
		}
	}
	return
}

func (p *awkp) unary(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	if !p.matchany("-", "+", "!") {
		return next(exec, stop)
	}
	op := p.peek(-1).kind
	val, err = p.unary(next, exec, stop) // Right associative.
	if err != nil || !exec {
		return
	}
	switch op {
	case "-":
		val.setNum(-1 * val.num())
	case "+":
		val.setNum(val.num())
	case "!":
		val.setBool(!val.bool())
	}
	return
}

func (p *awkp) exp(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if err != nil {
		return
	}
	if !p.match("^") {
		return
	}
	rval, err := p.exp(next, exec, stop) // Right associative.
	if err != nil {
		return
	}
	if !exec {
		return
	}
	val = p.num(math.Pow(val.num(), rval.num()))
	return
}

func (p *awkp) prefixop(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	if !p.matchany("++", "--") {
		return next(exec, stop)
	}
	sign := p.peek(-1).kind
	val, err = next(exec, stop)
	if !exec {
		return
	}
	if !val.assignable {
		err = p.lexer.newTokenErrorf(p.peek(0), "bad variable")
		return
	}

	switch sign {
	case "++":
		val.setNum(val.num() + 1)
	case "--":
		val.setNum(val.num() - 1)
	}
	if val.onassign != nil {
		if err = val.onassign(); err != nil {
			return
		}
	}
	return
}

func (p *awkp) postfixop(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	val, err = next(exec, stop)
	if !p.matchany("++", "--") {
		return
	}
	if !exec {
		return
	}
	if !val.assignable {
		err = p.lexer.newTokenErrorf(p.peek(0), "bad variable")
		return
	}

	var varval *awkcell
	switch p.peek(-1).kind {
	case "++":
		varval = val
		val = p.num(varval.num())
		varval.setNum(val.num() + 1)
	case "--":
		varval = val
		val = p.num(varval.num())
		varval.setNum(val.num() - 1)
	}
	if varval.onassign != nil {
		if err = val.onassign(); err != nil {
			return
		}
	}
	return
}

func (p *awkp) fieldref(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	if !p.match("$") {
		return next(exec, stop)
	}
	i, err := next(exec, stop)
	if err != nil || !exec {
		return nil, err
	}
	val = p.field(int(i.num()))
	return
}

func (p *awkp) group(next awkeval, exec bool, stop strset) (val *awkcell, err error) {
	if !p.match("(") {
		return next(exec, stop)
	}
	val, err = p.expr(exec, p.endexpr)
	if err != nil {
		return
	}
	err = p.mustmatch(")")
	return
}

func (p *awkp) val(_ awkeval, exec bool, stop strset) (val *awkcell, err error) {
	// TODO: should we handle stop tokens here?
	tok := p.next()
	switch tok.kind {
	case "number":
		num, err := strconv.ParseFloat(tok.name, 64)
		if err != nil {
			return nil, p.lexer.newTokenErrorf(tok, "bad number")
		}
		val = p.num(num)
	case "name":
		name := p.peek(-1).name
		if p.match("[") {
			var vals []*awkcell
			vals, err = p.exprlist(exec, stop)
			if err != nil {
				return
			}
			if err = p.mustmatch("]"); err != nil {
				return nil, err
			}
			if exec {
				idx := p.join(vals, p.sym("SUBSEP").string())
				val = p.sym(name).arr(idx)
			}
		} else {
			val = p.sym(name)
		}
	case "string":
		var str string
		str, err = p.unescapeStr(tok.name)
		if err != nil {
			return nil, p.lexer.newTokenErrorf(tok, err.Error())
		}
		val = p.string(str)
	case "ere":
		val = p.string(tok.name) // TODO: unescape
	case "builtin_func":
		p.fntok = append(p.fntok, tok)
		defer func() { p.fntok = p.fntok[:len(p.fntok)-1] }()
		return p.builtin(tok.name, exec, stop)
	case "func_name":
		p.fntok = append(p.fntok, tok)
		defer func() { p.fntok = p.fntok[:len(p.fntok)-1] }()
		return p.fn(tok.name, exec, stop)
	default:
		return nil, p.lexer.newTokenError(tok)
	}
	if !exec {
		return nil, err
	}
	return
}

func (p *awkp) builtin(name string, exec bool, stop strset) (val *awkcell, err error) {
	var args []*awkcell
	if p.match("(") {
		args, err = p.exprlist(true, stop)
		if err != nil {
			return
		}
		if err = p.mustmatch(")"); err != nil {
			return
		}
	}
	if !exec {
		return
	}
	fn, ok := p.builtins[name]
	if !ok {
		err = p.lexer.newTokenErrorf(p.fntok[len(p.fntok)-1], "bad function")
		return
	}
	return fn(args)
}

func (p *awkp) fn(name string, exec bool, stop strset) (val *awkcell, err error) {
	fn := p.sym(name).fnval
	if fn == nil {
		return nil, p.lexer.newTokenErrorf(p.peek(-1), "bad function: %s", name)
	}
	if err = p.mustmatch("("); err != nil {
		return
	}
	var args []*awkcell
	if args, err = p.exprlist(exec, stop); err != nil {
		return
	}
	if err = p.mustmatch(")"); err != nil {
		return
	}
	if !exec {
		return
	}
	val, err = p.call(fn, args)
	var terr *tokenError
	if errors.As(err, &terr) && terr.token.name == "return" {
		err = nil
	}
	return
}

func (p *awkp) call(fn *awkfn, args []*awkcell) (val *awkcell, err error) {
	p.frames = append(p.frames, &awkframe{symbols: make(map[string]*awkcell)})
	defer func() { p.frames = p.frames[:len(p.frames)-1] }()
	for i, tok := range fn.params {
		c := &awkcell{prog: p, assignable: true}
		if i < len(args) {
			c.setCell(args[i])
		}
		p.sym(tok.name).setCell(c)
	}
	pos := p.pos
	defer func() { p.pos = pos }()
	p.pos = fn.block.pos
	return p.evalblock(true)
}

func (p *awkp) fnlength(args []*awkcell) (val *awkcell, err error) {
	if len(args) > 2 {
		return nil, p.lexer.newTokenErrorf(p.peek(0),
			"bad argc: want 0-1, got %d", len(args))
	}
	var arg *awkcell
	if len(args) == 0 {
		arg = p.field(0)
	} else {
		arg = args[0]
	}
	return p.num(float64(utf8.RuneCountInString(arg.string()))), nil
}

func (p *awkp) fngsub(args []*awkcell) (val *awkcell, err error) {
	if len(args) < 2 || len(args) > 4 {
		return nil, p.lexer.newTokenErrorf(p.peek(0),
			"bad argc: want 2-3, got %d", len(args))
	}
	pat := args[0].string()
	repl := args[1].string()
	if len(args) == 3 {
		val = args[2]
	} else {
		val = p.field(0)
	}
	var re *regexp.Regexp
	if re, err = regexp.Compile(pat); err != nil {
		err = p.lexer.newTokenErrorf(p.peek(0), "bad regex: %s", err)
		return
	}
	val.setString(re.ReplaceAllString(val.string(), repl))
	return
}

func (p *awkp) fnint(args []*awkcell) (val *awkcell, err error) {
	if len(args) < 1 || len(args) > 1 {
		return nil, p.lexer.newTokenErrorf(p.peek(0), "bad argc: want 1, got %d", len(args))
	}
	input := args[0]
	return p.num(float64(int(input.num()))), nil
}

func (p *awkp) fnsprintf(args []*awkcell) (val *awkcell, err error) {
	var fmtd string
	fmtd, err = p.sprintf(args[0].string(), args[1:])
	if err != nil {
		return
	}
	val = p.string(fmtd)
	return
}

func (p *awkp) fnsubstr(args []*awkcell) (val *awkcell, err error) {
	if len(args) > 3 {
		return nil, p.lexer.newTokenErrorf(p.peek(0),
			"bad argc: want 2-3, got %d", len(args))
	}
	s := []rune(args[0].string())
	m := int(args[1].num())
	n := 0
	if len(args) > 1 {
		n = int(args[2].num())
	}
	val = p.string(string(s[m-1 : m-1+n]))
	return
}

type filesReader struct {
	readers []*fileReader
	offset  int
}

type fileReader struct {
	filename string
	reader   *bufio.Reader
}

func (fr *filesReader) ReadRune() (r rune, n int, err error) {
	for {
		if fr.offset >= len(fr.readers) {
			err = io.EOF
			return
		}
		r, n, err = fr.readers[fr.offset].reader.ReadRune()
		if err == io.EOF {
			fr.offset++
			continue
		}
		return
	}
}

func (fr *filesReader) Filename() string {
	if fr.offset >= len(fr.readers) {
		return ""
	}
	return fr.readers[fr.offset].filename
}

type awkmap struct {
	count    uint
	size     uint
	contents []*awkcell
}

const (
	awkmapinit = 50
	awkmapfull = 2
	awkmapgrow = 4
)

func (m *awkmap) get(key string) *awkcell {
	if m.size == 0 {
		m.size = awkmapinit
		m.contents = make([]*awkcell, m.size)
	}
	hash := m.hash(key)
	for c := m.contents[hash]; c != nil; c = c.next {
		if c.name == key {
			return c
		}
	}
	return nil
}

func (m *awkmap) set(key string, val *awkcell) {
	if m.size == 0 {
		m.size = awkmapinit
		m.contents = make([]*awkcell, m.size)
	}
	val.name = key
	hash := m.hash(key)
	var c *awkcell
	for {
		c = m.contents[hash]
		if c == nil {
			m.contents[hash] = val
			break
		} else if c.next == nil {
			c.next = val
			break
		}
	}
	m.count++
	if m.count > m.size*awkmapfull {
		m.rehash()
	}
}

func (m *awkmap) del(key string) {
	if m.size == 0 {
		return
	}
	hash := m.hash(key)
	var prevc *awkcell
	for c := m.contents[hash]; c != nil; c = c.next {
		if c.name == key && prevc != nil {
			prevc.next = c.next
			m.count--
		} else if c.name == key {
			m.contents[hash] = c.next
			m.count--
		}
	}
}

func (m *awkmap) hash(s string) uint {
	var val uint32
	for c := 0; c < len(s); c++ {
		val = uint32(s[c]) + 31*val
	}
	return uint(val) % m.size
}

func (m *awkmap) rehash() {
	m.size *= awkmapgrow
	nc := make([]*awkcell, m.size)
	for i := range m.contents {
		for c := m.contents[i]; c != nil; c = c.next {
			hash := m.hash(c.name)
			var ncc *awkcell
			for {
				ncc = nc[hash]
				if ncc == nil {
					nc[hash] = c
					break
				} else if ncc.next == nil {
					ncc.next = c
					break
				}
			}
		}
	}
	m.contents = nc
}
