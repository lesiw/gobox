package apps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TODO: Add POSIX example programs.
// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/awk.html

// TODO: user-defined functions - split up T.func
// TODO: at least one test per statement.
// TODO: optional test (selectable by cli flag) to pull down the One True Awk test suite.

var awkTestData = map[string]string{}

type awkTest struct {
	t        *testing.T
	input    string
	name     string
	outfiles []string
}

func (t *awkTest) prog() string {
	return "testdata/awk/" + t.input + "." + t.name + ".awk"
}

func (t *awkTest) inputpath() string {
	return "testdata/awk/" + t.input
}

func (t *awkTest) output() string {
	s, err := os.ReadFile("testdata/awk/" + t.input + "." + t.name + ".out")
	if err != nil {
		t.t.Fatalf("failed to read file: %v", err)
	}
	return string(s)
}

func (t *awkTest) run() (string, string) {
	var err error
	stdout := new(strings.Builder)
	stderr := new(strings.Builder)
	ios := &IOs{Out: stdout, Err: stderr}

	prog := t.prog()
	if len(t.outfiles) > 0 {
		prog, err = filepath.Abs(prog)
		if err != nil {
			t.t.Fatalf("failed to get absolute path: %v", err)
		}
	}
	argv := []string{"-f", prog}

	input := t.inputpath()
	if len(t.outfiles) > 0 && input != "" {
		input, err = filepath.Abs(input)
		if err != nil {
			t.t.Fatalf("failed to get absolute path: %v", err)
		}
	}
	if input != "" {
		argv = append(argv, input)
	}

	var dir string
	if len(t.outfiles) > 0 {
		pwd, err := os.Getwd()
		if err != nil {
			t.t.Fatal(err)
		}
		dir = t.t.TempDir()
		if err := os.Chdir(dir); err != nil {
			t.t.Fatalf("failed to chdir to temp directory: %s", err)
		}
		defer func() { os.Chdir(pwd) }()
	}

	ret := Awk(argv, ios)
	if ret != 0 {
		t.t.Fatalf("response code: want 0, got %d\nstderr\n---\n%s\n", ret, stderr.String())
	}
	return stdout.String(), dir
}

func TestAwk(t *testing.T) {
	files, err := os.ReadDir("testdata/awk")
	if err != nil {
		t.Fatal(err)
	}
	tests := make(map[string]*awkTest)
	for _, file := range files {
		if !strings.Contains(file.Name(), ".") {
			continue
		}
		test := strings.Split(file.Name(), ".")
		if len(test) < 2 {
			t.Fatalf("bad test case: %s", file.Name())
		}
		input := test[0]
		name := test[1]
		if _, ok := tests[name]; !ok {
			tests[name] = &awkTest{t: t, input: input, name: name}
		}
		ftype := test[2]
		if ftype != "awk" && ftype != "out" {
			tests[name].outfiles = append(tests[name].outfiles, ftype)
		}
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, outdir := test.run()
			if got != string(test.output()) {
				t.Errorf("bad output (stdout)\ngot\n----\n%s\nwant\n----\n%s\n",
					got, test.output())
			}
			for _, outfile := range test.outfiles {
				buf, err := os.ReadFile("testdata/awk/" + test.input + "." +
					test.name + "." + outfile + ".out")
				if err != nil {
					t.Fatalf("failed to read file: %v", err)
				}
				want := string(buf)
				buf, err = os.ReadFile(outdir + "/" + outfile)
				if err != nil {
					t.Fatalf("could not read output file: %v", err)
				}
				got := string(buf)
				if got != want {
					t.Errorf("bad output (%s)\ngot\n----\n%s\nwant\n----\n%s",
						outfile, got, want)
				}
			}
		})
	}
}

func TestAwkInlineProgram(t *testing.T) {
	stdout := new(strings.Builder)
	stderr := new(strings.Builder)
	ios := &IOs{
		In:  strings.NewReader("hello world"),
		Out: stdout,
		Err: stderr,
	}
	ret := Awk([]string{"{ print; }"}, ios)
	if ret != 0 {
		t.Fatalf("response code: want 0, got %d\nstderr\n---\n%s\n", ret, stderr.String())
	}
	if stdout.String() != "hello world\n" {
		t.Fatalf("output mismatch\n----\n%s\n----\n%s\n",
			stdout.String(), "hello world\n")
	}
}

// TODO
// func TestAwkInlineLoop(t *testing.T) {
// 	stdout := new(strings.Builder)
// 	stderr := new(strings.Builder)
// 	ios := &IOs{Out: stdout, Err: stderr}
// 	ret := Awk([]string{"$3 > 11", "apps/testdata/awk/elements"}, ios)
// 	if ret != 0 {
// 		t.Fatalf("response code: want 0, got %d\nstderr\n---\n%s\n", ret, stderr.String())
// 	}
// 	if stdout.String() != "\n" {
// 		t.Fatalf("output mismatch\n----\n%s\n----\n%s\n", stdout.String(), "\n")
// 	}
// }
