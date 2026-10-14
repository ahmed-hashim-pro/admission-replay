package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite docs/*.txt from the CLI's output")

func cli(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return out.String(), errb.String(), code
}

// The README quotes these outputs; docs/*.txt hold them, and this test fails
// when either goes stale. go test ./cmd/admission-replay -run Docs -update
// rewrites them.
var docs = []struct {
	file string
	args []string
	code int
}{
	{"compare.txt", []string{"compare", "examples/audit.log", "examples/policies/registry-allowlist.yaml",
		"examples/policies/strict-baseline.yaml", "examples/policies/targeted.yaml", "--bad", "examples/bad.txt"}, 0},
	{"replay.txt", []string{"replay", "examples/audit.log", "examples/policies/strict-baseline.yaml", "--bad", "examples/bad.txt", "--limit", "3"}, 0},
	{"targeted.txt", []string{"replay", "examples/audit.log", "examples/policies/targeted.yaml", "--bad", "examples/bad.txt",
		"--show", "caught", "--fail-on-block", "--fail-on-miss"}, 0},
	{"check.txt", []string{"check", "examples/policies/targeted.yaml"}, 0},
}

func TestDocs(t *testing.T) {
	chdirRoot(t)
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		out, errs, code := cli(t, d.args...)
		if code != d.code {
			t.Fatalf("%s: exit %d, want %d\n%s", d.file, code, d.code, errs)
		}
		cmd := "$ admission-replay " + strings.Join(globbed(d.args), " ") + "\n"
		got := cmd + out
		path := filepath.Join("docs", d.file)
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s is stale; rerun with -update\n--- got\n%s", path, got)
		}
		if !bytes.Contains(readme, want) {
			t.Errorf("README.md does not quote %s verbatim", path)
		}
	}
}

// globbed shows the three example policies as the glob a reader would type.
func globbed(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == "examples/policies/registry-allowlist.yaml" && i+2 < len(args) && args[i+2] == "examples/policies/targeted.yaml" {
			out = append(out, "examples/policies/*.yaml")
			i += 2
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func chdirRoot(t *testing.T) {
	t.Helper()
	wd, _ := os.Getwd()
	t.Chdir(filepath.Join(wd, "..", ".."))
}

func TestExitCodes(t *testing.T) {
	chdirRoot(t)
	strict := "examples/policies/strict-baseline.yaml"
	for _, tc := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"replay", "examples/audit.log", strict, "--bad", "examples/bad.txt", "--fail-on-miss"}, 1, ""},
		{[]string{"replay", "examples/audit.log", strict, "--fail-on-block"}, 1, ""},
		// Unlabelled, the three bad writes are just writes the policy blocks.
		{[]string{"replay", "examples/audit.log", "examples/policies/targeted.yaml", "--fail-on-block"}, 1, ""},
		{[]string{"replay", "examples/audit.log", "examples/policies/targeted.yaml", "--bad", "examples/bad.txt", "--fail-on-block", "--fail-on-miss"}, 0, ""},
		{[]string{"replay", "examples/audit.log", strict, "--fail-on-miss"}, 2, "--fail-on-miss needs --bad"},
		{[]string{"replay", "examples/audit.log", strict, "--show", "everything"}, 2, `unknown section "everything"`},
		{[]string{"replay", "examples/audit.log"}, 2, "one policy file"},
		{[]string{"compare", "examples/audit.log", strict, "--bad", "examples/policies/targeted.yaml"}, 2, "is not a write in the log"},
		{[]string{"compare", "nope.log", strict}, 2, "no such file"},
		{[]string{"compare", "examples/bad.txt", strict}, 2, "not an audit event"},
		{[]string{"frobnicate"}, 2, `unknown command "frobnicate"`},
		{[]string{}, 2, "usage:"},
	} {
		_, errs, code := cli(t, tc.args...)
		if code != tc.code || !strings.Contains(errs, tc.err) {
			t.Errorf("%v: exit %d (want %d), stderr %q (want %q)", tc.args, code, tc.code, errs, tc.err)
		}
	}
}

func TestCheckFindsCompileErrors(t *testing.T) {
	data, err := os.ReadFile("../../examples/policies/strict-baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(data), "c.image.startsWith('registry.example.com/')", "c.image.startswith('registry.example.com/')", 1)
	path := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(path, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code := cli(t, "check", path)
	if code != 1 || !strings.Contains(out, "spec.validations[0].expression") || !strings.Contains(out, "startswith") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestJSON(t *testing.T) {
	chdirRoot(t)
	out, _, code := cli(t, "replay", "examples/audit.log", "examples/policies/strict-baseline.yaml", "--bad", "examples/bad.txt", "--json")
	if code != 0 {
		t.Fatal(code)
	}
	var doc struct {
		Policy   string
		Summary  struct{ Blocked, Caught, Bad int }
		Outcomes []struct {
			AuditID string
			Denied  bool
			Bad     *string
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	denied := 0
	for _, o := range doc.Outcomes {
		if o.Denied && o.Bad == nil {
			denied++
		}
	}
	if doc.Policy != "strict-baseline" || doc.Summary.Bad != 3 || denied != doc.Summary.Blocked || denied == 0 {
		t.Fatalf("%+v (denied %d)", doc.Summary, denied)
	}
}
