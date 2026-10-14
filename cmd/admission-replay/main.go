// admission-replay replays a cluster's audit log through a proposed
// ValidatingAdmissionPolicy and reports what it would have blocked and what
// it would have let through.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/klog/v2"

	"github.com/ahmed-hashim-pro/admission-replay/history"
	"github.com/ahmed-hashim-pro/admission-replay/policy"
	"github.com/ahmed-hashim-pro/admission-replay/replay"
)

var version = "dev"

const usage = `admission-replay: replay a cluster's audit log through a proposed admission
policy, before it goes live.

usage:
  admission-replay compare LOG POLICY.yaml... [--bad FILE] [--initial FILE]
      rank candidate policies: bad writes caught, legitimate writes blocked
  admission-replay replay LOG POLICY.yaml [--bad FILE] [--initial FILE]
                          [--show WHAT] [--limit N] [--json]
                          [--fail-on-block] [--fail-on-miss]
      one candidate, write by write
  admission-replay check POLICY.yaml...
      parse the files and compile every CEL expression
  admission-replay version

LOG is a Kubernetes audit log (audit.k8s.io/v1, one JSON event per line, or
an EventList; may be gzipped) recorded at RequestResponse level for the
resources the policy matches. Each POLICY file holds ValidatingAdmissionPolicies
and their bindings, replayed together.

  --bad FILE      audit IDs of writes that should have been stopped, one per
                  line, optionally followed by a note
  --initial FILE  objects that existed before the log starts (kubectl get -o
                  yaml output), so their updates and deletes can be replayed
  --show WHAT     comma-separated: blocked, missed, caught, warned, skipped,
                  all (default blocked,missed,caught)
  --limit N       writes listed per section (default 10; 0 for all)

exit status: 0 ok; 1 a --fail-on gate tripped; 2 bad input.
`

func init() {
	// The informers inside the admission plugin log at info level.
	klog.SetOutput(io.Discard)
	klog.LogToStderr(false)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	code := 0
	switch args[0] {
	case "compare":
		err = compare(args[1:], stdout)
	case "replay":
		code, err = replayCmd(args[1:], stdout)
	case "check":
		code, err = check(args[1:], stdout)
	case "version", "--version":
		fmt.Fprintln(stdout, "admission-replay", version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		err = usageError{fmt.Sprintf("unknown command %q", args[0])}
	}
	if err != nil {
		var u usageError
		if errors.As(err, &u) {
			fmt.Fprintf(stderr, "admission-replay: %s\nrun admission-replay help for usage\n", u.msg)
		} else {
			fmt.Fprintf(stderr, "admission-replay: %v\n", err)
		}
		return 2
	}
	return code
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

// parse lets flags and positional arguments come in any order.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usageError{err.Error()}
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

type inputs struct {
	log        *history.Log
	logPath    string
	candidates []*policy.Candidate
	opts       replay.Options
}

func load(logPath string, policies []string, badPath, initialPath string) (*inputs, error) {
	in := &inputs{logPath: logPath}
	var err error
	if in.log, err = history.ReadFile(logPath); err != nil {
		return nil, err
	}
	if len(in.log.Entries) == 0 {
		return nil, fmt.Errorf("%s: no writes to replay (is it an audit log at Request or RequestResponse level?)", logPath)
	}
	for _, p := range policies {
		c, err := policy.Load(p)
		if err != nil {
			return nil, err
		}
		in.candidates = append(in.candidates, c)
	}
	if badPath != "" {
		if in.opts.Bad, err = readBad(badPath, in.log); err != nil {
			return nil, err
		}
	}
	if initialPath != "" {
		if in.opts.Initial, err = readInitial(initialPath); err != nil {
			return nil, err
		}
	}
	return in, nil
}

func readBad(path string, log *history.Log) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, e := range log.Entries {
		ids[e.ID] = true
	}
	bad := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, note, _ := strings.Cut(line, " ")
		if !ids[id] {
			return nil, fmt.Errorf("%s:%d: audit ID %s is not a write in the log", path, n, id)
		}
		if _, dup := bad[id]; dup {
			return nil, fmt.Errorf("%s:%d: audit ID %s is listed twice", path, n, id)
		}
		bad[id] = strings.TrimSpace(note)
	}
	return bad, nil
}

func readInitial(path string) ([]*unstructured.Unstructured, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := utilyaml.NewYAMLOrJSONDecoder(f, 4096)
	var out []*unstructured.Unstructured
	for {
		u := &unstructured.Unstructured{}
		if err := dec.Decode(&u.Object); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(u.Object) == 0 {
			continue
		}
		if u.IsList() {
			list, err := u.ToList()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			for i := range list.Items {
				out = append(out, &list.Items[i])
			}
			continue
		}
		out = append(out, u)
	}
}

// runAll replays each candidate in turn. Engines share the API server's CEL
// composition template, which is not safe to compile into while another
// engine evaluates, so candidates do not run concurrently.
func runAll(in *inputs) ([]*replay.Result, error) {
	results := make([]*replay.Result, len(in.candidates))
	for i, c := range in.candidates {
		r, err := replay.Run(in.log, c, in.opts)
		if err != nil {
			return nil, err
		}
		results[i] = r
	}
	return results, nil
}

func header(w io.Writer, in *inputs) {
	first, last := in.log.Entries[0].Time, in.log.Entries[len(in.log.Entries)-1].Time
	days := last.Sub(first).Hours() / 24
	fmt.Fprintf(w, "%s: %d writes from %s to %s (%.1f days)", in.logPath, len(in.log.Entries),
		first.UTC().Format("2006-01-02"), last.UTC().Format("2006-01-02"), days)
	if in.opts.Bad != nil {
		fmt.Fprintf(w, ", %d labelled bad", len(in.opts.Bad))
	}
	fmt.Fprintln(w)
}

func compare(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	bad := fs.String("bad", "", "")
	initial := fs.String("initial", "", "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		return usageError{"compare needs an audit log and at least one policy file"}
	}
	in, err := load(pos[0], pos[1:], *bad, *initial)
	if err != nil {
		return err
	}
	results, err := runAll(in)
	if err != nil {
		return err
	}
	type row struct {
		r *replay.Result
		s replay.Summary
	}
	rows := make([]row, len(results))
	for i, r := range results {
		rows[i] = row{r, r.Summarize()}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i].s, rows[j].s
		if a.Caught != b.Caught {
			return a.Caught > b.Caught
		}
		if a.Blocked != b.Blocked {
			return a.Blocked < b.Blocked
		}
		return a.Flagged < b.Flagged
	})

	header(w, in)
	fmt.Fprintln(w)
	width := len("policy")
	for _, rw := range rows {
		width = max(width, len(rw.r.Candidate.Name))
	}
	name := func(s string) string { return s + strings.Repeat(" ", width-len(s)) }
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
	labelled := in.opts.Bad != nil
	if labelled {
		fmt.Fprintf(tw, "\t%s\tbad caught\tlegit blocked\tby controllers\twarned\tskipped\t\n", name("policy"))
	} else {
		fmt.Fprintf(tw, "\t%s\tblocked\tby controllers\twarned\tskipped\t\n", name("policy"))
	}
	for i, rw := range rows {
		s := rw.s
		if labelled {
			caught := fmt.Sprintf("%d/%d", s.Caught, s.Bad)
			if s.BadWarned > 0 {
				caught += fmt.Sprintf(" (+%d warned)", s.BadWarned)
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%d\t%d\t%d\t\n", i+1, name(rw.r.Candidate.Name), caught, s.Blocked, s.BlockedBySys, s.Flagged, s.Skipped)
		} else {
			fmt.Fprintf(tw, "%d\t%s\t%d\t%d\t%d\t%d\t\n", i+1, name(rw.r.Candidate.Name), s.Blocked, s.BlockedBySys, s.Flagged, s.Skipped)
		}
	}
	tw.Flush()
	fmt.Fprintln(w)
	if !labelled {
		fmt.Fprintln(w, "no --bad labels: nothing to score as caught or missed.")
		notes(w, results)
		return nil
	}
	fmt.Fprintln(w, "ranked by bad writes caught, then legitimate writes blocked, then warnings.")
	first := true
	for _, rw := range rows {
		lead := name(rw.r.Candidate.Name)
		for _, o := range rw.r.Outcomes {
			if !o.IsBad || o.Verdict.Denied {
				continue
			}
			if first {
				fmt.Fprintln(w, "\nlet through:")
				first = false
			}
			fmt.Fprintf(w, "  %s  %s\n", lead, badName(&o))
			lead = strings.Repeat(" ", width)
		}
	}
	notes(w, results)
	return nil
}

func notes(w io.Writer, results []*replay.Result) {
	for _, r := range results {
		for _, n := range r.Candidate.Notes {
			fmt.Fprintf(w, "note: %s: %s\n", r.Candidate.Name, n)
		}
	}
	if len(results) > 0 && len(results[0].AssumedNamespaces) > 0 {
		fmt.Fprintf(w, "note: namespaces never created in the log, replayed with no labels of their own: %s (pass --initial)\n",
			strings.Join(results[0].AssumedNamespaces, ", "))
	}
	if len(results) > 0 {
		reasons := map[string]int{}
		for _, o := range results[0].Outcomes {
			if o.Skipped != "" {
				reasons[o.Skipped]++
			}
		}
		for _, k := range sortedKeys(reasons) {
			fmt.Fprintf(w, "note: %d writes skipped: %s\n", reasons[k], k)
		}
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func badName(o *replay.Outcome) string {
	if o.Bad != "" {
		return o.Bad
	}
	return o.Entry.ID
}

func replayCmd(args []string, w io.Writer) (int, error) {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	bad := fs.String("bad", "", "")
	initial := fs.String("initial", "", "")
	show := fs.String("show", "blocked,missed,caught", "")
	limit := fs.Int("limit", 10, "")
	asJSON := fs.Bool("json", false, "")
	failBlock := fs.Bool("fail-on-block", false, "")
	failMiss := fs.Bool("fail-on-miss", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return 0, err
	}
	if len(pos) != 2 {
		return 0, usageError{"replay needs an audit log and one policy file"}
	}
	if *failMiss && *bad == "" {
		return 0, usageError{"--fail-on-miss needs --bad"}
	}
	sections := map[string]bool{}
	for _, s := range strings.Split(*show, ",") {
		s = strings.TrimSpace(s)
		switch s {
		case "all":
			for _, k := range []string{"blocked", "missed", "caught", "warned", "skipped"} {
				sections[k] = true
			}
		case "blocked", "missed", "caught", "warned", "skipped":
			sections[s] = true
		case "":
		default:
			return 0, usageError{fmt.Sprintf("--show: unknown section %q", s)}
		}
	}
	in, err := load(pos[0], pos[1:], *bad, *initial)
	if err != nil {
		return 0, err
	}
	results, err := runAll(in)
	if err != nil {
		return 0, err
	}
	r := results[0]
	s := r.Summarize()
	if *asJSON {
		if err := writeJSON(w, r); err != nil {
			return 0, err
		}
	} else {
		printReplay(w, in, r, s, sections, *limit)
	}
	code := 0
	if *failBlock && s.Blocked > 0 {
		code = 1
	}
	if *failMiss && s.Caught < s.Bad {
		code = 1
	}
	return code, nil
}

func printReplay(w io.Writer, in *inputs, r *replay.Result, s replay.Summary, show map[string]bool, limit int) {
	header(w, in)
	c := r.Candidate
	for _, b := range c.Bindings {
		acts := make([]string, len(b.Spec.ValidationActions))
		for i, a := range b.Spec.ValidationActions {
			acts[i] = string(a)
		}
		fmt.Fprintf(w, "%s: binding %s -> policy %s (%s)\n", c.Name, b.Name, b.Spec.PolicyName, strings.Join(acts, ", "))
	}
	fmt.Fprintln(w)

	type section struct {
		key, title string
		match      func(*replay.Outcome) bool
	}
	secs := []section{
		{"blocked", fmt.Sprintf("BLOCKED %d legitimate writes", s.Blocked), func(o *replay.Outcome) bool {
			return !o.IsBad && o.Blocked() && !o.Entry.Failed()
		}},
		{"missed", fmt.Sprintf("LET THROUGH %d of %d bad writes", s.Bad-s.Caught, s.Bad), func(o *replay.Outcome) bool {
			return o.IsBad && !o.Verdict.Denied
		}},
		{"caught", fmt.Sprintf("CAUGHT %d of %d bad writes", s.Caught, s.Bad), func(o *replay.Outcome) bool {
			return o.IsBad && o.Verdict.Denied
		}},
		{"warned", fmt.Sprintf("WARNED %d legitimate writes (admitted)", s.Flagged), func(o *replay.Outcome) bool {
			return !o.IsBad && o.Flagged() && !o.Entry.Failed()
		}},
		{"skipped", fmt.Sprintf("SKIPPED %d writes", s.Skipped), func(o *replay.Outcome) bool { return o.Skipped != "" }},
	}
	for _, sec := range secs {
		if !show[sec.key] || (in.opts.Bad == nil && (sec.key == "missed" || sec.key == "caught")) {
			continue
		}
		var list []*replay.Outcome
		for i := range r.Outcomes {
			if sec.match(&r.Outcomes[i]) {
				list = append(list, &r.Outcomes[i])
			}
		}
		fmt.Fprintln(w, sec.title)
		for i, o := range list {
			if limit > 0 && i == limit {
				fmt.Fprintf(w, "  ... %d more (--limit 0 lists them all)\n", len(list)-limit)
				break
			}
			printOutcome(w, o)
		}
		if sec.key == "blocked" && len(list) > 0 {
			fmt.Fprintln(w, "  by user:")
			for _, cnt := range r.BlockedUsers() {
				fmt.Fprintf(w, "    %4d  %s\n", cnt.N, cnt.Label)
			}
			fmt.Fprintln(w, "  by failed validation:")
			for _, cnt := range r.BlockReasons() {
				fmt.Fprintf(w, "    %4d  %s\n", cnt.N, cnt.Label)
			}
		}
		fmt.Fprintln(w)
	}
	notes(w, []*replay.Result{r})
}

func printOutcome(w io.Writer, o *replay.Outcome) {
	e := o.Entry
	target := e.Name
	if target == "" && history.IsObject(e.Response) {
		target = e.Response.GetName()
	}
	if e.Namespace != "" {
		target = e.Namespace + "/" + target
	}
	fmt.Fprintf(w, "  %s  %-10s %-6s %s %s\n", e.Time.UTC().Format("2006-01-02 15:04"), e.User.GetName(), e.Verb, e.Resource.Resource, target)
	if o.IsBad && o.Bad != "" {
		fmt.Fprintf(w, "      labelled bad: %s\n", o.Bad)
	}
	if o.Skipped != "" {
		fmt.Fprintf(w, "      skipped: %s\n", o.Skipped)
		return
	}
	for _, f := range o.Verdict.Failures {
		who := f.Policy
		if f.Index < 0 {
			who = "configuration"
		}
		fmt.Fprintf(w, "      %s: %s\n", who, f.Message)
	}
	if o.IsBad && !o.Verdict.Denied && len(o.Verdict.Failures) == 0 {
		fmt.Fprintln(w, "      admitted: no validation failed")
	}
	fmt.Fprintf(w, "      audit ID %s\n", e.ID)
}

type jsonOutcome struct {
	AuditID   string    `json:"auditID"`
	Time      time.Time `json:"time"`
	User      string    `json:"user"`
	Verb      string    `json:"verb"`
	Resource  string    `json:"resource"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name"`
	Bad       *string   `json:"bad,omitempty"`
	Skipped   string    `json:"skipped,omitempty"`
	Denied    bool      `json:"denied"`
	Message   string    `json:"message,omitempty"`
	Failures  []string  `json:"failures,omitempty"`
	Warnings  []string  `json:"warnings,omitempty"`
}

func writeJSON(w io.Writer, r *replay.Result) error {
	out := struct {
		Policy   string         `json:"policy"`
		Summary  replay.Summary `json:"summary"`
		Outcomes []jsonOutcome  `json:"outcomes"`
	}{Policy: r.Candidate.Name, Summary: r.Summarize()}
	for _, o := range r.Outcomes {
		e := o.Entry
		j := jsonOutcome{AuditID: e.ID, Time: e.Time.UTC(), User: e.User.GetName(), Verb: e.Verb,
			Resource: e.Resource.GroupResource().String(), Namespace: e.Namespace, Name: e.Name,
			Skipped: o.Skipped, Denied: o.Verdict.Denied, Message: o.Verdict.Message, Warnings: o.Verdict.Warnings}
		if o.IsBad {
			note := o.Bad
			j.Bad = &note
		}
		for _, f := range o.Verdict.Failures {
			j.Failures = append(j.Failures, f.Message)
		}
		out.Outcomes = append(out.Outcomes, j)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func check(args []string, w io.Writer) (int, error) {
	if len(args) == 0 {
		return 0, usageError{"check needs at least one policy file"}
	}
	code := 0
	for _, p := range args {
		c, err := policy.Load(p)
		if err != nil {
			return 0, err
		}
		probs := c.Compile()
		fmt.Fprintf(w, "%s: %d policies, %d bindings", p, len(c.Policies), len(c.Bindings))
		if len(probs) == 0 {
			fmt.Fprintln(w, ", every expression compiles")
		} else {
			fmt.Fprintf(w, ", %d expressions do not compile\n", len(probs))
			code = 1
		}
		for _, pr := range probs {
			fmt.Fprintf(w, "  %s\n", pr)
		}
		for _, b := range c.Bindings {
			acts := make([]string, len(b.Spec.ValidationActions))
			for i, a := range b.Spec.ValidationActions {
				acts[i] = string(a)
			}
			fmt.Fprintf(w, "  binding %s -> policy %s (%s)\n", b.Name, b.Spec.PolicyName, strings.Join(acts, ", "))
		}
		for _, n := range c.Notes {
			fmt.Fprintf(w, "  note: %s\n", n)
		}
	}
	return code, nil
}
