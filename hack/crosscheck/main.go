// crosscheck compares admission-replay's verdicts with a real API server's.
//
// hack/crosscheck.sh binds a candidate's policies on a kind cluster with
// every binding's validationActions set to [Audit], so the server admits
// every write (and the cluster's state follows the original history) but
// records, in its own audit log, each write a validation failed. It then
// sends the example log's writes with their original audit IDs. This program
// replays the same log through admission-replay and checks, write by write,
// that both sides agree on whether a validation failed and on its message.
//
//	crosscheck -policy P.yaml -print-audit-only | kubectl apply -f -
//	crosscheck -log examples/audit.log -policy P.yaml -server server-audit.log
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"

	"github.com/ahmed-hashim-pro/admission-replay/history"
	"github.com/ahmed-hashim-pro/admission-replay/policy"
	"github.com/ahmed-hashim-pro/admission-replay/replay"
)

const failureKey = "validation.policy.admission.k8s.io/validation_failure"

func main() {
	logPath := flag.String("log", "", "the audit log that was replayed")
	policyPath := flag.String("policy", "", "candidate policy file")
	serverPath := flag.String("server", "", "audit log the crosscheck cluster wrote")
	printAudit := flag.Bool("print-audit-only", false, "print the candidate with every binding set to [Audit] and exit")
	flag.Parse()
	klog.SetOutput(io.Discard)
	klog.LogToStderr(false)

	c, err := policy.Load(*policyPath)
	check(err)
	if *printAudit {
		printAuditOnly(c)
		return
	}

	log, err := history.ReadFile(*logPath)
	check(err)
	res, err := replay.Run(log, c, replay.Options{})
	check(err)

	server := readServer(*serverPath)
	compared, failedBoth, disagree := 0, 0, 0
	for _, o := range res.Outcomes {
		e := o.Entry
		if strings.HasPrefix(e.User.GetName(), "system:") || e.Verb == "patch" {
			continue // not sent: the cluster's own controllers make their own
		}
		s, ok := server[e.ID]
		if !ok {
			fmt.Printf("MISSING  %s %s %s/%s: no event in the server's log\n", e.ID, e.Verb, e.Namespace, e.Name)
			disagree++
			continue
		}
		compared++
		if o.Skipped != "" {
			fmt.Printf("SKIPPED  %s: %s\n", e.ID, o.Skipped)
			disagree++
			continue
		}
		ours := map[string]bool{}
		for _, f := range o.Verdict.Failures {
			ours[f.Policy+": "+f.Message] = true
		}
		switch {
		case s.code >= 300:
			fmt.Printf("REJECTED %s %s %s/%s: the server rejected it (%d) with every binding in Audit\n", e.ID, e.Verb, e.Namespace, e.Name, s.code)
			disagree++
		case s.failure == "" && len(ours) == 0:
		case s.failure != "" && ours[s.failure]:
			failedBoth++
		default:
			disagree++
			fmt.Printf("DIFFER   %s %s %s %s/%s\n  server: %q\n  replay: %q\n", e.ID, e.Verb, e.Resource.Resource, e.Namespace, e.Name, s.failure, keys(ours))
		}
	}
	fmt.Printf("%s: %d writes compared with the API server, %d failed a validation on both sides, %d disagreements\n",
		c.Name, compared, failedBoth, disagree)
	if disagree > 0 || compared == 0 {
		os.Exit(1)
	}
}

type serverResult struct {
	code    int32
	failure string // "policy: message" of the first failure the server recorded
}

func readServer(path string) map[string]serverResult {
	data, err := os.ReadFile(path)
	check(err)
	out := map[string]serverResult{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var ev auditv1.Event
		check(json.Unmarshal(sc.Bytes(), &ev))
		if ev.Stage != auditv1.StageResponseComplete {
			continue
		}
		r := serverResult{code: 200}
		if ev.ResponseStatus != nil && ev.ResponseStatus.Code != 0 {
			r.code = ev.ResponseStatus.Code
		}
		if v, ok := ev.Annotations[failureKey]; ok {
			var fs []validating.ValidationFailureValue
			check(json.Unmarshal([]byte(v), &fs))
			if len(fs) > 0 {
				r.failure = fs[0].Policy + ": " + fs[0].Message
			}
		}
		// A write retried after a conflict appears once per attempt under
		// the same ID; the one that went through is the one that counts.
		if prev, ok := out[string(ev.AuditID)]; ok && prev.code < 300 {
			continue
		}
		out[string(ev.AuditID)] = r
	}
	check(sc.Err())
	return out
}

func printAuditOnly(c *policy.Candidate) {
	var docs []string
	for _, p := range c.Policies {
		p = p.DeepCopy()
		p.APIVersion, p.Kind = "admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy"
		docs = append(docs, marshal(p))
	}
	for _, b := range c.Bindings {
		b = b.DeepCopy()
		b.APIVersion, b.Kind = "admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBinding"
		b.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit}
		docs = append(docs, marshal(b))
	}
	fmt.Print(strings.Join(docs, "---\n"))
}

func marshal(v any) string {
	b, err := yaml.Marshal(v)
	check(err)
	return string(b)
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
