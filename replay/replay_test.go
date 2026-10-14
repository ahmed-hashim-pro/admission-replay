package replay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ahmed-hashim-pro/admission-replay/history"
	"github.com/ahmed-hashim-pro/admission-replay/policy"
)

type obj = map[string]any

type ev struct {
	verb, resource, ns, name, user string
	code                           int
	body                           obj // request and response object
}

// audit renders events as an audit log, one minute apart.
func audit(t *testing.T, evs ...ev) *history.Log {
	t.Helper()
	var buf bytes.Buffer
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i, e := range evs {
		group, version := "", "v1"
		if e.resource == "deployments" {
			group = "apps"
		}
		code := e.code
		if code == 0 {
			code = 200
		}
		m := obj{
			"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "RequestResponse",
			"auditID": fmt.Sprintf("id-%d", i), "stage": "ResponseComplete", "verb": e.verb,
			"user":                     obj{"username": e.user},
			"objectRef":                obj{"resource": e.resource, "namespace": e.ns, "name": e.name, "apiGroup": group, "apiVersion": version},
			"responseStatus":           obj{"code": code},
			"requestReceivedTimestamp": t0.Add(time.Duration(i) * time.Minute).Format("2006-01-02T15:04:05.000000Z07:00"),
			"stageTimestamp":           t0.Add(time.Duration(i) * time.Minute).Format("2006-01-02T15:04:05.000000Z07:00"),
		}
		if e.body != nil {
			m["requestObject"] = e.body
			if code < 300 {
				m["responseObject"] = e.body
			} else {
				m["responseObject"] = obj{"kind": "Status", "apiVersion": "v1", "code": code}
			}
		}
		b, _ := json.Marshal(m)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	log, err := history.Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return log
}

func deploy(ns, name string, replicas int, image string) obj {
	return obj{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": obj{"name": name, "namespace": ns, "labels": obj{"app": name}},
		"spec": obj{
			"replicas": replicas,
			"selector": obj{"matchLabels": obj{"app": name}},
			"template": obj{
				"metadata": obj{"labels": obj{"app": name}},
				"spec":     obj{"containers": []any{obj{"name": "app", "image": image}}},
			},
		},
	}
}

func namespace(name string, labels obj) obj {
	return obj{"apiVersion": "v1", "kind": "Namespace", "metadata": obj{"name": name, "labels": labels}}
}

func candidate(t *testing.T, resources, ops, expr, binding string) *policy.Candidate {
	t.Helper()
	doc := fmt.Sprintf(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: p
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ["", "apps"]
        apiVersions: ["v1"]
        operations: %s
        resources: %s
  validations:
    - expression: %q
      message: nope
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: b
spec:
  policyName: p
%s`, ops, resources, expr, binding)
	c, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "p"
	return c
}

func run(t *testing.T, log *history.Log, c *policy.Candidate, opts Options) *Result {
	t.Helper()
	r, err := Run(log, c, opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func verdicts(r *Result) string {
	var s []string
	for _, o := range r.Outcomes {
		switch {
		case o.Skipped != "":
			s = append(s, "skip")
		case o.Verdict.Denied:
			s = append(s, "deny")
		case o.Flagged():
			s = append(s, "warn")
		default:
			s = append(s, "ok")
		}
	}
	return strings.Join(s, " ")
}

func TestUpdatesSeeTheOldObject(t *testing.T) {
	// Never cut replicas by more than half in one step.
	c := candidate(t, `["deployments"]`, `["CREATE", "UPDATE"]`,
		"oldObject == null || object.spec.replicas * 2 >= oldObject.spec.replicas", "  validationActions: [Deny]\n")
	log := audit(t,
		ev{verb: "create", resource: "deployments", ns: "shop", name: "web", user: "ci", body: deploy("shop", "web", 8, "x:1")},
		ev{verb: "update", resource: "deployments", ns: "shop", name: "web", user: "ci", body: deploy("shop", "web", 4, "x:1")},
		ev{verb: "update", resource: "deployments", ns: "shop", name: "web", user: "ci", body: deploy("shop", "web", 1, "x:1")},
	)
	if got := verdicts(run(t, log, c, Options{})); got != "ok ok deny" {
		t.Fatal(got)
	}
}

func TestDeletesNeedState(t *testing.T) {
	c := candidate(t, `["configmaps"]`, `["DELETE"]`, "oldObject.metadata.name != 'keep'", "  validationActions: [Deny]\n")
	cm := obj{"apiVersion": "v1", "kind": "ConfigMap", "metadata": obj{"name": "keep", "namespace": "shop"}}
	log := audit(t,
		ev{verb: "delete", resource: "configmaps", ns: "shop", name: "keep", user: "bob"},
	)
	r := run(t, log, c, Options{})
	if got := verdicts(r); got != "skip" || !strings.Contains(r.Outcomes[0].Skipped, "--initial") {
		t.Fatalf("%s: %q", got, r.Outcomes[0].Skipped)
	}
	r = run(t, log, c, Options{Initial: []*unstructured.Unstructured{{Object: cm}}})
	if got := verdicts(r); got != "deny" {
		t.Fatal(got)
	}
}

func TestFailedWritesDoNotChangeState(t *testing.T) {
	c := candidate(t, `["deployments"]`, `["CREATE", "UPDATE"]`, "object.spec.replicas < 10", "  validationActions: [Deny]\n")
	log := audit(t,
		ev{verb: "create", resource: "deployments", ns: "shop", name: "web", user: "ci", code: 409, body: deploy("shop", "web", 20, "x:1")},
		ev{verb: "update", resource: "deployments", ns: "shop", name: "web", user: "ci", body: deploy("shop", "web", 2, "x:1")},
	)
	r := run(t, log, c, Options{})
	// The failed create is still judged (it was a write someone attempted)
	// but never stored, so the update has no old object.
	if got := verdicts(r); got != "deny skip" {
		t.Fatal(got)
	}
	if s := r.Summarize(); s.FailedBefore != 1 || s.Blocked != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestNamespaceLabelsFollowTheLog(t *testing.T) {
	c := candidate(t, `["deployments"]`, `["CREATE", "UPDATE"]`, "object.spec.replicas < 10",
		"  validationActions: [Deny]\n  matchResources:\n    namespaceSelector:\n      matchLabels:\n        env: prod\n")
	log := audit(t,
		ev{verb: "create", resource: "namespaces", name: "shop", user: "dana", body: namespace("shop", obj{"env": "staging"})},
		ev{verb: "create", resource: "deployments", ns: "shop", name: "web", user: "ci", body: deploy("shop", "web", 20, "x:1")},
		ev{verb: "update", resource: "namespaces", name: "shop", user: "dana", body: namespace("shop", obj{"env": "prod"})},
		ev{verb: "update", resource: "deployments", ns: "shop", name: "web", user: "ci", body: deploy("shop", "web", 20, "x:2")},
	)
	if got := verdicts(run(t, log, c, Options{})); got != "ok ok ok deny" {
		t.Fatal(got)
	}
}

func TestUnknownNamespaceIsAssumed(t *testing.T) {
	c := candidate(t, `["deployments"]`, `["CREATE"]`, "object.spec.replicas < 10", "  validationActions: [Deny]\n")
	r := run(t, audit(t, ev{verb: "create", resource: "deployments", ns: "legacy", name: "web", user: "ci", body: deploy("legacy", "web", 20, "x:1")}), c, Options{})
	if got := verdicts(r); got != "deny" || len(r.AssumedNamespaces) != 1 {
		t.Fatalf("%s %v", got, r.AssumedNamespaces)
	}
}

func TestTerminatingNamespaceStaysKnown(t *testing.T) {
	c := candidate(t, `["deployments"]`, `["CREATE"]`, "true", "  validationActions: [Deny]\n")
	gone := namespace("tmp", obj{"team": "x"})
	gone["metadata"].(obj)["deletionTimestamp"] = "2026-09-01T00:01:00Z"
	log := audit(t,
		ev{verb: "create", resource: "namespaces", name: "tmp", user: "dana", body: namespace("tmp", obj{"team": "x"})},
		ev{verb: "delete", resource: "namespaces", ns: "tmp", name: "tmp", user: "dana", body: gone},
		ev{verb: "create", resource: "deployments", ns: "tmp", name: "late", user: "ci", code: 403, body: deploy("tmp", "late", 1, "x:1")},
	)
	r := run(t, log, c, Options{})
	if len(r.AssumedNamespaces) != 0 || verdicts(r) != "ok ok ok" {
		t.Fatalf("%v %s", r.AssumedNamespaces, verdicts(r))
	}
}

func TestSummary(t *testing.T) {
	c := candidate(t, `["deployments"]`, `["CREATE", "UPDATE"]`, "object.spec.replicas < 10", "  validationActions: [Warn]\n")
	strict := candidate(t, `["deployments"]`, `["CREATE", "UPDATE"]`, "object.spec.replicas < 10", "  validationActions: [Deny]\n")
	log := audit(t,
		ev{verb: "create", resource: "deployments", ns: "shop", name: "a", user: "ci", body: deploy("shop", "a", 20, "x:1")},
		ev{verb: "create", resource: "deployments", ns: "shop", name: "b", user: "system:serviceaccount:kube-system:x", body: deploy("shop", "b", 20, "x:1")},
		ev{verb: "create", resource: "deployments", ns: "shop", name: "c", user: "mallory", body: deploy("shop", "c", 50, "x:1")},
		ev{verb: "create", resource: "deployments", ns: "shop", name: "d", user: "mallory", body: deploy("shop", "d", 1, "evil:1")},
	)
	bad := map[string]string{"id-2": "too big", "id-3": "evil image"}
	s := run(t, log, c, Options{Bad: bad}).Summarize()
	want := Summary{Replayed: 4, Flagged: 2, Bad: 2, BadWarned: 1, Missed: 1}
	if s != want {
		t.Fatalf("warn:\n got %+v\nwant %+v", s, want)
	}
	r := run(t, log, strict, Options{Bad: bad})
	s = r.Summarize()
	want = Summary{Replayed: 4, Blocked: 2, BlockedBySys: 1, Bad: 2, Caught: 1, Missed: 1}
	if s != want {
		t.Fatalf("deny:\n got %+v\nwant %+v", s, want)
	}
	if u := r.BlockedUsers(); len(u) != 2 {
		t.Fatalf("%v", u)
	}
	if rs := r.BlockReasons(); len(rs) != 1 || rs[0].N != 2 || rs[0].Label != "nope" {
		t.Fatalf("%v", rs)
	}
}
