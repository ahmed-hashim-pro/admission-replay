package policy

import (
	"strings"
	"testing"
)

const vap = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: max-replicas
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  validations:
    - expression: object.spec.replicas <= 5
`

func binding(actions string) string {
	return `---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: max-replicas
spec:
  policyName: max-replicas
  validationActions: ` + actions + "\n"
}

func TestParse(t *testing.T) {
	c, err := Parse([]byte("# comment only\n---\n" + vap + binding("[Deny]")))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Policies) != 1 || len(c.Bindings) != 1 || len(c.Notes) != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestParseRejects(t *testing.T) {
	for _, tc := range []struct{ name, doc, want string }{
		{"misspelt field", strings.Replace(vap, "validations:", "validation:", 1), `unknown field "spec.validation"`},
		{"unknown policy", vap + strings.Replace(binding("[Deny]"), "policyName: max-replicas", "policyName: nope", 1), `policyName "nope" is not a policy in this file`},
		{"deny and warn", vap + binding("[Deny, Warn]"), "Deny and Warn may not be used together"},
		{"no actions", vap + binding("[]"), "validationActions is required"},
		{"bad action", vap + binding("[Block]"), `unknown validationAction "Block"`},
		{"other kind", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n", "is not a ValidatingAdmissionPolicy"},
		{"no rules", strings.Replace(vap, "  matchConstraints:\n", "  matchConstraintz:\n", 1), "unknown field"},
		{"empty", "# nothing\n", "no ValidatingAdmissionPolicy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestErrorNamesTheDocumentLine(t *testing.T) {
	_, err := Parse([]byte(vap + "---\napiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicyBinding\nmetadata:\n  name: b\nspec:\n  policyNam: max-replicas\n"))
	if err == nil || !strings.Contains(err.Error(), "line 15") {
		t.Fatalf("got %v", err)
	}
}

func TestUnboundPolicyIsANote(t *testing.T) {
	c, err := Parse([]byte(vap))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Notes) != 1 || !strings.Contains(c.Notes[0], "has no binding") {
		t.Fatalf("%v", c.Notes)
	}
}

func TestCompile(t *testing.T) {
	doc := strings.Replace(vap, "    - expression: object.spec.replicas <= 5\n",
		"    - expression: object.spec.replicas <= 5\n"+
			"    - expression: object.spec.replicas <=\n"+
			"    - expression: variables.nope > 1\n"+
			"      messageExpression: \"'x' + 1\"\n", 1) + binding("[Deny]")
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	probs := c.Compile()
	fields := []string{}
	for _, p := range probs {
		fields = append(fields, p.Field)
	}
	want := []string{"spec.validations[1].expression", "spec.validations[2].expression", "spec.validations[2].messageExpression"}
	if strings.Join(fields, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v\nwant %v\n%v", fields, want, probs)
	}
}

func TestExamplesCompile(t *testing.T) {
	for _, f := range []string{"strict-baseline", "registry-allowlist", "targeted"} {
		c, err := Load("../examples/policies/" + f + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		if probs := c.Compile(); len(probs) > 0 {
			t.Errorf("%s: %v", f, probs)
		}
	}
}

func TestErrorLineWithLeadingSeparator(t *testing.T) {
	_, err := Parse([]byte("---\n# the binding\napiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicyBinding\nmetadata:\n  name: b\nspec:\n  policyNam: x\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("got %v", err)
	}
}
