// Package policy loads candidate policies: YAML files holding
// ValidatingAdmissionPolicies and their bindings.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"
)

// Candidate is one file's policies and bindings, replayed together, as they
// would be if that file were applied to the cluster.
type Candidate struct {
	Name     string
	Path     string
	Policies []*admissionregistrationv1.ValidatingAdmissionPolicy
	Bindings []*admissionregistrationv1.ValidatingAdmissionPolicyBinding
	Notes    []string // things that are legal but probably not intended
}

var strict = json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme.Scheme, scheme.Scheme,
	json.SerializerOptions{Yaml: true, Strict: true})

// Load reads a YAML (or JSON) file of one or more documents.
func Load(path string) (*Candidate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	c.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return c, nil
}

// Parse decodes the documents strictly: an unknown or misspelt field is an
// error, as it is for kubectl apply --validate=strict.
func Parse(data []byte) (*Candidate, error) {
	c := &Candidate{}
	for _, d := range splitDocs(data) {
		raw, start := d.raw, d.line
		// Point at the document's first line of content, not a comment.
		for _, l := range bytes.Split(raw, []byte("\n")) {
			if t := bytes.TrimSpace(l); len(t) > 0 && t[0] != '#' {
				break
			}
			start++
		}
		if len(bytes.TrimSpace(stripComments(raw))) == 0 {
			continue
		}
		obj, gvk, err := strict.Decode(raw, nil, nil)
		if err != nil && !runtime.IsStrictDecodingError(err) {
			return nil, fmt.Errorf("document at line %d: %w", start, err)
		}
		if err != nil {
			return nil, fmt.Errorf("document at line %d (%s): %w", start, gvk.Kind, err)
		}
		switch o := obj.(type) {
		case *admissionregistrationv1.ValidatingAdmissionPolicy:
			c.Policies = append(c.Policies, o)
		case *admissionregistrationv1.ValidatingAdmissionPolicyBinding:
			c.Bindings = append(c.Bindings, o)
		default:
			return nil, fmt.Errorf("document at line %d: %s is not a ValidatingAdmissionPolicy or ValidatingAdmissionPolicyBinding (admissionregistration.k8s.io/v1)", start, gvk)
		}
	}
	return c, c.validate()
}

type document struct {
	raw  []byte
	line int // first line of the document in the file
}

// splitDocs splits a YAML stream on --- separator lines, keeping each
// document's starting line for error messages.
func splitDocs(data []byte) []document {
	var docs []document
	cur := document{line: 1}
	for i, l := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(l, []byte("---")) && len(bytes.TrimSpace(l[3:])) == 0 {
			docs = append(docs, cur)
			cur = document{line: i + 2}
			continue
		}
		cur.raw = append(cur.raw, l...)
		cur.raw = append(cur.raw, '\n')
	}
	return append(docs, cur)
}

func stripComments(b []byte) []byte {
	var out []byte
	for _, l := range bytes.Split(b, []byte("\n")) {
		if t := bytes.TrimSpace(l); len(t) > 0 && t[0] != '#' {
			out = append(out, l...)
			out = append(out, '\n')
		}
	}
	return out
}

// validate applies the API server's checks that matter for replay, so a file
// the cluster would reject is not silently replayed.
func (c *Candidate) validate() error {
	if len(c.Policies) == 0 {
		return errors.New("no ValidatingAdmissionPolicy in the file")
	}
	names := map[string]bool{}
	for _, p := range c.Policies {
		if p.Name == "" {
			return errors.New("a ValidatingAdmissionPolicy has no metadata.name")
		}
		if names[p.Name] {
			return fmt.Errorf("policy %s is defined twice", p.Name)
		}
		names[p.Name] = true
		if p.Spec.MatchConstraints == nil || len(p.Spec.MatchConstraints.ResourceRules) == 0 {
			return fmt.Errorf("policy %s: spec.matchConstraints.resourceRules is required", p.Name)
		}
		if len(p.Spec.Validations) == 0 && len(p.Spec.AuditAnnotations) == 0 {
			return fmt.Errorf("policy %s: needs at least one of spec.validations or spec.auditAnnotations", p.Name)
		}
		if p.Spec.ParamKind != nil {
			return fmt.Errorf("policy %s: paramKind is not supported yet", p.Name)
		}
	}
	bound := map[string]bool{}
	bnames := map[string]bool{}
	for _, b := range c.Bindings {
		if b.Name == "" {
			return errors.New("a ValidatingAdmissionPolicyBinding has no metadata.name")
		}
		if bnames[b.Name] {
			return fmt.Errorf("binding %s is defined twice", b.Name)
		}
		bnames[b.Name] = true
		if !names[b.Spec.PolicyName] {
			return fmt.Errorf("binding %s: policyName %q is not a policy in this file", b.Name, b.Spec.PolicyName)
		}
		if len(b.Spec.ValidationActions) == 0 {
			return fmt.Errorf("binding %s: spec.validationActions is required", b.Name)
		}
		seen := map[admissionregistrationv1.ValidationAction]bool{}
		for _, a := range b.Spec.ValidationActions {
			switch a {
			case admissionregistrationv1.Deny, admissionregistrationv1.Warn, admissionregistrationv1.Audit:
			default:
				return fmt.Errorf("binding %s: unknown validationAction %q (Deny, Warn or Audit)", b.Name, a)
			}
			if seen[a] {
				return fmt.Errorf("binding %s: validationAction %s listed twice", b.Name, a)
			}
			seen[a] = true
		}
		if seen[admissionregistrationv1.Deny] && seen[admissionregistrationv1.Warn] {
			return fmt.Errorf("binding %s: Deny and Warn may not be used together", b.Name)
		}
		if b.Spec.ParamRef != nil {
			return fmt.Errorf("binding %s: paramRef is not supported yet", b.Name)
		}
		bound[b.Spec.PolicyName] = true
	}
	for _, p := range c.Policies {
		if !bound[p.Name] {
			c.Notes = append(c.Notes, fmt.Sprintf("policy %s has no binding, so it never runs", p.Name))
		}
	}
	return nil
}
