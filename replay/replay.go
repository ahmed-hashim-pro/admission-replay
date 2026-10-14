// Package replay feeds an audit log's writes, in order, through a candidate
// policy and scores the result against the changes you labelled bad.
package replay

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/ahmed-hashim-pro/admission-replay/engine"
	"github.com/ahmed-hashim-pro/admission-replay/history"
	"github.com/ahmed-hashim-pro/admission-replay/policy"
)

// Outcome is what the candidate would have done with one write.
type Outcome struct {
	Entry   *history.Entry
	Verdict engine.Verdict
	Bad     string // the label's note, if the write is labelled bad
	IsBad   bool
	Skipped string // why the write could not be replayed, if it was not
}

// Blocked: the candidate would have denied a write that went through.
func (o *Outcome) Blocked() bool { return o.Skipped == "" && o.Verdict.Denied }

// Flagged: not denied, but warned or audited.
func (o *Outcome) Flagged() bool {
	return o.Skipped == "" && !o.Verdict.Denied && (len(o.Verdict.Warnings) > 0 || len(o.Verdict.Audit) > 0)
}

// Result is a candidate's replay.
type Result struct {
	Candidate *policy.Candidate
	Outcomes  []Outcome
	// AssumedNamespaces were written to but never created in the log or the
	// initial state; they were replayed with only the label the API server
	// puts on every namespace.
	AssumedNamespaces []string
}

// Options configure a replay.
type Options struct {
	// Bad maps audit IDs to a note: the writes that should have been stopped.
	Bad map[string]string
	// Initial is the cluster's state when the log starts, so updates and
	// deletes of objects created before it have an oldObject.
	Initial []*unstructured.Unstructured
}

type key struct{ group, resource, namespace, name string }

func keyOf(gvr schema.GroupVersionResource, ns, name string) key {
	return key{gvr.Group, gvr.Resource, ns, name}
}

// Run replays the log through one candidate.
func Run(log *history.Log, c *policy.Candidate, opts Options) (*Result, error) {
	state := map[key]*unstructured.Unstructured{}
	var namespaces []*corev1.Namespace
	for _, u := range opts.Initial {
		gvk := u.GroupVersionKind()
		gvr, err := resourceFor(gvk)
		if err != nil {
			return nil, fmt.Errorf("initial state: %s %s: %w", gvk.Kind, u.GetName(), err)
		}
		state[keyOf(gvr, u.GetNamespace(), u.GetName())] = u
		if gvk.Kind == "Namespace" && gvk.Group == "" {
			ns := &corev1.Namespace{}
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, ns); err != nil {
				return nil, err
			}
			namespaces = append(namespaces, ns)
		}
	}
	eng, err := engine.New(c.Policies, c.Bindings, namespaces)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Name, err)
	}
	defer eng.Close()

	res := &Result{Candidate: c}
	known := map[string]bool{}
	for _, ns := range namespaces {
		known[ns.Name] = true
	}
	for _, e := range log.Entries {
		if e.Namespace != "" && !known[e.Namespace] && !(e.Resource.Group == "" && e.Resource.Resource == "namespaces") {
			known[e.Namespace] = true
			res.AssumedNamespaces = append(res.AssumedNamespaces, e.Namespace)
			ns := &corev1.Namespace{}
			ns.Name = e.Namespace
			ns.Labels = map[string]string{"kubernetes.io/metadata.name": e.Namespace}
			if err := eng.SetNamespace(ns); err != nil {
				return nil, err
			}
		}
		o := Outcome{Entry: e}
		o.Bad, o.IsBad = opts.Bad[e.ID]
		name := e.Name
		if name == "" && history.IsObject(e.Response) {
			name = e.Response.GetName() // generateName
		}
		k := keyOf(e.Resource, e.Namespace, name)
		isNamespace := e.Resource.Group == "" && e.Resource.Resource == "namespaces"
		if isNamespace {
			// The API server puts a namespace's own name in objectRef.namespace
			// for some verbs on it and not others.
			k.namespace = ""
		}
		old := state[k]
		req, skip := request(e, name, old)
		if skip != "" {
			o.Skipped = skip
		} else {
			v, err := eng.Evaluate(req)
			if err != nil {
				return nil, fmt.Errorf("%s: audit event %s (line %d): %w", c.Name, e.ID, e.Line, err)
			}
			o.Verdict = v
		}
		res.Outcomes = append(res.Outcomes, o)

		// Advance the state as the cluster did, whatever the candidate thought.
		if e.Failed() {
			continue
		}
		var now *unstructured.Unstructured
		switch e.Verb {
		case "delete":
			// An object with finalizers (a namespace, say) stays, marked for
			// deletion, until they finish; the delete returns it.
			if history.IsObject(e.Response) && e.Response.GetDeletionTimestamp() != nil {
				now = e.Response
				state[k] = now
			} else {
				delete(state, k)
			}
		default:
			now = stored(e)
			if now != nil {
				state[k] = now
			}
		}
		if isNamespace {
			if now == nil {
				err = eng.DeleteNamespace(name)
			} else if now != nil {
				ns := &corev1.Namespace{}
				if err = runtime.DefaultUnstructuredConverter.FromUnstructured(now.Object, ns); err == nil {
					err = eng.SetNamespace(ns)
				}
			}
			if err != nil {
				return nil, fmt.Errorf("namespace %s: %w", name, err)
			}
			known[name] = now != nil
		}
	}
	return res, nil
}

// stored is the object as the cluster stored it after the write.
func stored(e *history.Entry) *unstructured.Unstructured {
	if history.IsObject(e.Response) {
		return e.Response
	}
	if e.Verb != "patch" && history.IsObject(e.Request) {
		return e.Request
	}
	return nil
}

// request rebuilds the admission request an audit event records.
func request(e *history.Entry, name string, old *unstructured.Unstructured) (engine.Request, string) {
	r := engine.Request{
		Resource: e.Resource, Namespace: e.Namespace, Name: name, User: e.User,
	}
	var obj *unstructured.Unstructured
	switch e.Verb {
	case "create":
		r.Operation = admission.Create
		obj = stored(e)
		if e.Failed() && history.IsObject(e.Request) {
			obj = e.Request
		}
		if obj == nil {
			return r, "no object body (log at RequestResponse level)"
		}
		obj = obj.DeepCopy()
		obj.SetResourceVersion("")
	case "update", "patch":
		r.Operation = admission.Update
		if old == nil {
			return r, "object existed before the log starts (pass --initial)"
		}
		if e.Failed() {
			if e.Verb == "patch" || !history.IsObject(e.Request) {
				return r, "failed patch: the log does not hold the object it would have produced"
			}
			obj = e.Request.DeepCopy()
		} else {
			obj = stored(e)
			if obj == nil {
				return r, "no object body (log at RequestResponse level)"
			}
			obj = obj.DeepCopy()
		}
		obj.SetResourceVersion(old.GetResourceVersion())
	case "delete":
		r.Operation = admission.Delete
		if old == nil {
			return r, "object existed before the log starts (pass --initial)"
		}
	}

	src := obj
	if src == nil {
		src = old
	}
	r.Kind = src.GroupVersionKind()
	if r.Resource.Version == "" {
		r.Resource.Version = r.Kind.Version
	}
	var err error
	if obj != nil {
		if r.Object, err = typed(obj); err != nil {
			return r, "object does not decode: " + err.Error()
		}
	}
	if old != nil && e.Verb != "create" {
		if r.OldObject, err = typed(old); err != nil {
			return r, "old object does not decode: " + err.Error()
		}
	}
	return r, ""
}

// typed converts built-in kinds to their Go types, as the API server holds
// them when admission runs; other kinds (custom resources) stay unstructured,
// as they are in the API server too.
func typed(u *unstructured.Unstructured) (runtime.Object, error) {
	gvk := u.GroupVersionKind()
	obj, err := scheme.Scheme.New(gvk)
	if err != nil {
		return u.DeepCopy(), nil
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, obj); err != nil {
		return nil, err
	}
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	return obj, nil
}

// resourceFor maps a built-in kind to its resource, for --initial objects,
// which carry a kind but no objectRef.
func resourceFor(gvk schema.GroupVersionKind) (schema.GroupVersionResource, error) {
	if !scheme.Scheme.Recognizes(gvk) {
		return schema.GroupVersionResource{}, fmt.Errorf("unknown kind %s; only built-in kinds are supported in --initial", gvk)
	}
	plural := strings.ToLower(gvk.Kind)
	switch {
	case plural == "endpoints":
	case strings.HasSuffix(plural, "s"):
		plural += "es"
	case strings.HasSuffix(plural, "y"):
		plural = strings.TrimSuffix(plural, "y") + "ies"
	default:
		plural += "s"
	}
	return gvk.GroupVersion().WithResource(plural), nil
}
