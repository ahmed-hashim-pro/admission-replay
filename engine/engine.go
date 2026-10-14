// Package engine evaluates ValidatingAdmissionPolicies offline by running the
// kube-apiserver's own ValidatingAdmissionPolicy admission plugin
// (k8s.io/apiserver) against an in-memory fake API, one request at a time.
//
// The plugin is not reimplemented: matching (matchConstraints, namespace and
// object selectors, matchConditions), variables, validations,
// messageExpression, failurePolicy and the CEL environment and cost limits
// are all the apiserver's code at the version pinned in go.mod.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/warning"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

// Request is one write as admission sees it.
type Request struct {
	Operation   admission.Operation
	Resource    schema.GroupVersionResource
	Subresource string
	Kind        schema.GroupVersionKind
	Namespace   string
	Name        string
	Object      runtime.Object // nil for DELETE
	OldObject   runtime.Object // nil for CREATE
	User        user.Info
	DryRun      bool
}

// Failure is one validation that failed, attributed to its policy and binding.
type Failure struct {
	Policy  string
	Binding string
	Index   int // index into spec.validations; -1 for a configuration error
	Message string
	Actions []admissionregistrationv1.ValidationAction
}

// Verdict is what the policies would have done with a request.
type Verdict struct {
	// Denied: the request would have been rejected. Message is the error the
	// API server would have returned (the first denying failure).
	Denied  bool
	Message string
	// Failures lists every failed validation, whatever its binding's actions.
	// The API server reports only the first; all of them are useful here.
	Failures []Failure
	Warnings []string
	// Audit lists failures whose bindings include the Audit action.
	Audit []Failure
}

// Engine holds one set of policies and bindings (a candidate) and the
// namespaces it has seen.
type Engine struct {
	plugin  *validating.Plugin
	client  *fake.Clientset
	factory informers.SharedInformerFactory
	stop    chan struct{}
	actions map[string][]admissionregistrationv1.ValidationAction // binding -> original actions
}

const failureKey = "validation.policy.admission.k8s.io/validation_failure"

// The plugin compiles every policy against one CEL composition template
// shared by the whole process, as the API server does. The API server runs
// one plugin, so compiles never overlap; here each engine runs its own, so
// starting engines is serialized.
var compiling sync.Mutex

// New starts an engine for the given policies and bindings. Every binding is
// loaded with its validationActions replaced by [Audit], so the plugin
// reports every failed validation instead of stopping at the first Deny; the
// original actions are applied afterwards in Evaluate.
func New(policies []*admissionregistrationv1.ValidatingAdmissionPolicy, bindings []*admissionregistrationv1.ValidatingAdmissionPolicyBinding, namespaces []*corev1.Namespace) (*Engine, error) {
	for _, p := range policies {
		if p.Spec.ParamKind != nil {
			return nil, fmt.Errorf("policy %s: paramKind is not supported yet", p.Name)
		}
	}
	compiling.Lock()
	defer compiling.Unlock()
	e := &Engine{actions: map[string][]admissionregistrationv1.ValidationAction{}}
	var objs []runtime.Object
	for _, p := range policies {
		p = p.DeepCopy()
		defaultPolicy(p)
		objs = append(objs, p)
	}
	for _, b := range bindings {
		e.actions[b.Name] = b.Spec.ValidationActions
		b = b.DeepCopy()
		b.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit}
		defaultBinding(b)
		objs = append(objs, b)
	}
	for _, ns := range namespaces {
		objs = append(objs, ns.DeepCopy())
	}
	e.client = fake.NewSimpleClientset(objs...)
	e.factory = informers.NewSharedInformerFactory(e.client, 0)
	e.stop = make(chan struct{})

	p := validating.NewPlugin(nil)
	p.SetExternalKubeInformerFactory(e.factory)
	p.SetExternalKubeClientSet(e.client)
	p.SetDynamicClient(dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()))
	p.SetRESTMapper(restMapper())
	p.SetAuthorizer(allowAll{})
	p.SetDrainedNotification(e.stop)
	if err := p.ValidateInitialization(); err != nil {
		return nil, err
	}
	e.factory.Start(e.stop)
	e.factory.WaitForCacheSync(e.stop)
	if !p.WaitForReady() {
		return nil, errors.New("admission plugin did not become ready")
	}
	// Ready means the policy source has compiled the policies it was started
	// with, so every binding is live before the first request.
	e.plugin = p
	return e, nil
}

// Close stops the engine's informers.
func (e *Engine) Close() { close(e.stop) }

// SetNamespace creates or updates a namespace in the engine's view, and waits
// until the plugin's namespace lister sees it, so the next request is matched
// against the namespace as it was at that point in the history.
func (e *Engine) SetNamespace(ns *corev1.Namespace) error {
	ctx := context.Background()
	ns = ns.DeepCopy()
	ns.ResourceVersion = ""
	cur, err := e.client.CoreV1().Namespaces().Get(ctx, ns.Name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		_, err = e.client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	case err == nil:
		ns.ResourceVersion = cur.ResourceVersion
		_, err = e.client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	}
	if err != nil {
		return err
	}
	// Wait for what policies can read: labels (selectors) and annotations
	// (namespaceObject in CEL).
	lister := e.factory.Core().V1().Namespaces().Lister()
	return wait.PollUntilContextTimeout(ctx, time.Millisecond, 10*time.Second, true, func(context.Context) (bool, error) {
		got, err := lister.Get(ns.Name)
		if err != nil {
			return false, nil
		}
		return sameMap(got.Labels, ns.Labels) && sameMap(got.Annotations, ns.Annotations), nil
	})
}

// DeleteNamespace removes a namespace from the engine's view.
func (e *Engine) DeleteNamespace(name string) error {
	ctx := context.Background()
	err := e.client.CoreV1().Namespaces().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	lister := e.factory.Core().V1().Namespaces().Lister()
	return wait.PollUntilContextTimeout(ctx, time.Millisecond, 10*time.Second, true, func(context.Context) (bool, error) {
		_, err := lister.Get(name)
		return apierrors.IsNotFound(err), nil
	})
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Evaluate runs one request through the plugin.
func (e *Engine) Evaluate(r Request) (Verdict, error) {
	attrs := &collectingAttributes{Attributes: admission.NewAttributesRecord(
		r.Object, r.OldObject, r.Kind, r.Namespace, r.Name, r.Resource, r.Subresource,
		r.Operation, operationOptions(r.Operation), r.DryRun, r.User)}
	rec := &warnings{}
	ctx := warning.WithWarningRecorder(context.Background(), rec)
	err := e.plugin.Validate(ctx, attrs, objectInterfaces)

	var v Verdict
	for _, raw := range attrs.failures {
		var vals []validating.ValidationFailureValue
		if jerr := json.Unmarshal([]byte(raw), &vals); jerr != nil {
			return v, fmt.Errorf("decoding validation failure: %w", jerr)
		}
		for _, f := range vals {
			v.Failures = append(v.Failures, Failure{
				Policy: f.Policy, Binding: f.Binding, Index: f.ExpressionIndex,
				Message: f.Message, Actions: e.actions[f.Binding],
			})
		}
	}
	if err != nil {
		// With every binding in Audit, the plugin only returns an error for a
		// configuration error under failurePolicy Fail (or an internal one).
		var se *apierrors.StatusError
		if !errors.As(err, &se) {
			return v, err
		}
		v.Denied = true
		v.Message = se.ErrStatus.Message
		v.Failures = append(v.Failures, Failure{Index: -1, Message: se.ErrStatus.Message})
	}
	for _, f := range v.Failures {
		for _, a := range f.Actions {
			switch a {
			case admissionregistrationv1.Deny:
				if !v.Denied {
					v.Denied = true
					v.Message = denyMessage(r, f)
				}
			case admissionregistrationv1.Warn:
				v.Warnings = append(v.Warnings, fmt.Sprintf("Validation failed for ValidatingAdmissionPolicy '%s' with binding '%s': %s", f.Policy, f.Binding, f.Message))
			case admissionregistrationv1.Audit:
				v.Audit = append(v.Audit, f)
			}
		}
	}
	v.Warnings = append(v.Warnings, rec.list...)
	return v, nil
}

// denyMessage reproduces the API server's Forbidden message for a denial.
func denyMessage(r Request, f Failure) string {
	msg := fmt.Sprintf("ValidatingAdmissionPolicy '%s' with binding '%s' denied request: %s", f.Policy, f.Binding, f.Message)
	attrs := admission.NewAttributesRecord(r.Object, r.OldObject, r.Kind, r.Namespace, r.Name, r.Resource, r.Subresource, r.Operation, nil, false, r.User)
	return admission.NewForbidden(attrs, errors.New(msg)).Error()
}

func operationOptions(op admission.Operation) runtime.Object {
	switch op {
	case admission.Create:
		return &metav1.CreateOptions{}
	case admission.Update:
		return &metav1.UpdateOptions{}
	case admission.Delete:
		return &metav1.DeleteOptions{}
	}
	return nil
}

// collectingAttributes keeps every validation-failure annotation. The
// apiserver's record refuses a second value for the same key, so in a real
// audit log only the first failure of a request appears.
type collectingAttributes struct {
	admission.Attributes
	mu       sync.Mutex
	failures []string
}

func (c *collectingAttributes) AddAnnotation(key, value string) error {
	if key == failureKey {
		c.mu.Lock()
		c.failures = append(c.failures, value)
		c.mu.Unlock()
		return nil
	}
	return c.Attributes.AddAnnotation(key, value)
}

type warnings struct{ list []string }

func (w *warnings) AddWarning(_, text string) { w.list = append(w.list, text) }

// allowAll answers every authorizer check in CEL with "allowed", as the
// apiserver would for a cluster-admin.
type allowAll struct{}

func (allowAll) Authorize(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
	return authorizer.DecisionAllow, "", nil
}

var objectInterfaces = admission.NewObjectInterfacesFromScheme(scheme.Scheme)

// restMapper knows every built-in kind in client-go's scheme. The plugin only
// uses it to resolve paramKind, which is not supported yet.
func restMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper(nil)
	gvks := make([]schema.GroupVersionKind, 0)
	for gvk := range scheme.Scheme.AllKnownTypes() {
		if strings.HasSuffix(gvk.Kind, "List") || strings.HasSuffix(gvk.Kind, "Options") || gvk.Version == runtime.APIVersionInternal {
			continue
		}
		gvks = append(gvks, gvk)
	}
	sort.Slice(gvks, func(i, j int) bool { return gvks[i].String() < gvks[j].String() })
	for _, gvk := range gvks {
		m.Add(gvk, meta.RESTScopeNamespace)
	}
	return m
}

// defaultPolicy and defaultBinding apply the API server's defaults for the
// fields the plugin reads, since these objects never pass through the API.
func defaultPolicy(p *admissionregistrationv1.ValidatingAdmissionPolicy) {
	if p.Spec.FailurePolicy == nil {
		f := admissionregistrationv1.Fail
		p.Spec.FailurePolicy = &f
	}
	if p.Spec.MatchConstraints != nil {
		defaultMatch(p.Spec.MatchConstraints)
	}
}

func defaultBinding(b *admissionregistrationv1.ValidatingAdmissionPolicyBinding) {
	if b.Spec.MatchResources != nil {
		defaultMatch(b.Spec.MatchResources)
	}
}

func defaultMatch(m *admissionregistrationv1.MatchResources) {
	if m.NamespaceSelector == nil {
		m.NamespaceSelector = &metav1.LabelSelector{}
	}
	if m.ObjectSelector == nil {
		m.ObjectSelector = &metav1.LabelSelector{}
	}
	if m.MatchPolicy == nil {
		mp := admissionregistrationv1.Equivalent
		m.MatchPolicy = &mp
	}
	for _, rules := range [][]admissionregistrationv1.NamedRuleWithOperations{m.ResourceRules, m.ExcludeResourceRules} {
		for i := range rules {
			if rules[i].Scope == nil {
				s := admissionregistrationv1.AllScopes
				rules[i].Scope = &s
			}
		}
	}
}
