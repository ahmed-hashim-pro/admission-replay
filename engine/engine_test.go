package engine

import (
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

var (
	deployGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	deployGVK = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
)

func policy(name string, matchConditions []admissionregistrationv1.MatchCondition, validations ...admissionregistrationv1.Validation) *admissionregistrationv1.ValidatingAdmissionPolicy {
	return &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{"CREATE", "UPDATE"},
						Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
					},
				}},
			},
			MatchConditions: matchConditions,
			Validations:     validations,
		},
	}
}

func binding(name, policy string, selector map[string]string, actions ...admissionregistrationv1.ValidationAction) *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	b := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: policy, ValidationActions: actions},
	}
	if selector != nil {
		b.Spec.MatchResources = &admissionregistrationv1.MatchResources{NamespaceSelector: &metav1.LabelSelector{MatchLabels: selector}}
	}
	return b
}

func deployment(ns, name string, replicas int32, image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}}},
		},
	}
}

func create(obj *appsv1.Deployment, who string) Request {
	return Request{
		Operation: admission.Create, Resource: deployGVR, Kind: deployGVK,
		Namespace: obj.Namespace, Name: obj.Name, Object: obj,
		User: &user.DefaultInfo{Name: who},
	}
}

func ns(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func mustEngine(t *testing.T, ps []*admissionregistrationv1.ValidatingAdmissionPolicy, bs []*admissionregistrationv1.ValidatingAdmissionPolicyBinding, nss ...*corev1.Namespace) *Engine {
	t.Helper()
	e, err := New(ps, bs, nss)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func eval(t *testing.T, e *Engine, r Request) Verdict {
	t.Helper()
	v, err := e.Evaluate(r)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDenyAndAdmit(t *testing.T) {
	e := mustEngine(t,
		[]*admissionregistrationv1.ValidatingAdmissionPolicy{policy("max-replicas", nil,
			admissionregistrationv1.Validation{Expression: "object.spec.replicas <= 5", Message: "too many replicas"})},
		[]*admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding("max-replicas", "max-replicas", nil, admissionregistrationv1.Deny)},
		ns("shop", nil))

	v := eval(t, e, create(deployment("shop", "web", 10, "nginx:1.27"), "alice"))
	if !v.Denied {
		t.Fatalf("10 replicas admitted: %+v", v)
	}
	want := `deployments.apps "web" is forbidden: ValidatingAdmissionPolicy 'max-replicas' with binding 'max-replicas' denied request: too many replicas`
	if v.Message != want {
		t.Fatalf("message\n got %q\nwant %q", v.Message, want)
	}
	if v := eval(t, e, create(deployment("shop", "web", 3, "nginx:1.27"), "alice")); v.Denied || len(v.Failures) != 0 {
		t.Fatalf("3 replicas: %+v", v)
	}
}

func TestEveryFailureIsReported(t *testing.T) {
	e := mustEngine(t,
		[]*admissionregistrationv1.ValidatingAdmissionPolicy{policy("two", nil,
			admissionregistrationv1.Validation{Expression: "object.spec.replicas <= 5", Message: "too many replicas"},
			admissionregistrationv1.Validation{Expression: "object.spec.template.spec.containers.all(c, !c.image.endsWith(':latest'))", Message: "no latest"})},
		[]*admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding("two", "two", nil, admissionregistrationv1.Deny)},
		ns("shop", nil))
	v := eval(t, e, create(deployment("shop", "web", 10, "nginx:latest"), "alice"))
	if len(v.Failures) != 2 || !strings.Contains(v.Message, "too many replicas") {
		t.Fatalf("%+v", v)
	}
}

func TestWarnAndAuditDoNotDeny(t *testing.T) {
	e := mustEngine(t,
		[]*admissionregistrationv1.ValidatingAdmissionPolicy{policy("max-replicas", nil,
			admissionregistrationv1.Validation{Expression: "object.spec.replicas <= 5", Message: "too many replicas"})},
		[]*admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding("soft", "max-replicas", nil, admissionregistrationv1.Warn, admissionregistrationv1.Audit)},
		ns("shop", nil))
	v := eval(t, e, create(deployment("shop", "web", 10, "nginx:1.27"), "alice"))
	if v.Denied || len(v.Warnings) != 1 || len(v.Audit) != 1 {
		t.Fatalf("%+v", v)
	}
}

func TestNamespaceSelectorFollowsLabelChanges(t *testing.T) {
	e := mustEngine(t,
		[]*admissionregistrationv1.ValidatingAdmissionPolicy{policy("max-replicas", nil,
			admissionregistrationv1.Validation{Expression: "object.spec.replicas <= 5"})},
		[]*admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding("prod-only", "max-replicas", map[string]string{"env": "prod"}, admissionregistrationv1.Deny)},
		ns("shop", map[string]string{"env": "staging"}))
	big := create(deployment("shop", "web", 10, "nginx:1.27"), "alice")
	if v := eval(t, e, big); v.Denied {
		t.Fatalf("staging namespace denied: %+v", v)
	}
	if err := e.SetNamespace(ns("shop", map[string]string{"env": "prod"})); err != nil {
		t.Fatal(err)
	}
	if v := eval(t, e, big); !v.Denied {
		t.Fatalf("prod namespace admitted: %+v", v)
	}
}

func TestMatchConditionsSeeTheUser(t *testing.T) {
	e := mustEngine(t,
		[]*admissionregistrationv1.ValidatingAdmissionPolicy{policy("max-replicas",
			[]admissionregistrationv1.MatchCondition{{Name: "not-system", Expression: "!request.userInfo.username.startsWith('system:')"}},
			admissionregistrationv1.Validation{Expression: "object.spec.replicas <= 5"})},
		[]*admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding("b", "max-replicas", nil, admissionregistrationv1.Deny)},
		ns("shop", nil))
	if v := eval(t, e, create(deployment("shop", "web", 10, "x:1"), "system:serviceaccount:kube-system:deployment-controller")); v.Denied {
		t.Fatalf("system user denied: %+v", v)
	}
	if v := eval(t, e, create(deployment("shop", "web", 10, "x:1"), "alice")); !v.Denied {
		t.Fatalf("alice admitted: %+v", v)
	}
}

func TestRuntimeErrorFollowsFailurePolicy(t *testing.T) {
	// Indexing a missing map key is a runtime error in CEL. Under the default
	// failurePolicy (Fail) that denies; under Ignore it admits.
	p := policy("labels", nil, admissionregistrationv1.Validation{Expression: "object.metadata.labels['team'] != ''"})
	ignore := p.DeepCopy()
	ignore.Name = "labels-ignore"
	f := admissionregistrationv1.Ignore
	ignore.Spec.FailurePolicy = &f
	for _, tc := range []struct {
		p      *admissionregistrationv1.ValidatingAdmissionPolicy
		denied bool
	}{{p, true}, {ignore, false}} {
		e := mustEngine(t, []*admissionregistrationv1.ValidatingAdmissionPolicy{tc.p},
			[]*admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding("b", tc.p.Name, nil, admissionregistrationv1.Deny)}, ns("shop", nil))
		if v := eval(t, e, create(deployment("shop", "web", 1, "x:1"), "alice")); v.Denied != tc.denied {
			t.Fatalf("%s: denied=%v want %v: %+v", tc.p.Name, v.Denied, tc.denied, v)
		}
	}
}

func TestCompileErrorDeniesUnderFail(t *testing.T) {
	e := mustEngine(t,
		[]*admissionregistrationv1.ValidatingAdmissionPolicy{policy("broken", nil, admissionregistrationv1.Validation{Expression: "object.spec.replicas <="})},
		[]*admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding("b", "broken", nil, admissionregistrationv1.Deny)},
		ns("shop", nil))
	v := eval(t, e, create(deployment("shop", "web", 1, "x:1"), "alice"))
	if !v.Denied || !strings.Contains(v.Message, "compilation failed") {
		t.Fatalf("%+v", v)
	}
}
