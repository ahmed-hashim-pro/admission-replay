package policy

import (
	"fmt"

	celgo "github.com/google/cel-go/cel"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

// Problem is an expression that does not compile.
type Problem struct {
	Policy string
	Field  string // e.g. spec.validations[2].expression
	Err    string
}

func (p Problem) String() string { return fmt.Sprintf("policy %s: %s: %s", p.Policy, p.Field, p.Err) }

type expr struct {
	src     string
	returns []*celgo.Type
}

func (e expr) GetExpression() string           { return e.src }
func (e expr) ReturnTypes() []*celgo.Type      { return e.returns }
func (e expr) GetName() string                 { return "" }
func (e namedExpr) GetName() string            { return e.name }
func (e namedExpr) GetExpression() string      { return e.src }
func (e namedExpr) ReturnTypes() []*celgo.Type { return []*celgo.Type{celgo.AnyType} }

type namedExpr struct{ name, src string }

// Compile compiles every CEL expression in the candidate with the API
// server's environment, as the policy plugin does, and reports each one that
// fails. A policy with such an expression fails every request it matches
// (or ignores them, under failurePolicy: Ignore).
func (c *Candidate) Compile() []Problem {
	var out []Problem
	for _, p := range c.Policies {
		vars := plugincel.OptionalVariableDeclarations{HasParams: p.Spec.ParamKind != nil, HasAuthorizer: true, StrictCost: true}
		noAuthz := vars
		noAuthz.HasAuthorizer = false
		comp, err := plugincel.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), true))
		if err != nil {
			out = append(out, Problem{Policy: p.Name, Field: "spec", Err: err.Error()})
			continue
		}
		named := make([]plugincel.NamedExpressionAccessor, len(p.Spec.Variables))
		for i, v := range p.Spec.Variables {
			named[i] = namedExpr{v.Name, v.Expression}
		}
		comp.CompileAndStoreVariables(named, vars, environment.StoredExpressions)
		one := func(field string, e expr, opts plugincel.OptionalVariableDeclarations) {
			cond := comp.CompileCondition([]plugincel.ExpressionAccessor{e}, opts, environment.StoredExpressions)
			for _, err := range cond.CompilationErrors() {
				out = append(out, Problem{Policy: p.Name, Field: field, Err: err.Error()})
			}
		}
		for i, v := range p.Spec.Variables {
			one(fmt.Sprintf("spec.variables[%d].expression (%s)", i, v.Name), expr{v.Expression, []*celgo.Type{celgo.AnyType}}, vars)
		}
		for i, m := range p.Spec.MatchConditions {
			one(fmt.Sprintf("spec.matchConditions[%d].expression (%s)", i, m.Name), expr{m.Expression, []*celgo.Type{celgo.BoolType}}, vars)
		}
		for i, v := range p.Spec.Validations {
			one(fmt.Sprintf("spec.validations[%d].expression", i), expr{v.Expression, []*celgo.Type{celgo.BoolType}}, vars)
			if v.MessageExpression != "" {
				one(fmt.Sprintf("spec.validations[%d].messageExpression", i), expr{v.MessageExpression, []*celgo.Type{celgo.StringType}}, noAuthz)
			}
		}
		for i, a := range p.Spec.AuditAnnotations {
			one(fmt.Sprintf("spec.auditAnnotations[%d].valueExpression", i), expr{a.ValueExpression, []*celgo.Type{celgo.StringType, celgo.NullType}}, vars)
		}
	}
	return out
}
