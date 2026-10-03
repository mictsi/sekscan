// Package policy evaluates organizational policies, not legal compatibility.
package policy

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"sekscan/internal/config"
)

type expressionParser struct {
	tokens []string
	at     int
	depth  int
	policy config.LicensePolicy
}
type expressionResult struct {
	Decision  string
	Canonical string
}

func EvaluateExpression(expression string, p config.LicensePolicy) (string, string, error) {
	if len(expression) > 8192 {
		return "review", "", fmt.Errorf("license expression is too long")
	}
	tokens := []string{}
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for _, r := range expression {
		switch {
		case unicode.IsSpace(r):
			flush()
		case r == '(' || r == ')':
			flush()
			tokens = append(tokens, string(r))
		case unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(".-+:", r):
			current.WriteRune(r)
		default:
			return "review", "", fmt.Errorf("invalid character in SPDX expression")
		}
	}
	flush()
	if len(tokens) == 0 {
		return p.Unknown, "", fmt.Errorf("missing license expression")
	}
	parser := expressionParser{tokens: tokens, policy: p}
	r, e := parser.parseOR()
	if e != nil {
		return "review", "", e
	}
	if parser.at != len(tokens) {
		return "review", "", fmt.Errorf("unexpected SPDX token %q", tokens[parser.at])
	}
	return r.Decision, r.Canonical, nil
}
func (p *expressionParser) peek() string {
	if p.at >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.at]
}
func combine(op string, a, b expressionResult) expressionResult {
	r := expressionResult{}
	parts := []string{a.Canonical, b.Canonical}
	sort.Strings(parts)
	r.Canonical = "(" + strings.Join(parts, " "+op+" ") + ")"
	if op == "OR" {
		switch {
		case a.Decision == "pass" || b.Decision == "pass":
			r.Decision = "pass"
		case a.Decision == "review" || b.Decision == "review":
			r.Decision = "review"
		default:
			r.Decision = "fail"
		}
	} else {
		switch {
		case a.Decision == "fail" || b.Decision == "fail":
			r.Decision = "fail"
		case a.Decision == "review" || b.Decision == "review":
			r.Decision = "review"
		default:
			r.Decision = "pass"
		}
	}
	return r
}
func (p *expressionParser) parseOR() (expressionResult, error) {
	a, e := p.parseAND()
	if e != nil {
		return a, e
	}
	for p.peek() == "OR" {
		p.at++
		b, e := p.parseAND()
		if e != nil {
			return a, e
		}
		a = combine("OR", a, b)
	}
	return a, nil
}
func (p *expressionParser) parseAND() (expressionResult, error) {
	a, e := p.primary()
	if e != nil {
		return a, e
	}
	for p.peek() == "AND" {
		p.at++
		b, e := p.primary()
		if e != nil {
			return a, e
		}
		a = combine("AND", a, b)
	}
	return a, nil
}
func (p *expressionParser) primary() (expressionResult, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 64 {
		return expressionResult{}, fmt.Errorf("SPDX expression nesting limit exceeded")
	}
	token := p.peek()
	if token == "(" {
		p.at++
		r, e := p.parseOR()
		if e != nil {
			return r, e
		}
		if p.peek() != ")" {
			return r, fmt.Errorf("unclosed SPDX expression")
		}
		p.at++
		return r, nil
	}
	if token == "" || token == ")" || token == "AND" || token == "OR" || token == "WITH" {
		return expressionResult{}, fmt.Errorf("expected license identifier")
	}
	p.at++
	if p.peek() == "WITH" {
		p.at++
		exception := p.peek()
		if exception == "" || exception == "(" || exception == ")" || exception == "AND" || exception == "OR" || exception == "WITH" {
			return expressionResult{}, fmt.Errorf("expected SPDX exception identifier")
		}
		p.at++
		token += " WITH " + exception
	}
	decision := p.policy.Unlisted
	switch strings.ToUpper(token) {
	case "NOASSERTION", "NONE", "UNKNOWN", "UNLICENSED":
		decision = p.policy.Unknown
	default:
		for _, v := range p.policy.Allow {
			if token == v {
				decision = "pass"
			}
		}
		for _, v := range p.policy.Deny {
			if token == v {
				decision = "fail"
			}
		}
	}
	return expressionResult{Decision: decision, Canonical: token}, nil
}
