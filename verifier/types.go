package verifier

// RuleSet is a set of Rules
type RuleSet struct {
	Rules []Rule
}

// Rule describes a rule
type Rule struct {
	Regex    string
	Kind     string
	RuleTree map[string]interface{}
}
