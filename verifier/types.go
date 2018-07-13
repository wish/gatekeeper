package verifier

// TODO: Use emebedded structs

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

// LT describes a LT() function
type LT struct {
	Gatekeeper bool
	Operation  string
	Value      float64
}

// GT describes a GT() function
type GT struct {
	Gatekeeper bool
	Operation  string
	Value      float64
}

// EQ describes a EQ() function
type EQ struct {
	Gatekeeper bool
	Operation  string
	Value      interface{}
}

// AND describes a AND() function
type AND struct {
	Gatekeeper bool
	Operation  string
	Op1        map[string]interface{}
	Op2        map[string]interface{}
}

// OR describes a OR() function
type OR struct {
	Gatekeeper bool
	Operation  string
	Op1        map[string]interface{}
	Op2        map[string]interface{}
}

// NOT describes a NOT() function
type NOT struct {
	Gatekeeper bool
	Operation  string
	Op         map[string]interface{}
}

// TAG describes a TAG() function
type TAG struct {
	Gatekeeper bool
	Operation  string
	Tag        string
}

// PATH describes a PATH() function
type PATH struct {
	Gatekeeper bool
	Operation  string
	Index      int
}
