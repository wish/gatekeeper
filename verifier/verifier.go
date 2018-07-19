package verifier

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	jsonnet "github.com/google/go-jsonnet"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"

	"github.com/wish/gatekeeper/parser"
)

var tagMap map[string]string

// Verify verifies the given folder of Kubernetes files, then returns the errors encountered
func Verify(ruleSet RuleSet, base string) []error {
	errs := []error{}
	tagMap = make(map[string]string)

	err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		_, err = parser.ParseObjectsFromFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("Could not parse %v: %v", path, err))
			return nil
		}

		for _, rule := range ruleSet.Rules {
			reg, err := regexp.Compile(rule.Regex)
			if err != nil {
				errs = append(errs, fmt.Errorf("Could not compile regex: %v", rule.Regex))
			} else if reg.MatchString(info.Name()) {
				errs = append(errs, verifyFileWithRule(path, rule)...)
			}
		}

		return nil
	})

	if err != nil {
		errs = append(errs, fmt.Errorf("Error while traversing folder: %v", err))
	}
	return errs
}

// Verifies a file with a rule
func verifyFileWithRule(path string, rule Rule) []error {
	errs := []error{}

	resources, errs := parseFile(path)

	//Parse path variables
	pathVars := strings.Split(path, "/")

	// Traverse the rules tree and verify file tree on each node
	errs = append(errs, verifyResources(rule, resources, pathVars)...)

	return errs
}

// Parses a Kubernetes configuration file into a map[string]interface
func parseFile(path string) ([]map[string]interface{}, []error) {
	tree := make([]map[string]interface{}, 0)
	errs := []error{}

	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Cannot read " + path)
		os.Exit(1)
	}

	resources := strings.Split(string(fileContent), "---")
	for _, resource := range resources {
		if strings.TrimSpace(resource) == "" {
			continue
		}
		var resourceMap map[string]interface{}
		if err := json.Unmarshal([]byte(resource), &resourceMap); err != nil {
			errs = append(errs, err)
		}
		tree = append(tree, resourceMap)
	}
	return tree, errs
}

// Verifies a list of resources with a rule
func verifyResources(rule Rule, resources []map[string]interface{}, pathVars []string) []error {
	errs := []error{}

	for _, resource := range resources {
		if _, ok := resource["kind"]; !ok {
			errs = append(errs, fmt.Errorf("Resource in %v does not have 'kind' field", strings.Join(pathVars, "/")))
			continue
		}

		if rule.Kind == resource["kind"] && rule.Type == "deny" && len(rule.RuleTree) == 0 {
			errs = append(errs, fmt.Errorf("Kind %v not allowed", rule.Kind))
			continue
		}

		if rule.Kind == resource["kind"] {
			var allow bool
			if rule.Type == "allow" {
				allow = true
			} else if rule.Type == "deny" {
				allow = false
			} else {
				errs = append(errs, fmt.Errorf("Invalid type field in rule (must be allow or deny): %v", rule.Type))
				return errs
			}
			errs = append(errs, verifyResourcesTraverseHelper(rule.RuleTree, resource, pathVars, "", allow)...)
		}
	}

	return errs
}

// Traverses rule tree to properly apply rules
func verifyResourcesTraverseHelper(ruleTree map[string]interface{}, resourceTree map[string]interface{}, pathVars []string, parentKey string, allow bool) []error {
	errs := []error{}
	for k, v := range ruleTree {
		// Check resource tree has key
		if _, ok := resourceTree[k]; !ok {
			errs = append(errs, fmt.Errorf("Resource does not contain key %v", k))
			continue
		}
		key := k
		if parentKey != "" {
			key = parentKey + "." + k
		}

		switch t := v.(type) {
		case []interface{}:
			// TODO: arrays???
		case map[string]interface{}:
			if _, ok := t["gatekeeper"]; ok {
				errs = append(errs, applyRule(t, key, resourceTree[k], pathVars, allow)...)
			} else {
				switch r := resourceTree[k].(type) {
				case map[string]interface{}:
					errs = append(errs, verifyResourcesTraverseHelper(t, r, pathVars, key, allow)...)
				default:
					errs = append(errs, fmt.Errorf("Resource key %v does not contain an object for a value", k))
				}
			}
		}
	}
	return errs
}

// Applies a rule to a key/value pair, returns list of errors encountered
func applyRule(rule map[string]interface{}, key string, val interface{}, pathVars []string, allow bool) []error {
	errs := []error{}
	switch rule["operation"] {
	case "&":
		var and AND
		if err := mapstructure.Decode(rule, &and); err != nil {
			errs = append(errs, err)
			return errs
		}
		rulePassed := checkRule(and.Op1, val, pathVars) && checkRule(and.Op2, val, pathVars)
		if !rulePassed && allow {
			errs = append(errs, fmt.Errorf("Broken AND() rule at key %v in allow rule", key))
		} else if rulePassed && !allow {
			errs = append(errs, fmt.Errorf("Broken AND() rule at key %v in deny rule", key))
		}
	case "|":
		var or OR
		if err := mapstructure.Decode(rule, &or); err != nil {
			errs = append(errs, err)
			return errs
		}
		rulePassed := checkRule(or.Op1, val, pathVars) || checkRule(or.Op2, val, pathVars)
		if !rulePassed && allow {
			errs = append(errs, fmt.Errorf("Broken OR() rule at key %v in allow rule", key))
		} else if rulePassed && !allow {
			errs = append(errs, fmt.Errorf("Broken OR() rule at key %v in deny rule", key))
		}
	case "!":
		var not NOT
		if err := mapstructure.Decode(rule, &not); err != nil {
			errs = append(errs, err)
			return errs
		}
		rulePassed := !checkRule(not.Op, val, pathVars)
		if !rulePassed && allow {
			errs = append(errs, fmt.Errorf("Broken NOT() rule at key %v in allow rule", key))
		} else if rulePassed && !allow {
			errs = append(errs, fmt.Errorf("Broken NOT() rule at key %v in deny rule", key))
		}
	case "<":
		var lt LT
		if err := mapstructure.Decode(rule, &lt); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := val.(float64)
		rulePassed := resourceVal < lt.Value
		if !rulePassed && allow {
			errs = append(errs, fmt.Errorf("Broken LT() rule at key %v in allow rule: %v >= %v", key, resourceVal, lt.Value))
		} else if rulePassed && !allow {
			errs = append(errs, fmt.Errorf("Broken LT() rule at key %v in deny rule: %v < %v", key, resourceVal, lt.Value))
		}
	case ">":
		var gt GT
		if err := mapstructure.Decode(rule, &gt); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := val.(float64)
		rulePassed := resourceVal > gt.Value
		if !rulePassed && allow {
			errs = append(errs, fmt.Errorf("Broken GT() rule at key %v in allow rule: %v <= %v", key, resourceVal, gt.Value))
		} else if rulePassed && !allow {
			errs = append(errs, fmt.Errorf("Broken GT() rule at key %v in deny rule: %v > %v", key, resourceVal, gt.Value))
		}
	case "=":
		var eq EQ
		if err := mapstructure.Decode(rule, &eq); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := fmt.Sprintf("%v", val)
		eqVal := fmt.Sprintf("%v", eq.Value)
		rulePassed := resourceVal == eqVal
		if !rulePassed && allow {
			errs = append(errs, fmt.Errorf("Broken EQ() rule at key %v in allow rule: %v != %v", key, resourceVal, eqVal))
		} else if rulePassed && !allow {
			errs = append(errs, fmt.Errorf("Broken EQ() rule at key %v in deny rule: %v == %v", key, resourceVal, eqVal))
		}
	case "tag":
		var tag TAG
		if err := mapstructure.Decode(rule, &tag); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := fmt.Sprintf("%v", val)
		if val, ok := tagMap[tag.Tag]; ok {
			rulePassed := resourceVal == val
			if !rulePassed && allow {
				errs = append(errs, fmt.Errorf("Broken TAG() rule at key %v in allow rule: %v != %v", key, resourceVal, val))
			} else if rulePassed && !allow {
				errs = append(errs, fmt.Errorf("Broken TAG() rule at key %v in deny rule: %v == %v", key, resourceVal, val))
			}
		} else {
			tagMap[tag.Tag] = resourceVal
		}
	case "path":
		var path PATH
		if err := mapstructure.Decode(rule, &path); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := fmt.Sprintf("%v", val)
		if path.Index > len(pathVars)-1 {
			errs = append(errs, fmt.Errorf("PATH() index %v is out of bounds at key %v: %v", path.Index, key, strings.Join(pathVars, "/")))
			return errs
		}
		val := pathVars[len(pathVars)-1-path.Index]
		rulePassed := resourceVal == val
		if !rulePassed && allow {
			errs = append(errs, fmt.Errorf("Broken PATH() rule at key %v in allow rule: %v != %v", key, resourceVal, val))
		} else if rulePassed && !allow {
			errs = append(errs, fmt.Errorf("Broken PATH() rule at key %v in deny rule: %v == %v", key, resourceVal, val))
		}
	default:
		errs = append(errs, fmt.Errorf("Unknown gatekeeper operation encountered: %v", rule["operation"]))
	}
	return errs
}

// Checks if gatekeeper function is satisfied, returns boolean result of check
func checkRule(gFunction map[string]interface{}, val interface{}, pathVars []string) bool {
	switch gFunction["operation"] {
	case "&":
		var and AND
		mapstructure.Decode(gFunction, &and)
		return checkRule(and.Op1, val, pathVars) && checkRule(and.Op2, val, pathVars)
	case "|":
		var or OR
		mapstructure.Decode(gFunction, &or)
		return checkRule(or.Op1, val, pathVars) || checkRule(or.Op2, val, pathVars)
	case "!":
		var not NOT
		mapstructure.Decode(gFunction, &not)
		return !checkRule(not.Op, val, pathVars)
	case ">":
		var gt GT
		mapstructure.Decode(gFunction, &gt)
		val, _ := val.(float64)
		return val > gt.Value
	case "<":
		var lt LT
		mapstructure.Decode(gFunction, &lt)
		val, _ := val.(float64)
		return val < lt.Value
	case "=":
		var eq EQ
		mapstructure.Decode(gFunction, &eq)
		val := fmt.Sprintf("%v", val)
		eqVal := fmt.Sprintf("%v", eq.Value)
		return val == eqVal
	case "tag":
		var tag TAG
		mapstructure.Decode(gFunction, &tag)
		val := fmt.Sprintf("%v", val)
		if tagVal, ok := tagMap[tag.Tag]; ok {
			return val == tagVal
		}
		return true
	case "path":
		var path PATH
		mapstructure.Decode(gFunction, &path)
		if path.Index > len(pathVars)-1 {
			return false
		}
		pathVal := pathVars[len(pathVars)-1-path.Index]
		val := fmt.Sprintf("%v", val)
		return val == pathVal
	default:
		return false
	}
}

// ParseRuleset parses the ruleset file and returns a RuleSet object
func ParseRuleset(rulesetPath string) RuleSet {
	// Prepend gatekeeper functions to ruleset
	gatekeeperFunctions, err := ioutil.ReadFile(path.Join(viper.GetString("gopath"), "src/github.com/wish/gatekeeper/gatekeeper.jsonnet"))
	if err != nil {
		fmt.Println("Error reading gatekeeper.jsonnet: " + err.Error())
		os.Exit(1)
	}

	// Read ruleset
	ruleSetContent, err := ioutil.ReadFile(rulesetPath)
	if err != nil {
		fmt.Println("Error reading " + rulesetPath + ": " + err.Error())
		os.Exit(1)
	}

	// Run go-jsonnet on concatenated result of gatekeeper functions + ruleset
	jsonnetResult := string(gatekeeperFunctions) + string(ruleSetContent)
	vm := jsonnet.MakeVM()
	jsonResult, err := vm.EvaluateSnippet("<cmdline>", jsonnetResult)
	if err != nil {
		fmt.Println("Error using go-jsonnet to parse ruleset: " + err.Error())
	}

	var ruleSet RuleSet
	err = json.Unmarshal([]byte(jsonResult), &ruleSet)
	if err != nil {
		fmt.Println("Error unmarshalling ruleset json: " + err.Error())
		os.Exit(1)
	}
	return ruleSet
}
