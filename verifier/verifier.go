package verifier

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	jsonnet "github.com/google/go-jsonnet"
	"github.com/mitchellh/mapstructure"

	"github.com/wish/gatekeeper/parser"
)

var resourceIds map[ResourceIdentifier]bool

// Verify verifies the given folder of Kubernetes files, then returns the errors encountered
func Verify(ruleSet RuleSet, base string) []error {
	errs := []error{}
	resourceIds = make(map[ResourceIdentifier]bool)

	err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		for _, ignore := range ruleSet.Ignore {
			if info.Name() == ignore {
				return nil
			}
		}

		_, err = parser.ParseObjectsFromFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("Could not parse %v: %v", path, err))
			return nil
		}

		// Verify structural defaults
		errs = append(errs, verifyStructure(path)...)

		// Verify rules
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

	//Tag map
	tagMap := make(map[string]string)

	// Traverse the rules tree and verify file tree on each node
	errs = append(errs, verifyResources(rule, resources, pathVars, tagMap)...)

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

	resources := strings.Split(strings.TrimSuffix(strings.TrimSpace(string(fileContent)), "..."), "---\n")
	for _, resource := range resources {
		if strings.TrimSpace(resource) == "" {
			continue
		}
		var resourceMap map[string]interface{}
		if err := json.Unmarshal([]byte(resource), &resourceMap); err != nil {
			errs = append(errs, fmt.Errorf("Error unmarshalling file %v: %v", path, err.Error()))
		}
		tree = append(tree, resourceMap)
	}
	return tree, errs
}

// Verifies a list of resources with a rule
func verifyResources(rule Rule, resources []map[string]interface{}, pathVars []string, tagMap map[string]string) []error {
	errs := []error{}

	for _, resource := range resources {

		// Check kind exists
		if _, ok := resource["kind"]; !ok {
			errDetails := map[string]interface{}{
				"path":     strings.Join(pathVars, "/"),
				"resource": resource,
			}
			errs = append(errs, NewGatekeeperError("Resource does not have 'kind' field: \n%v", errDetails))
			continue
		}

		// Verify any deny rules for this resource kind
		if rule.Kind == resource["kind"] && rule.Type == "deny" && len(rule.RuleTree) == 0 {
			errDetails := map[string]interface{}{
				"path": strings.Join(pathVars, "/"),
				"kind": resource["kind"],
			}
			errs = append(errs, NewGatekeeperError("Kind not allowed due to deny rule: \n%v", errDetails))
			continue
		}

		if rule.Kind == resource["kind"] {
			var allow bool
			if rule.Type == "allow" {
				allow = true
			} else if rule.Type == "deny" {
				allow = false
			} else {
				errDetails := map[string]interface{}{
					"path": strings.Join(pathVars, "/"),
					"type": rule.Type,
				}
				errs = append(errs, NewGatekeeperError("Invalid type field in rule (must be allow or deny): \n%v", errDetails))
				return errs
			}
			errs = append(errs, verifyResourcesTraverseHelper(rule.RuleTree, resource, pathVars, tagMap, "", allow)...)
		}
	}

	return errs
}

// Traverses rule tree to properly apply rules
func verifyResourcesTraverseHelper(ruleTree map[string]interface{}, resourceTree map[string]interface{}, pathVars []string, tagMap map[string]string, parentKey string, allow bool) []error {
	errs := []error{}
	for k, v := range ruleTree {
		// Check resource tree has key
		if _, ok := resourceTree[k]; !ok {
			errDetails := map[string]interface{}{
				"path": strings.Join(pathVars, "/"),
				"key":  k,
			}
			errs = append(errs, NewGatekeeperError("Resource does not have expected key: \n%v", errDetails))
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
				errs = append(errs, applyRule(t, key, resourceTree[k], pathVars, tagMap, allow)...)
			} else {
				switch r := resourceTree[k].(type) {
				case map[string]interface{}:
					errs = append(errs, verifyResourcesTraverseHelper(t, r, pathVars, tagMap, key, allow)...)
				default:
					errDetails := map[string]interface{}{
						"path":  strings.Join(pathVars, "/"),
						"key":   k,
						"value": r,
					}
					errs = append(errs, NewGatekeeperError("Expected object, but key does not contain an object for a value: \n%v", errDetails))
				}
			}
		}
	}
	return errs
}

// Applies a rule to a key/value pair, returns list of errors encountered
func applyRule(rule map[string]interface{}, key string, val interface{}, pathVars []string, tagMap map[string]string, allow bool) []error {
	errs := []error{}
	switch rule["operation"] {
	case "&":
		var and AND
		if err := mapstructure.Decode(rule, &and); err != nil {
			errs = append(errs, err)
			return errs
		}
		rulePassed := checkRule(and.Op1, val, pathVars, tagMap) && checkRule(and.Op2, val, pathVars, tagMap)
		errDetails := map[string]interface{}{
			"path":        strings.Join(pathVars, "/"),
			"key":         key,
			"value":       val,
			"operation_1": and.Op1,
			"operation_2": and.Op2,
		}
		if !rulePassed && allow {
			errDetails["rule_type"] = "allow"
			errs = append(errs, NewGatekeeperError("Broken AND() rule: \n%v", errDetails))
		} else if rulePassed && !allow {
			errDetails["rule_type"] = "deny"
			errs = append(errs, NewGatekeeperError("Broken AND() rule: \n%v", errDetails))
		}
	case "|":
		var or OR
		if err := mapstructure.Decode(rule, &or); err != nil {
			errs = append(errs, err)
			return errs
		}
		rulePassed := checkRule(or.Op1, val, pathVars, tagMap) || checkRule(or.Op2, val, pathVars, tagMap)
		errDetails := map[string]interface{}{
			"path":        strings.Join(pathVars, "/"),
			"key":         key,
			"value":       val,
			"operation_1": or.Op1,
			"operation_2": or.Op2,
		}
		if !rulePassed && allow {
			errDetails["rule_type"] = "allow"
			errs = append(errs, NewGatekeeperError("Broken OR() rule: \n%v", errDetails))
		} else if rulePassed && !allow {
			errDetails["rule_type"] = "deny"
			errs = append(errs, NewGatekeeperError("Broken OR() rule: \n%v", errDetails))
		}
	case "!":
		var not NOT
		if err := mapstructure.Decode(rule, &not); err != nil {
			errs = append(errs, err)
			return errs
		}
		rulePassed := !checkRule(not.Op, val, pathVars, tagMap)
		errDetails := map[string]interface{}{
			"path":      strings.Join(pathVars, "/"),
			"key":       key,
			"value":     val,
			"operation": not.Op,
		}
		if !rulePassed && allow {
			errDetails["rule_type"] = "allow"
			errs = append(errs, NewGatekeeperError("Broken NOT() rule: \n%v", errDetails))
		} else if rulePassed && !allow {
			errDetails["rule_type"] = "deny"
			errs = append(errs, NewGatekeeperError("Broken NOT() rule: \n%v", errDetails))
		}
	case "<":
		var lt LT
		if err := mapstructure.Decode(rule, &lt); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := val.(float64)
		rulePassed := resourceVal < lt.Value
		errDetails := map[string]interface{}{
			"path":     strings.Join(pathVars, "/"),
			"key":      key,
			"expected": lt.Value,
			"actual":   resourceVal,
		}
		if !rulePassed && allow {
			errDetails["rule_type"] = "allow"
			errs = append(errs, NewGatekeeperError("Broken LT() rule: \n%v", errDetails))
		} else if rulePassed && !allow {
			errDetails["rule_type"] = "deny"
			errs = append(errs, NewGatekeeperError("Broken LT() rule: \n%v", errDetails))
		}
	case ">":
		var gt GT
		if err := mapstructure.Decode(rule, &gt); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := val.(float64)
		rulePassed := resourceVal > gt.Value
		errDetails := map[string]interface{}{
			"path":     strings.Join(pathVars, "/"),
			"key":      key,
			"expected": gt.Value,
			"actual":   resourceVal,
		}
		if !rulePassed && allow {
			errDetails["rule_type"] = "allow"
			errs = append(errs, NewGatekeeperError("Broken GT() rule: \n%v", errDetails))
		} else if rulePassed && !allow {
			errDetails["rule_type"] = "deny"
			errs = append(errs, NewGatekeeperError("Broken GT() rule: \n%v", errDetails))
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
		errDetails := map[string]interface{}{
			"path":     strings.Join(pathVars, "/"),
			"key":      key,
			"expected": eqVal,
			"actual":   resourceVal,
		}
		if !rulePassed && allow {
			errDetails["rule_type"] = "allow"
			errs = append(errs, NewGatekeeperError("Broken EQ() rule: \n%v", errDetails))
		} else if rulePassed && !allow {
			errDetails["rule_type"] = "deny"
			errs = append(errs, NewGatekeeperError("Broken EQ() rule: \n%v", errDetails))
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
			errDetails := map[string]interface{}{
				"path":     strings.Join(pathVars, "/"),
				"key":      key,
				"expected": val,
				"actual":   resourceVal,
			}
			if !rulePassed && allow {
				errDetails["rule_type"] = "allow"
				errs = append(errs, NewGatekeeperError("Broken TAG() rule: \n%v", errDetails))
			} else if rulePassed && !allow {
				errDetails["rule_type"] = "deny"
				errs = append(errs, NewGatekeeperError("Broken TAG() rule: \n%v", errDetails))
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
			errDetails := map[string]interface{}{
				"path":  strings.Join(pathVars, "/"),
				"index": path.Index,
				"key":   key,
			}
			errs = append(errs, NewGatekeeperError("PATH() index is out of bounds: \n%v", errDetails))
			return errs
		}
		val := pathVars[len(pathVars)-1-path.Index]
		rulePassed := resourceVal == val
		errDetails := map[string]interface{}{
			"path":     strings.Join(pathVars, "/"),
			"key":      key,
			"expected": val,
			"actual":   resourceVal,
		}
		if !rulePassed && allow {
			errDetails["rule_type"] = "allow"
			errs = append(errs, NewGatekeeperError("Broken PATH() rule: \n%v", errDetails))
		} else if rulePassed && !allow {
			errDetails["rule_type"] = "deny"
			errs = append(errs, NewGatekeeperError("Broken PATH() rule: \n%v", errDetails))
		}
	default:
		errs = append(errs, fmt.Errorf("Unknown gatekeeper operation encountered: %v", rule["operation"]))
	}
	return errs
}

// Checks if gatekeeper function is satisfied, returns boolean result of check
// TODO: return a list of errors so that you can see what caused an AND(), OR(), or NOT() rule to fail
func checkRule(gFunction map[string]interface{}, val interface{}, pathVars []string, tagMap map[string]string) bool {
	switch gFunction["operation"] {
	case "&":
		var and AND
		mapstructure.Decode(gFunction, &and)
		return checkRule(and.Op1, val, pathVars, tagMap) && checkRule(and.Op2, val, pathVars, tagMap)
	case "|":
		var or OR
		mapstructure.Decode(gFunction, &or)
		return checkRule(or.Op1, val, pathVars, tagMap) || checkRule(or.Op2, val, pathVars, tagMap)
	case "!":
		var not NOT
		mapstructure.Decode(gFunction, &not)
		return !checkRule(not.Op, val, pathVars, tagMap)
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

// verifyStructure verifies structural rules
func verifyStructure(path string) []error {
	errs := []error{}

	//Parse path variables
	pathVars := strings.Split(path, "/")
	resources, errs := parseFile(path)
	for _, resource := range resources {

		// Check kind exists
		if _, ok := resource["kind"]; !ok {
			errDetails := map[string]interface{}{
				"path":     strings.Join(pathVars, "/"),
				"resource": resource,
			}
			errs = append(errs, NewGatekeeperError("Resource does not have 'kind' field: \n%v", errDetails))
			continue
		}

		// Check metadata exists
		if _, ok := resource["metadata"]; !ok {
			errDetails := map[string]interface{}{
				"path":     strings.Join(pathVars, "/"),
				"resource": resource,
			}
			errs = append(errs, NewGatekeeperError("Resource does not have 'metadata' field: \n%v", errDetails))
			continue
		}

		// Verify metadata is object
		switch md := resource["metadata"].(type) {
		case map[string]interface{}:
			// Check metadata.name exists
			if _, ok := md["name"]; !ok {
				errDetails := map[string]interface{}{
					"path":     strings.Join(pathVars, "/"),
					"resource": resource,
				}
				errs = append(errs, NewGatekeeperError("Resource does not have 'metadata.name' field: \n%v", errDetails))
				continue
			}

			// Check metadata.name and namespace are unique
			resourceName := fmt.Sprintf("%v", md["name"])
			resourceNamespace := "default"
			resourceKind := fmt.Sprintf("%v", resource["kind"])
			if _, ok := md["namespace"]; ok {
				resourceNamespace = fmt.Sprintf("%v", md["namespace"])
			}

			resourceID := ResourceIdentifier{resourceName, resourceNamespace, resourceKind}
			if _, ok := resourceIds[resourceID]; ok && resourceIds[resourceID] {
				errDetails := map[string]interface{}{
					"path":                strings.Join(pathVars, "/"),
					"duplicate_name":      resourceName,
					"duplicate_namespace": resourceNamespace,
					"duplicate_kind":      resource["kind"],
					"resource":            resource,
				}
				errs = append(errs, NewGatekeeperError("Duplicate resource with same namespace, name, and kind: \n%v", errDetails))
				continue
			} else {
				resourceIds[resourceID] = true
			}

		default:
			errs = append(errs, fmt.Errorf("Resource in %v has an invalid 'metadata' field type", strings.Join(pathVars, "/")))
			continue
		}
	}
	return errs
}

// ParseRuleset parses the ruleset file and returns a RuleSet object
func ParseRuleset(rulesetPath string, gatekeeperFunctions string) RuleSet {
	// Read ruleset
	ruleSetContent, err := ioutil.ReadFile(rulesetPath)
	if err != nil {
		fmt.Println("Error reading " + rulesetPath + ": " + err.Error())
		os.Exit(1)
	}

	// Run go-jsonnet on concatenated result of gatekeeper functions + ruleset
	jsonnetResult := gatekeeperFunctions + string(ruleSetContent)
	vm := jsonnet.MakeVM()
	jsonResult, err := vm.EvaluateSnippet("<cmdline>", jsonnetResult)
	if err != nil {
		fmt.Println("Error using go-jsonnet to parse ruleset: " + err.Error())
		os.Exit(1)
	}

	var ruleSet RuleSet
	err = json.Unmarshal([]byte(jsonResult), &ruleSet)
	if err != nil {
		fmt.Println("Error unmarshalling ruleset json: " + err.Error())
		os.Exit(1)
	}
	return ruleSet
}

// NewGatekeeperError creates a new gatekeeper error and appends to the given errors slice
func NewGatekeeperError(errString string, errDetails map[string]interface{}) error {
	b, err := json.MarshalIndent(errDetails, "", "	")
	if err != nil {
		return fmt.Errorf("Error unmarshalling error details: \n%v", err)
	}
	return fmt.Errorf(errString, string(b))
}
