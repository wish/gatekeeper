package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

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

func verifyFileWithRule(path string, rule Rule) []error {
	errs := []error{}

	resources, errs := parseFile(path)

	//Parse path variables
	pathVars := strings.Split(path, "/")

	// Traverse the rules tree and verify file tree on each node
	errs = append(errs, verifyResources(rule, resources, pathVars)...)

	return errs
}

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

// Verifies a list of resources with a rule tree
func verifyResources(rule Rule, resources []map[string]interface{}, pathVars []string) []error {
	errs := []error{}

	for _, resource := range resources {
		if _, ok := resource["kind"]; !ok {
			errs = append(errs, fmt.Errorf("Resource in %v does not have 'kind' field", strings.Join(pathVars, "/")))
			continue
		}

		if rule.Kind == resource["kind"] {
			errs = append(errs, verifyResourcesTraverseHelper(rule.RuleTree, resource, pathVars, "")...)
		}
	}

	return errs
}

func verifyResourcesTraverseHelper(ruleTree map[string]interface{}, resourceTree map[string]interface{}, pathVars []string, parentKey string) []error {
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
				errs = append(errs, applyRule(t, key, resourceTree[k], pathVars)...)
			} else {
				switch r := resourceTree[k].(type) {
				case map[string]interface{}:
					errs = append(errs, verifyResourcesTraverseHelper(t, r, pathVars, key)...)
				default:
					errs = append(errs, fmt.Errorf("Resource key %v does not contain an object for a value", k))
				}
			}
		}
	}
	return errs
}

func applyRule(rule map[string]interface{}, key string, val interface{}, pathVars []string) []error {
	errs := []error{}
	switch rule["operation"] {
	case "&":
		var and AND
		if err := mapstructure.Decode(rule, &and); err != nil {
			errs = append(errs, err)
			return errs
		}
		if !(checkRule(and.Op1, val, pathVars) && checkRule(and.Op2, val, pathVars)) {
			errs = append(errs, fmt.Errorf("Broken AND() rule at key %v", key))
		}
	case "|":
		var or OR
		if err := mapstructure.Decode(rule, &or); err != nil {
			errs = append(errs, err)
			return errs
		}
		if !(checkRule(or.Op1, val, pathVars) || checkRule(or.Op2, val, pathVars)) {
			errs = append(errs, fmt.Errorf("Broken OR() rule at key %v", key))
		}
	case "!":
		var not NOT
		if err := mapstructure.Decode(rule, &not); err != nil {
			errs = append(errs, err)
			return errs
		}
		if checkRule(not.Op, val, pathVars) {
			errs = append(errs, fmt.Errorf("Broken NOT() rule at key %v", key))
		}
	case "<":
		var lt LT
		if err := mapstructure.Decode(rule, &lt); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := val.(float64)
		if resourceVal >= lt.Value {
			errs = append(errs, fmt.Errorf("Broken LT() rule at key %v: %v >= %v", key, resourceVal, lt.Value))
		}
	case ">":
		var gt GT
		if err := mapstructure.Decode(rule, &gt); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := val.(float64)
		if resourceVal <= gt.Value {
			errs = append(errs, fmt.Errorf("Broken GT() rule at key %v: %v <= %v", key, resourceVal, gt.Value))
		}
	case "=":
		var eq EQ
		if err := mapstructure.Decode(rule, &eq); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := fmt.Sprintf("%v", val)
		eqVal := fmt.Sprintf("%v", eq.Value)
		if resourceVal != eqVal {
			errs = append(errs, fmt.Errorf("Broken EQ() rule at key %v: %v != %v", key, resourceVal, eqVal))
		}
	case "tag":
		var tag TAG
		if err := mapstructure.Decode(rule, &tag); err != nil {
			errs = append(errs, err)
			return errs
		}
		resourceVal := fmt.Sprintf("%v", val)
		if val, ok := tagMap[tag.Tag]; ok {
			if resourceVal != val {
				errs = append(errs, fmt.Errorf("Broken TAG() rule at key %v: %v != %v", key, resourceVal, val))
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
		if resourceVal != val {
			errs = append(errs, fmt.Errorf("Broken PATH() rule at key %v: %v != %v", key, resourceVal, val))
		}
	default:
		errs = append(errs, fmt.Errorf("Unknown gatekeeper operation encountered: %v", rule["operation"]))
	}
	return errs
}

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

	// TODO: link with go-jsonnet instead of manually calling command
	command := exec.Command("jsonnet", "-e", jsonnetResult)
	var outB, errB bytes.Buffer
	command.Stdout = &outB
	command.Stderr = &errB
	err = command.Run()
	jsonResult := outB.Bytes()
	jsonnetErr := errB.String()
	if err != nil {
		fmt.Println("Error when using go-jsonnet to parse jsonnet file: " + jsonnetErr)
		os.Exit(1)
	}

	var ruleSet RuleSet
	err = json.Unmarshal(jsonResult, &ruleSet)
	if err != nil {
		fmt.Println("Error unmarshalling ruleset json: " + err.Error())
		os.Exit(1)
	}
	return ruleSet
}
