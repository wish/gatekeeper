package verifier

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/viper"

	"github.com/wish/gatekeeper/parser"
)

// Verify verifies the given folder of Kubernetes files, then returns the errors encountered
func Verify(ruleSet RuleSet, base string) []error {
	errs := []error{}

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

	// Traverse the rules tree and verify file tree on each node
	errs = append(errs, verifyResources(rule, resources, path)...)

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
func verifyResources(rule Rule, resources []map[string]interface{}, path string) []error {
	errs := []error{}

	for _, resource := range resources {
		if _, ok := resource["kind"]; !ok {
			errs = append(errs, fmt.Errorf("Resource in %v does not have 'kind' field", path))
			continue
		}
		if rule.Kind == resource["kind"] {
			errs = append(errs, verifyResourcesTraverseHelper(rule.RuleTree, resource)...)
		}
	}

	return errs
}

func verifyResourcesTraverseHelper(ruleTree map[string]interface{}, resourceTree map[string]interface{}) []error {
	errs := []error{}
	for k, v := range ruleTree {
		switch t := v.(type) {
		case map[string]interface{}:
			if _, ok := resourceTree[k]; !ok {
				errs = append(errs, fmt.Errorf("Resource does not contain key %v", k))
				continue
			}

			if _, ok := t["gatekeeper"]; ok {
				switch t["operation"] {
				case "<":
					val, err := interfaceToFloat(t["value"])
					if err != nil {
						errs = append(errs, err)
						continue
					}
					resourceVal, err := interfaceToFloat(resourceTree[k])
					if err != nil {
						errs = append(errs, err)
						continue
					}
					if resourceVal >= val {
						errs = append(errs, fmt.Errorf("Broken < rule at key %v: %v >= %v", k, resourceVal, val))
					}
				case ">":
					val, err := interfaceToFloat(t["value"])
					if err != nil {
						errs = append(errs, err)
						continue
					}
					resourceVal, err := interfaceToFloat(resourceTree[k])
					if err != nil {
						errs = append(errs, err)
						continue
					}
					if resourceVal <= val {
						errs = append(errs, fmt.Errorf("Broken > rule at key %v: %v <= %v", k, resourceVal, val))
					}
				case "=":
					val := fmt.Sprintf("%v", t["value"])
					resourceVal := fmt.Sprintf("%v", resourceTree[k])
					if resourceVal != val {
						errs = append(errs, fmt.Errorf("Broken = rule at key %v: %v != %v", k, resourceVal, val))
					}
				default:
					errs = append(errs, fmt.Errorf("Unknown gatekeeper operation encountered: %v", t["operation"]))
				}
			} else {
				switch r := resourceTree[k].(type) {
				case map[string]interface{}:
					errs = append(errs, verifyResourcesTraverseHelper(t, r)...)
				default:
					errs = append(errs, fmt.Errorf("Resource key %v does contain an object for a value", k))
				}
			}
		default:
			continue
		}
	}
	return errs
}

// TODO: possibility of overflow with int64 -> float64
func interfaceToFloat(obj interface{}) (float64, error) {
	switch i := obj.(type) {
	case float64:
		return i, nil
	case float32:
		return float64(i), nil
	case int64:
		return float64(i), nil
	case int32:
		return float64(i), nil
	case int16:
		return float64(i), nil
	case int8:
		return float64(i), nil
	case int:
		return float64(i), nil
	case string:
		return strconv.ParseFloat(i, 64)
	default:
		return 0, fmt.Errorf("Cannot convert %v to float64", obj)
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
	jsonResult, err := exec.Command("jsonnet", "-e", jsonnetResult).Output()
	if err != nil {
		fmt.Println("Error when using go-jsonnet to parse jsonnet file: " + err.Error())
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
