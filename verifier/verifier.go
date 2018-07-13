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
	"strconv"
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
				case "&":
					var and AND
					if err := mapstructure.Decode(t, &and); err != nil {
						errs = append(errs, err)
						continue
					}
					if !(applyGatekeeperFunction(and.Op1, resourceTree[k]) && applyGatekeeperFunction(and.Op2, resourceTree[k])) {
						errs = append(errs, fmt.Errorf("Broken AND() rule at key %v", k))
					}
				case "|":
					var or OR
					if err := mapstructure.Decode(t, &or); err != nil {
						errs = append(errs, err)
						continue
					}
					if !(applyGatekeeperFunction(or.Op1, resourceTree[k]) || applyGatekeeperFunction(or.Op2, resourceTree[k])) {
						errs = append(errs, fmt.Errorf("Broken OR() rule at key %v", k))
					}
				case "!":
					var not NOT
					if err := mapstructure.Decode(t, &not); err != nil {
						errs = append(errs, err)
						continue
					}
					if applyGatekeeperFunction(not.Op, resourceTree[k]) {
						errs = append(errs, fmt.Errorf("Broken NOT() rule at key %v", k))
					}
				case "<":
					var lt LT
					if err := mapstructure.Decode(t, &lt); err != nil {
						errs = append(errs, err)
						continue
					}
					resourceVal, err := interfaceToFloat(resourceTree[k])
					if err != nil {
						errs = append(errs, err)
						continue
					}
					if resourceVal >= lt.Value {
						errs = append(errs, fmt.Errorf("Broken LT() rule at key %v: %v >= %v", k, resourceVal, lt.Value))
					}
				case ">":
					var gt GT
					if err := mapstructure.Decode(t, &gt); err != nil {
						errs = append(errs, err)
						continue
					}
					resourceVal, err := interfaceToFloat(resourceTree[k])
					if err != nil {
						errs = append(errs, err)
						continue
					}
					if resourceVal <= gt.Value {
						errs = append(errs, fmt.Errorf("Broken GT() rule at key %v: %v <= %v", k, resourceVal, gt.Value))
					}
				case "=":
					var eq EQ
					if err := mapstructure.Decode(t, &eq); err != nil {
						errs = append(errs, err)
						continue
					}
					resourceVal := fmt.Sprintf("%v", resourceTree[k])
					if resourceVal != eq.Value {
						errs = append(errs, fmt.Errorf("Broken EQ() rule at key %v: %v != %v", k, resourceVal, eq.Value))
					}
				case "tag":
					var tag TAG
					if err := mapstructure.Decode(t, &tag); err != nil {
						errs = append(errs, err)
						continue
					}
					resourceVal := fmt.Sprintf("%v", resourceTree[k])
					if val, ok := tagMap[tag.Tag]; ok {
						if resourceVal != val {
							errs = append(errs, fmt.Errorf("Broken TAG() rule at key %v: %v != %v", k, resourceVal, val))
						}
					} else {
						tagMap[tag.Tag] = resourceVal
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

func applyGatekeeperFunction(gFunction map[string]interface{}, val interface{}) bool {
	switch gFunction["operation"] {
	case "&":
		var and AND
		mapstructure.Decode(gFunction, &and)
		return applyGatekeeperFunction(and.Op1, val) && applyGatekeeperFunction(and.Op2, val)
	case "|":
		var or OR
		mapstructure.Decode(gFunction, &or)
		return applyGatekeeperFunction(or.Op1, val) || applyGatekeeperFunction(or.Op2, val)
	case "!":
		var not NOT
		mapstructure.Decode(gFunction, &not)
		return !applyGatekeeperFunction(not.Op, val)
	case ">":
		var gt GT
		mapstructure.Decode(gFunction, &gt)
		val, _ := interfaceToFloat(val)
		return val > gt.Value
	case "<":
		var lt LT
		mapstructure.Decode(gFunction, &lt)
		val, _ := interfaceToFloat(val)
		return val < lt.Value
	case "=":
		var eq EQ
		mapstructure.Decode(gFunction, &eq)
		val := fmt.Sprintf("%v", val)
		return val == eq.Value
	default:
		return false
	}
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
