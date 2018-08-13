package verifier

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

type CheckRuleArgObj struct {
	Rule     map[string]interface{}
	Val      interface{}
	PathVars []string
	Result   bool
}

type ApplyRuleArgObj struct {
	Rule     map[string]interface{}
	Key      string
	Val      interface{}
	PathVars []string
	Allow    bool
	Result   []string
}

var verifyTestFolder = "test_files/verifier_test_verify_folder/service"
var checkRuleTestFile = "test_files/verifier_test_check_rule.json"
var applyRuleTestFile = "test_files/verifier_test_apply_rule.json"
var parseRulesetTestJsonnet = "test_files/verifier_test_parse_ruleset.jsonnet"
var parseRulesetTestFile = "test_files/verifier_test_parse_ruleset.json"

func TestVerify(t *testing.T) {
	var ruleSet RuleSet
	ruleSetRaw, err := ioutil.ReadFile(parseRulesetTestFile)
	if err != nil {
		t.Errorf("Cannot read test file %v", parseRulesetTestFile)
	}
	err = json.Unmarshal(ruleSetRaw, &ruleSet)
	expected := map[string]bool{
		"Broken AND() rule at key spec.replicas in deny rule":                                                                                            false,
		"Duplicate resource in test_files/verifier_test_verify_folder/service/sample.json with namespace 'service' and name 'service-containerB-config'": false,
	}
	result := Verify(ruleSet, verifyTestFolder)
	for _, err := range result {
		found := false
		for errString, encountered := range expected {
			if err.Error() == errString {
				if !encountered {
					expected[errString] = true
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected %v, got %v when verifying %v with ruleset %v", expected, result, verifyTestFolder, parseRulesetTestFile)
			break
		}
	}
	for errString, encountered := range expected {
		if !encountered {
			t.Errorf("Did not encounter expected error %v when verifying %v with ruleset %v", errString, verifyTestFolder, parseRulesetTestFile)
		}
	}

}

func TestVerifyFileWithRule(t *testing.T) {

}

func TestParseFile(t *testing.T) {

}

func TestVerifyResources(t *testing.T) {

}

func TestVerifyResourcesTraverseHelper(t *testing.T) {

}

func TestApplyRule(t *testing.T) {
	var testCases = make([]ApplyRuleArgObj, 0)
	testCasesRaw, err := ioutil.ReadFile(applyRuleTestFile)
	if err != nil {
		t.Errorf("Cannot read test file %v", applyRuleTestFile)
	}
	err = json.Unmarshal(testCasesRaw, &testCases)
	if err != nil {
		t.Errorf("Error when unmarshalling test file %v", checkRuleTestFile)
	}

	tagMap = map[string]string{
		"valid_tag": "service",
	}
	for _, testCase := range testCases {
		result := applyRule(testCase.Rule, testCase.Key, testCase.Val, testCase.PathVars, testCase.Allow)
		if len(result) != len(testCase.Result) {
			t.Errorf("Expected %v, got %v when running this test case: %v", testCase.Result, result, testCase)
		} else {
			for _, err := range result {
				found := false
				for _, errString := range testCase.Result {
					if err.Error() == errString {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected %v, got %v when running this test case: %v", testCase.Result, result, testCase)
					break
				}
			}
		}
	}
}

func TestCheckRule(t *testing.T) {
	var testCases = make([]CheckRuleArgObj, 0)
	testCasesRaw, err := ioutil.ReadFile(checkRuleTestFile)
	if err != nil {
		t.Errorf("Cannot read test file %v", checkRuleTestFile)
	}
	err = json.Unmarshal(testCasesRaw, &testCases)
	if err != nil {
		t.Errorf("Error when unmarshalling test file %v", checkRuleTestFile)
	}

	tagMap = map[string]string{
		"valid_tag": "service",
	}
	for _, testCase := range testCases {
		result := checkRule(testCase.Rule, testCase.Val, testCase.PathVars)
		if result != testCase.Result {
			t.Errorf("Expected %v, got %v when running this test case: %v", testCase.Result, result, testCase)
		}
	}

}

func TestParseRuleset(t *testing.T) {
	var expected RuleSet
	expectedRaw, err := ioutil.ReadFile(parseRulesetTestFile)
	if err != nil {
		t.Errorf("Cannot read test file %v", parseRulesetTestFile)
	}
	err = json.Unmarshal(expectedRaw, &expected)
	if err != nil {
		t.Errorf("Error when unmarshalling test file %v", parseRulesetTestFile)
	}
	viper.BindEnv("gopath", "GOPATH")
	result := ParseRuleset(parseRulesetTestJsonnet)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v when parsing test jsonnet: %v", expected, result, parseRulesetTestJsonnet)
	}
}
