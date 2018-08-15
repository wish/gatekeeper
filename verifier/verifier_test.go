package verifier

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/gobuffalo/packr"
)

type CheckRuleArgObj struct {
	Rule     map[string]interface{}
	Val      interface{}
	PathVars []string
	Result   bool
}

type ApplyRuleArgObj struct {
	Rule       map[string]interface{}
	Key        string
	Val        interface{}
	PathVars   []string
	Allow      bool
	Result     []string
	ErrDetails []map[string]interface{}
	FullError  []string
}

type VerifyArgObj struct {
	Result     []string
	ErrDetails []map[string]interface{}
	FullError  []string
}

var verifyTestFolder = "test_files/verifier_test_verify_folder/service"
var verifyTestFile = "test_files/verifier_test_verify_rule.json"
var checkRuleTestFile = "test_files/verifier_test_check_rule.json"
var applyRuleTestFile = "test_files/verifier_test_apply_rule.json"
var parseRulesetTestJsonnet = "test_files/verifier_test_parse_ruleset.jsonnet"
var parseRulesetTestFile = "test_files/verifier_test_parse_ruleset.json"

func TestVerify(t *testing.T) {
	//Parse ruleset
	var ruleSet RuleSet
	ruleSetRaw, err := ioutil.ReadFile(parseRulesetTestFile)
	if err != nil {
		t.Errorf("Cannot read ruleset file %v", parseRulesetTestFile)
		return
	}
	err = json.Unmarshal(ruleSetRaw, &ruleSet)
	if err != nil {
		t.Errorf("Error when unmarshalling ruleset file %v: %v", parseRulesetTestFile, err)
		return
	}

	//Parse expected results
	var expectedResults VerifyArgObj
	expectedResultsRaw, err := ioutil.ReadFile(verifyTestFile)
	if err != nil {
		t.Errorf("Cannot read test file %v", verifyTestFile)
		return
	}
	err = json.Unmarshal(expectedResultsRaw, &expectedResults)
	if err != nil {
		t.Errorf("Error when unmarshalling test file %v: %v", verifyTestFile, err)
		return
	}

	for i, errString := range expectedResults.Result {
		errDetails, _ := json.MarshalIndent(expectedResults.ErrDetails[i], "", "	")
		fullErrString := fmt.Sprintf(errString, string(errDetails))
		expectedResults.FullError = append(expectedResults.FullError, fullErrString)
	}

	result := Verify(ruleSet, verifyTestFolder)
	if len(result) != len(expectedResults.FullError) {
		t.Errorf("Expected \n%v\nbut got \n%v\nwhen verifying %v with ruleset %v", expectedResults.FullError, result, verifyTestFolder, parseRulesetTestFile)
	} else {
		for _, err := range result {
			found := false
			for _, fullErr := range expectedResults.FullError {
				if regexp.MustCompile("/\\s/g").ReplaceAllString(err.Error(), "") == regexp.MustCompile("/\\s/g").ReplaceAllString(fullErr, "") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected \n%v\nbut got \n%v\nwhen verifying %v with ruleset %v", expectedResults.FullError, result, verifyTestFolder, parseRulesetTestFile)
				break
			}
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
		return
	}
	err = json.Unmarshal(testCasesRaw, &testCases)
	if err != nil {
		t.Errorf("Error when unmarshalling test file %v: %v", applyRuleTestFile, err)
		return
	}

	for c, testCase := range testCases {
		for i, errString := range testCase.Result {
			if i < len(testCase.ErrDetails) {
				errDetails, err := json.MarshalIndent(testCase.ErrDetails[i], "", "	")
				if err != nil {
					t.Errorf("Error when marshalling error details in file %v: %v", applyRuleTestFile, err)
					return
				}
				fullErrString := fmt.Sprintf(errString, string(errDetails))
				testCases[c].FullError = append(testCases[c].FullError, fullErrString)
			} else {
				testCases[c].FullError = append(testCases[c].FullError, errString)
			}
		}
	}

	tagMap := map[string]string{
		"valid_tag": "service",
	}
	for _, testCase := range testCases {
		result := applyRule(testCase.Rule, testCase.Key, testCase.Val, testCase.PathVars, tagMap, testCase.Allow)
		if len(result) != len(testCase.Result) {
			t.Errorf("Expected \n%v\nbut got \n%v\nwhen running this test case: %v", testCase.FullError, result, testCase)
		} else {
			for _, err := range result {
				found := false
				for _, fullErr := range testCase.FullError {
					if regexp.MustCompile("/\\s/g").ReplaceAllString(err.Error(), "") == regexp.MustCompile("/\\s/g").ReplaceAllString(fullErr, "") {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected \n%v\nbut got \n%v\nwhen running this test case: %v", testCase.FullError, result, testCase)
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
		return
	}
	err = json.Unmarshal(testCasesRaw, &testCases)
	if err != nil {
		t.Errorf("Error when unmarshalling test file %v: %v", checkRuleTestFile, err)
		return
	}

	tagMap := map[string]string{
		"valid_tag": "service",
	}
	for _, testCase := range testCases {
		result := checkRule(testCase.Rule, testCase.Val, testCase.PathVars, tagMap)
		if result != testCase.Result {
			t.Errorf("Expected \n%v\nbut got \n%v\nwhen running this test case: %v", testCase.Result, result, testCase)
		}
	}

}

func TestParseRuleset(t *testing.T) {
	var expected RuleSet
	expectedRaw, err := ioutil.ReadFile(parseRulesetTestFile)
	if err != nil {
		t.Errorf("Cannot read test file %v", parseRulesetTestFile)
		return
	}
	err = json.Unmarshal(expectedRaw, &expected)
	if err != nil {
		t.Errorf("Error when unmarshalling test file %v: %v", parseRulesetTestFile, err)
		return
	}
	// Get gatekeeper function definitions
	box := packr.NewBox("../function_definitions")
	gatekeeperFunctions, err := box.MustString("gatekeeper.jsonnet")
	if err != nil {
		fmt.Println("Error: Could not get gatekeeper.jsonnet from packr.")
		os.Exit(1)
	}
	result := ParseRuleset(parseRulesetTestJsonnet, gatekeeperFunctions)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v when parsing test jsonnet: %v", expected, result, parseRulesetTestJsonnet)
	}
}
