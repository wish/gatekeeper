
// LT() checks if the selected field is less than the given value
local LT(value=0) = {
  gatekeeper: true,
  operation: "<",
  value: value
};

// GT() checks if the selected field is greater than the given value
local GT(value=0) = {
  gatekeeper: true,
  operation: ">",
  value: value
};

// EQ() checks if the selected field is equal to the given value
local EQ(value="") = {
  gatekeeper: true,
  operation: "=",
  value: value
};

// AND() checks if both op1 and op2 are satisfied
local AND(op1, op2) = {
  gatekeeper: true,
  operation: "&",
  op1: op1,
  op2: op2,
};

// OR() checks if one of op1 or op2 is satisfied
local OR(op1, op2) = {
  gatekeeper: true,
  operation: "|",
  op1: op1,
  op2: op2,
};

// NOT() checks if op is not satisfied
local NOT(op) = {
  gatekeeper: true,
  operation: "!",
  op: op,
};

// TAG() verifies that all TAG() with the same tag have the same value
local TAG(tag) = {
  gatekeeper: true,
  operation: "tag",
  tag: tag,
};
