
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

