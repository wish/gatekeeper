{
  rules: [
    {
      regex: "sample.json",
      kind: "Deployment",
      type: "deny",
      ruleTree: {
        spec: {
          replicas: AND(GT(2), LT(25))
        },
      },
    },
    {
      regex: "sample.json",
      kind: "Deployment",
      type: "allow",
      ruleTree: {
        spec: {
          replicas: AND(GT(2), LT(25))
        },
      },
    },
    {
      regex: ".*namespace.json",
      kind: "Namespace",
      type: "allow",
      ruleTree: {
        metadata: {
          labels: {
            name: AND(TAG("namespace"), PATH(1))
          },
          name: TAG("namespace")
        },
      },
    },
    {
      regex: ".*.json",
      kind: "RoleBinding",
      type: "deny",
      ruleTree: {},
    },
  ]
}
