{
  rules: [
    {
      regex: "sample.json",
      kind: "Deployment",
      ruleTree: {
        spec: {
          replicas: AND(GT(2), LT(25))
        },
      },
    },
    {
      regex: ".*namespace.json",
      kind: "Namespace",
      ruleTree: {
        metadata: {
          labels: {
            name: AND(TAG("namespace"), PATH(1))
          },
          name: TAG("namespace")
        },
      },
    },
  ]
}
