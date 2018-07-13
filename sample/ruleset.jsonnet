{
  rules: [
    {
      regex: "sample.json",
      kind: "Deployment",
      ruleTree: {
        spec: {
          replicas: AND(LT(2), GT(25))
        },
      },
    },
    {
      regex: ".*namespace.json",
      kind: "Namespace",
      ruleTree: {
        metadata: {
          labels: {
            name: [
              TAG("namespace"),
              PATH(1)
            ]
          },
          name: TAG("namespace")
        },
      },
    },
  ]
}
