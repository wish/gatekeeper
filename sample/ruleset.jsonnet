{
  rules: [
    {
      regex: "sample.json",
      kind: "Deployment",
      ruleTree: {
        spec: {
          replicas: GT(0)
        },
      },
    },
    {
      regex: ".*namespace.json",
      kind: "Namespace",
      ruleTree: {
        metadata: {
          labels: {
            name: TAG("namespace")
          },
          name: TAG("namespace")
        },
      },
    },
  ]
}
