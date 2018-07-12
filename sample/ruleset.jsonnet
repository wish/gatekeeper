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
  ]
}
