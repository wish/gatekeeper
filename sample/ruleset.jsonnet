{
  rules: [
    {
      regex: "sample.json",
      kind: "Deployment",
      ruleTree: {
        spec: {
          replicas: LT(24),
        },
      },
    },
  ]
}
