{
  ignore: ["channel.yaml"],
  rules: [
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
  ]
}
