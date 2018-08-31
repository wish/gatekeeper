# Gatekeeper

[![Build Status](https://travis-ci.org/wish/gatekeeper.svg?branch=master)](https://travis-ci.org/wish/gatekeeper)
[![Docker Repository on Quay](https://quay.io/repository/wish/gatekeeper/status "Docker Repository on Quay")](https://quay.io/repository/wish/gatekeeper)

`gatekeeper` is a tool for verifying Kubernetes configuration files against custom rules defined in a Jsonnet ruleset. It will return a list of errors it encounters while verifying the files.

```
$ gatekeeper -r sample/ruleset.jsonnet sample/service
1. Broken LT() rule: 
{
	"actual": 24,
	"expected": 20,
	"key": "spec.replicas",
	"path": "sample/service/sample.json",
	"rule_type": "allow"
}
```


## Building

First install [dep](https://github.com/golang/dep) and run `dep ensure`. Then run `make` to build a binary inside `$GOPATH/bin`.

```
$ dep ensure
$ make
```


## Ruleset Layout

Gatekeeper requires a jsonnet file that defines the rules you want to apply. The jsonnet file must be in the format of:

```
{
    ignore: ["somefile.yaml"],
    rules: [
        {
            regex: "file.json",
            kind: "Deployment",
            type: "allow",
            ruleTree: {
                ...
            }
        },
        ...
    ]
}
```

`ignore` contains filenames that gatekeeper will ignore.

`rules` is an array of rule objects. Each rule object has 4 required keys. 


`regex` matches the files that this rule will apply to. `gatekeeper` will check the regex on the filename of each file.

`kind` matches the kind of resources that this rule will apply to.

`type` can be either `allow` or `deny`. An allow rule will pass if no functions are broken. A deny rule will produce an error if any of the functions pass.

`ruleTree` defines the actual content of the rule in a json object. It follows the same layout as the resource kind that it's applied to. You can use ruleset functions to check the values of specific fields in the resource. See the sample ruleset.jsonnet for examples.



## Ruleset Functions

There are a variety of functions you can use in you ruleset jsonnet to check values in your Kubernetes configuration:


#### LT()

LT() is used to verify that the field in the configuration is less than the specified number

```
...
    spec: {
        replicas: LT(3)
    }
...
```

#### GT()

GT() is used to verify that the field in the configuration is greater than the specified number

```
...
    spec: {
        replicas: GT(0)
    }
...
```

#### EQ()

EQ() is used to verify that the field in the configuration is equal to the specified value

```
...
    metadata: {
        name: EQ("service")
    }
...
```

#### AND()

AND() is used to verify that both of its child functions are valid.

```
...
    spec: {
        replicas: AND(GT(0), LT(30))
    }
...
```

#### OR()

OR() is used to verify that at least one of its child functions are valid

```
...
    metadata: {
        name: OR(EQ("serviceA"), EQ("serviceB"))
    }
...
```

#### NOT()

NOT() is used to verify that its child functions is not valid

```
...
    spec: {
        replicas: NOT(EQ(7))
    }
...
```

#### TAG()

TAG() is used to verify that all fields in the configuration with the same tag in their TAG() function has the same value

```
...
    metadata: {
        labels: {
            name: TAG("namespace")
        },
        name: TAG("namespace") 
    }
...
```

#### PATH()

PATH() is used to verify that the field in the configuration is equal to the section of the file path indicated by the index.

Verifying file /path/to/file:

```
...
    metadata: {
        name: PATH(0) //verify name == "file",
        name2: PATH(1) //verify name2 == "to",
        name3: PATH(2) //verify name3 == "path"
    }
...
```


## Contributing

If you would have any suggestions, improvements, or bugs please open issues [here](https://github.com/wish/gatekeeper/issues).
If you would like to contribute to gatekeeper, please make a pull request.
