package parser

import (
	"fmt"
	"io"
	"os"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

func ParseNamespaces(path string) (map[string]bool, error) {
	objs, err := ParseObjectsFromFile(path)
	if err != nil {
		return nil, err
	}

	ret := map[string]bool{}
	for _, obj := range objs {
		switch o := obj.(type) {
		case *v1.Namespace:
			if o.Name != o.Labels["name"] {
				return nil, fmt.Errorf(".name (%v) and .labels[name] (%v) have to be equal", o.Name, o.Labels["name"])
			}
			_, ok := ret[o.Name]
			if ok {
				return nil, fmt.Errorf("namespace %v cannot be declared twice", o.Name)
			}
			ret[o.Name] = true
		default:
			// return nil, fmt.Errorf("only Namespace is allowed found: %v", obj.GetObjectKind().GroupVersionKind().Kind)
		}
	}
	return ret, nil
}

func ParseObjectsFromFile(path string) ([]runtime.Object, error) {
	ret := []runtime.Object{}
	decode := scheme.Codecs.UniversalDeserializer().Decode

	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	d := yaml.NewDocumentDecoder(f)
	out := []byte{}
	for {
		b := make([]byte, 1)
		_, err := d.Read(b)
		out = append(out, b...)
		if err == nil {
			obj, _, err := decode(out, nil, nil)
			if err != nil {
				return nil, err
			}
			ret = append(ret, obj)
			out = []byte{}
		}
		if err == io.EOF {
			d.Close()
			break
		}
	}
	return ret, nil
}
