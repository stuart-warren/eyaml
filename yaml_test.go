package eyaml_test

import (
	"bytes"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

var ydoc = []byte(`
---
key1:
    key2: value2
    key3: value3
`)

func TestYamlDecrypt(t *testing.T) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewBuffer(ydoc))
	err := dec.Decode(&doc)
	if err != nil {
		t.Errorf("couldn't decode yaml: %v", err)
	}
	fmt.Printf("%+v\n", doc)
	for _, content := range doc.Content {
		fmt.Printf("%+v\n", content)
		for _, content := range content.Content {
			fmt.Printf("%+v\n", content)
		}
	}
}
