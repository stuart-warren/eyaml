package eyaml

import (
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

func (e EyamlPkcs7) DecryptYaml(r io.Reader) (yaml.Node, error) {
	dec := yaml.NewDecoder(r)
	var doc yaml.Node
	err := dec.Decode(&doc)
	if err != nil {
		return doc, err
	}

	return doc, nil
}

func (e EyamlPkcs7) DecryptYamlNode(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode {
		for i, n := range node.Content {
			node.Content[i] = e.DecryptYamlNode(n)
		}
	}
	if node.Kind == yaml.SequenceNode {
		for i, n := range node.Content {
			node.Content[i] = e.DecryptYamlNode(n)
		}
	}
	if node.Kind == yaml.MappingNode {
		for i, n := range node.Content {
			node.Content[i] = e.DecryptYamlNode(n)
		}
		e.DecryptYamlNodeContent(node.Content)
	}
	return node
}

func (e EyamlPkcs7) DecryptYamlNodeContent(node []*yaml.Node) {
	for i, n := range node {
		if strings.HasPrefix(n.Value, "ENC[PKCS7,") && strings.HasSuffix(n.Value, "]") {
			payload := []byte(n.Value[9 : len(n.Value)-1])
			decrypted, err := e.DecryptBytes(payload)
			if err != nil {
				panic(err)
			}
			node[i].Value = string(decrypted)
		}
	}
}
