package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/goccy/go-yaml"
	"github.com/open-policy-agent/opa/rego"
	"io/ioutil"
	"log"
	"os"
)

// This is POC code
func main() {
	ctx := context.Background()

	module, err := readFile("policy.rego")
	if err != nil {
		log.Fatal(err)
	}

	query, err := rego.New(
		rego.Query("x = data"),
		rego.Module("policy.rego", string(module)),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatal(err)
	}

	yml, err := readFile("input.yml")
	if err != nil {
		log.Fatal(err)
	}

	var input map[string]interface{}
	if err := yaml.Unmarshal(yml, &input); err != nil {
		log.Fatal(err)
	}

	eval, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
	}

	for _, result := range eval {
		for _, binding := range result.Bindings {
			body, err := json.MarshalIndent(binding, "", "  ")
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(body))
		}
	}

}

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	all, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return all, nil
}
