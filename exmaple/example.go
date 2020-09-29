package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"log"
)

func main() {
	module := `
package example.authz

default allow = false

allow {
    some id
    input.method = "GET"
    input.path = ["salary", id]
    input.subject.user = id
}

allow {
    is_admin
}

is_admin {
    input.subject.groups[_] == "admin1"
}
`
	ctx := context.Background()

	query, err := rego.New(
		rego.Query("x = data.example.authz.allow"),
		rego.Module("example.rego", module),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatal(err)
	}

	input := map[string]interface{}{
		"method": "GET",
		"path":   []interface{}{"salary", "bob"},
		"subject": map[string]interface{}{
			"user":   "bob",
			"groups": []interface{}{"sales", "marketing"},
		},
	}

	eval, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
	}

	for _, result := range eval {
		fmt.Printf("result bindings: %+v\n", result.Bindings) // eval: {Expressions:[true] Bindings:map[x:true]}
	}

}
