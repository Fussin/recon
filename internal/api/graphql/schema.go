package graphql

import (
	"github.com/graphql-go/graphql"
)

// Schema is the GraphQL schema.
var Schema, _ = graphql.NewSchema(graphql.SchemaConfig{
	Query:    queryType,
	Mutation: mutationType,
})

var vulnerabilityType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Vulnerability",
	Fields: graphql.Fields{
		"id":          &graphql.Field{Type: graphql.Int},
		"scan_id":     &graphql.Field{Type: graphql.Int},
		"plugin":      &graphql.Field{Type: graphql.String},
		"description": &graphql.Field{Type: graphql.String},
		"severity":    &graphql.Field{Type: graphql.String},
		"created_at":  &graphql.Field{Type: graphql.String},
		"updated_at":  &graphql.Field{Type: graphql.String},
	},
})

var queryType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Query",
	Fields: graphql.Fields{
		"vulnerability": &graphql.Field{
			Type:        vulnerabilityType,
			Description: "Get a vulnerability by ID.",
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.Int),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				// ...
				return nil, nil
			},
		},
		"vulnerabilities": &graphql.Field{
			Type:        graphql.NewList(vulnerabilityType),
			Description: "Get all vulnerabilities.",
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				// ...
				return nil, nil
			},
		},
	},
})

var mutationType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Mutation",
	Fields: graphql.Fields{
		"createVulnerability": &graphql.Field{
			Type:        vulnerabilityType,
			Description: "Create a new vulnerability.",
			Args: graphql.FieldConfigArgument{
				"scan_id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.Int),
				},
				"plugin": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
				"description": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
				"severity": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				// ...
				return nil, nil
			},
		},
	},
})
