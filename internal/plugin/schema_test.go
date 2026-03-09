package plugin

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

// Schema conformance tests verify that Go types match the JSON Schema
// at docs/plugin-protocol.schema.json. This catches drift between the
// Go implementation and the formal protocol specification.

const schemaPath = "../../docs/plugin-protocol.schema.json"

// schemaDoc is a partial representation of the JSON Schema for validation.
type schemaDoc struct {
	Defs map[string]schemaDef `json:"$defs"`
}

type schemaDef struct {
	Type       string                `json:"type"`
	Required   []string              `json:"required"`
	Properties map[string]schemaProp `json:"properties"`
	Enum       []string              `json:"enum"`
	OneOf      []json.RawMessage     `json:"oneOf"`
}

type schemaProp struct {
	Type json.RawMessage `json:"type"` // string or array of strings
	Ref  string          `json:"$ref"`
}

func loadSchema(t *testing.T) schemaDoc {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc schemaDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	return doc
}

// jsonFieldNames returns the json tag names for a struct type.
func jsonFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool)
	for field := range t.Fields() {
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		names[name] = true
	}
	return names
}

// TestSchema_ValidJSON verifies the schema file is valid JSON.
func TestSchema_ValidJSON(t *testing.T) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("schema is not valid JSON")
	}
}

// TestSchema_RequestFieldsMatch verifies that the Go Request struct fields
// match the evaluateRequest schema properties.
func TestSchema_RequestFieldsMatch(t *testing.T) {
	doc := loadSchema(t)
	evalReq, ok := doc.Defs["evaluateRequest"]
	if !ok {
		t.Fatal("schema missing $defs/evaluateRequest")
	}

	goFields := jsonFieldNames(reflect.TypeFor[Request]())
	schemaFields := make(map[string]bool)
	for name := range evalReq.Properties {
		schemaFields[name] = true
	}

	for name := range goFields {
		if !schemaFields[name] {
			t.Errorf("Go Request field %q not in schema evaluateRequest", name)
		}
	}
	for name := range schemaFields {
		if !goFields[name] {
			t.Errorf("schema evaluateRequest property %q not in Go Request struct", name)
		}
	}
}

// TestSchema_ResultFieldsMatch verifies that the Go Result struct fields
// match the evaluateResult block schema properties.
func TestSchema_ResultFieldsMatch(t *testing.T) {
	doc := loadSchema(t)
	evalResult, ok := doc.Defs["evaluateResult"]
	if !ok {
		t.Fatal("schema missing $defs/evaluateResult")
	}

	// evaluateResult uses oneOf [null, object]. Find the object variant.
	var blockSchema schemaDef
	for _, raw := range evalResult.OneOf {
		var s schemaDef
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		if s.Type == "object" {
			blockSchema = s
			break
		}
	}
	if blockSchema.Properties == nil {
		t.Fatal("schema evaluateResult has no object variant")
	}

	goFields := jsonFieldNames(reflect.TypeFor[Result]())
	schemaFields := make(map[string]bool)
	for name := range blockSchema.Properties {
		schemaFields[name] = true
	}

	for name := range goFields {
		if !schemaFields[name] {
			t.Errorf("Go Result field %q not in schema evaluateResult", name)
		}
	}
	for name := range schemaFields {
		if !goFields[name] {
			t.Errorf("schema evaluateResult property %q not in Go Result struct", name)
		}
	}
}

// TestSchema_RuleSnapshotFieldsMatch verifies that the Go RuleSnapshot struct
// fields match the schema ruleSnapshot properties.
func TestSchema_RuleSnapshotFieldsMatch(t *testing.T) {
	doc := loadSchema(t)
	ruleDef, ok := doc.Defs["ruleSnapshot"]
	if !ok {
		t.Fatal("schema missing $defs/ruleSnapshot")
	}

	goFields := jsonFieldNames(reflect.TypeFor[RuleSnapshot]())
	schemaFields := make(map[string]bool)
	for name := range ruleDef.Properties {
		schemaFields[name] = true
	}

	for name := range goFields {
		if !schemaFields[name] {
			t.Errorf("Go RuleSnapshot field %q not in schema ruleSnapshot", name)
		}
	}
	for name := range schemaFields {
		if !goFields[name] {
			t.Errorf("schema ruleSnapshot property %q not in Go RuleSnapshot struct", name)
		}
	}
}

// TestSchema_InitParamsFieldsMatch verifies InitParams fields match.
func TestSchema_InitParamsFieldsMatch(t *testing.T) {
	doc := loadSchema(t)
	initDef, ok := doc.Defs["initParams"]
	if !ok {
		t.Fatal("schema missing $defs/initParams")
	}

	goFields := jsonFieldNames(reflect.TypeFor[InitParams]())
	schemaFields := make(map[string]bool)
	for name := range initDef.Properties {
		schemaFields[name] = true
	}

	for name := range goFields {
		if !schemaFields[name] {
			t.Errorf("Go InitParams field %q not in schema initParams", name)
		}
	}
	for name := range schemaFields {
		if !goFields[name] {
			t.Errorf("schema initParams property %q not in Go InitParams struct", name)
		}
	}
}

// TestSchema_SeverityEnumMatch verifies the schema severity enum matches ValidSeverities.
func TestSchema_SeverityEnumMatch(t *testing.T) {
	doc := loadSchema(t)
	sevDef, ok := doc.Defs["severity"]
	if !ok {
		t.Fatal("schema missing $defs/severity")
	}

	for _, s := range sevDef.Enum {
		if !rules.ValidSeverities[rules.Severity(s)] {
			t.Errorf("schema severity enum %q not in Go ValidSeverities", s)
		}
	}
	for s := range rules.ValidSeverities {
		if !slices.Contains(sevDef.Enum, string(s)) {
			t.Errorf("Go ValidSeverities %q not in schema severity enum", s)
		}
	}
}

// TestSchema_ActionEnumMatch verifies the schema action enum matches the rules action constants.
func TestSchema_ActionEnumMatch(t *testing.T) {
	doc := loadSchema(t)
	actDef, ok := doc.Defs["action"]
	if !ok {
		t.Fatal("schema missing $defs/action")
	}

	validActions := map[rules.Action]bool{
		rules.ActionBlock: true,
		rules.ActionLog:   true,
		rules.ActionAlert: true,
	}

	for _, a := range actDef.Enum {
		if !validActions[rules.Action(a)] {
			t.Errorf("schema action enum %q not in Go action constants", a)
		}
	}
	for a := range validActions {
		if !slices.Contains(actDef.Enum, string(a)) {
			t.Errorf("Go action constant %q not in schema action enum", a)
		}
	}
}

// TestSchema_MethodConstants verifies the schema wireRequest methods match Go constants.
func TestSchema_MethodConstants(t *testing.T) {
	doc := loadSchema(t)
	wireDef, ok := doc.Defs["wireRequest"]
	if !ok {
		t.Fatal("schema missing $defs/wireRequest")
	}

	goMethods := map[string]bool{
		MethodInit:     true,
		MethodEvaluate: true,
		MethodClose:    true,
	}

	// Extract method constants from oneOf variants.
	type methodConst struct {
		Properties struct {
			Method struct {
				Const string `json:"const"`
			} `json:"method"`
		} `json:"properties"`
	}

	var schemaMethods []string
	for _, raw := range wireDef.OneOf {
		var mc methodConst
		if err := json.Unmarshal(raw, &mc); err != nil {
			continue
		}
		if mc.Properties.Method.Const != "" {
			schemaMethods = append(schemaMethods, mc.Properties.Method.Const)
		}
	}

	for _, m := range schemaMethods {
		if !goMethods[m] {
			t.Errorf("schema method %q not in Go constants", m)
		}
	}
	for m := range goMethods {
		if !slices.Contains(schemaMethods, m) {
			t.Errorf("Go method constant %q not in schema wireRequest", m)
		}
	}
}

// TestSchema_RoundTrip_Request verifies a Go Request marshals to JSON that
// contains all schema-required fields.
func TestSchema_RoundTrip_Request(t *testing.T) {
	doc := loadSchema(t)
	evalReq := doc.Defs["evaluateRequest"]

	req := Request{
		ToolName:   "Bash",
		Arguments:  json.RawMessage(`{"command":"ls"}`),
		Operation:  rules.OpExecute,
		Operations: []rules.Operation{rules.OpExecute, rules.OpRead},
		Command:    "ls",
		Paths:      []string{"/home/user"},
		Hosts:      []string{"example.com"},
		Content:    "test",
		Evasive:    true,
		Rules: []RuleSnapshot{{
			Name:     "r1",
			Source:   rules.SourceBuiltin,
			Severity: rules.SeverityCritical,
			Priority: 10,
			Message:  "blocked",
			Locked:   true,
			Enabled:  true,
			HitCount: 5,
		}},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	json.Unmarshal(data, &m)

	for _, field := range evalReq.Required {
		if _, ok := m[field]; !ok {
			t.Errorf("required field %q missing from marshaled Request", field)
		}
	}
}

// TestSchema_ResultRequiredFieldsNonEmpty verifies that the schema requires
// non-empty rule_name and message (minLength: 1), matching Go's Result.Validate().
func TestSchema_ResultRequiredFieldsNonEmpty(t *testing.T) {
	doc := loadSchema(t)
	evalResult, ok := doc.Defs["evaluateResult"]
	if !ok {
		t.Fatal("schema missing $defs/evaluateResult")
	}

	// Find the block (object) variant
	type propWithMinLen struct {
		Type      string `json:"type"`
		MinLength *int   `json:"minLength"`
	}
	type objSchema struct {
		Type       string                    `json:"type"`
		Properties map[string]propWithMinLen `json:"properties"`
	}

	for _, raw := range evalResult.OneOf {
		var s objSchema
		if err := json.Unmarshal(raw, &s); err != nil || s.Type != "object" {
			continue
		}
		for _, field := range []string{"rule_name", "message"} {
			prop, ok := s.Properties[field]
			if !ok {
				t.Errorf("schema evaluateResult missing %q property", field)
				continue
			}
			if prop.MinLength == nil || *prop.MinLength < 1 {
				t.Errorf("schema evaluateResult.%s should have minLength >= 1 (matching Go Result.Validate)", field)
			}
		}
		return
	}
	t.Fatal("schema evaluateResult has no object variant")
}

// TestSchema_RoundTrip_WireRequest verifies WireRequest marshals correctly.
func TestSchema_RoundTrip_WireRequest(t *testing.T) {
	for _, method := range []string{MethodInit, MethodEvaluate, MethodClose} {
		t.Run(method, func(t *testing.T) {
			var params json.RawMessage
			switch method {
			case MethodInit:
				params, _ = json.Marshal(InitParams{Name: "test", Config: json.RawMessage(`{}`)})
			case MethodEvaluate:
				params, _ = json.Marshal(Request{ToolName: "Bash", Operation: rules.OpExecute, Arguments: json.RawMessage(`{}`)})
			case MethodClose:
				// no params
			}

			wireReq := WireRequest{Method: method, Params: params}
			data, err := json.Marshal(wireReq)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var m map[string]any
			json.Unmarshal(data, &m)

			if m["method"] != method {
				t.Errorf("method = %v, want %v", m["method"], method)
			}
		})
	}
}
