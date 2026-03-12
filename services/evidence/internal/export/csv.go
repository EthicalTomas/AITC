package export

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"reflect"
)

// MarshalCSV serialises the artifact Records field to a CSV byte slice.
//
// Records must be a slice of structs or a slice of maps[string]string.
// Each exported struct field becomes a column, using the json struct tag as the
// header name (falling back to the field name).
// If Records is nil or an empty slice the function returns a header-only CSV.
func MarshalCSV(a *Artifact) ([]byte, error) {
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)

	if a.Records == nil {
		_ = w.Write([]string{"control_id", "tenant_id", "period_start", "period_end"})
		w.Flush()
		return buf.Bytes(), w.Error()
	}

	rv := reflect.ValueOf(a.Records)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Slice {
		return nil, fmt.Errorf("csv export: Records must be a slice, got %T", a.Records)
	}
	if rv.Len() == 0 {
		w.Flush()
		return buf.Bytes(), w.Error()
	}

	// Derive headers from the first element.
	first := rv.Index(0)
	if first.Kind() == reflect.Ptr {
		first = first.Elem()
	}
	if first.Kind() != reflect.Struct {
		return nil, fmt.Errorf("csv export: slice elements must be structs, got %s", first.Kind())
	}

	headers, fields := structHeaders(first.Type())
	if err := w.Write(headers); err != nil {
		return nil, fmt.Errorf("csv export: write header: %w", err)
	}

	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i)
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}
		row := make([]string, len(fields))
		for j, f := range fields {
			row[j] = fmt.Sprintf("%v", elem.FieldByIndex(f.Index).Interface())
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("csv export: write row %d: %w", i, err)
		}
	}

	w.Flush()
	return buf.Bytes(), w.Error()
}

type fieldInfo struct {
	Index []int
	Name  string
}

// structHeaders returns column headers and field metadata for a struct type.
// It uses the "json" tag if present, otherwise falls back to the Go field name.
// Unexported fields and fields tagged `json:"-"` are skipped.
func structHeaders(t reflect.Type) ([]string, []fieldInfo) {
	var headers []string
	var fields []fieldInfo
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if tag != "" {
			// strip omitempty and similar options
			for j, c := range tag {
				if c == ',' {
					tag = tag[:j]
					break
				}
			}
			if tag != "" {
				name = tag
			}
		}
		headers = append(headers, name)
		fields = append(fields, fieldInfo{Index: f.Index, Name: name})
	}
	return headers, fields
}

