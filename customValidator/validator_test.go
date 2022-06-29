// Copyright 2020 Gin Core Team. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package customValidator

import (
	"errors"
	"fmt"
	"testing"
)

func TestSliceValidationError(t *testing.T) {
	tests := []struct {
		name string
		err  SliceValidationError
		want string
	}{
		{"has nil elements", SliceValidationError{errors.New("test error"), nil}, "[0]: test error"},
		{"has zero elements", SliceValidationError{}, ""},
		{"has one element", SliceValidationError{errors.New("test one error")}, "[0]: test one error"},
		{"has two elements",
			SliceValidationError{
				errors.New("first error"),
				errors.New("second error"),
			},
			"[0]: first error\n[1]: second error",
		},
		{"has many elements",
			SliceValidationError{
				errors.New("first error"),
				errors.New("second error"),
				nil,
				nil,
				nil,
				errors.New("last error"),
			},
			"[0]: first error\n[1]: second error\n[5]: last error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("SliceValidationError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultValidator(t *testing.T) {
	type exampleStruct struct {
		A string `binding:"max=8"`
		B int    `binding:"gt=0"`
	}
	type exampleMold struct {
		A string `binding:"max=8" mod:"default=bob"`
		B int    `binding:"gt=0"`
	}
	tests := []struct {
		name    string
		v       *CustomValidator
		obj     any
		wantErr bool
	}{
		{"validate nil obj", &CustomValidator{}, nil, false},                                                  // 0
		{"validate int obj", &CustomValidator{}, 3, false},                                                    // 1
		{"validate struct failed-1", &CustomValidator{}, exampleStruct{A: "123456789", B: 1}, true},           // 2
		{"validate struct failed-2", &CustomValidator{}, exampleStruct{A: "12345678", B: 0}, true},            // 3
		{"validate struct passed", &CustomValidator{}, exampleStruct{A: "12345678", B: 1}, false},             // 4 *
		{"validate *struct failed-1", &CustomValidator{}, &exampleStruct{A: "123456789", B: 1}, true},         // 5
		{"validate *struct failed-2", &CustomValidator{}, &exampleStruct{A: "12345678", B: 0}, true},          // 6
		{"validate *struct passed", &CustomValidator{}, &exampleStruct{A: "12345678", B: 1}, false},           // 7 *
		{"validate []struct failed-1", &CustomValidator{}, []exampleStruct{{A: "123456789", B: 1}}, true},     // 8
		{"validate []struct failed-2", &CustomValidator{}, []exampleStruct{{A: "12345678", B: 0}}, true},      // 9
		{"validate []struct passed", &CustomValidator{}, []exampleStruct{{A: "12345678", B: 1}}, false},       // 10 *
		{"validate []*struct failed-1", &CustomValidator{}, []*exampleStruct{{A: "123456789", B: 1}}, true},   // 11
		{"validate []*struct failed-2", &CustomValidator{}, []*exampleStruct{{A: "12345678", B: 0}}, true},    // 12
		{"validate []*struct passed", &CustomValidator{}, []*exampleStruct{{A: "12345678", B: 1}}, false},     // 13 *
		{"validate *[]struct failed-1", &CustomValidator{}, &[]exampleStruct{{A: "123456789", B: 1}}, true},   // 14
		{"validate *[]struct failed-2", &CustomValidator{}, &[]exampleStruct{{A: "12345678", B: 0}}, true},    // 15
		{"validate *[]struct passed", &CustomValidator{}, &[]exampleStruct{{A: "12345678", B: 1}}, false},     // 16 *
		{"validate *[]*struct failed-1", &CustomValidator{}, &[]*exampleStruct{{A: "123456789", B: 1}}, true}, // 17
		{"validate *[]*struct failed-2", &CustomValidator{}, &[]*exampleStruct{{A: "12345678", B: 0}}, true},  // 18
		{"validate *[]*struct passed", &CustomValidator{}, &[]*exampleStruct{{A: "12345678", B: 1}}, false},   // 19 *
		{"validate struct failed-1", &CustomValidator{}, exampleStruct{B: 1}, true},                           // 20
	}
	for ii, tt := range tests {
		t.Run(fmt.Sprintf("name:%s test-no:%d", tt.name, ii), func(t *testing.T) {
			fmt.Printf("Test %d\n", ii)
			if err := tt.v.ValidateStruct(tt.obj); (err != nil) != tt.wantErr {
				t.Errorf("CustomValidator.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
