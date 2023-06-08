// Copyright 2017 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package customValidator

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/mold"
	"github.com/go-playground/validator/v10"
)

type CustomValidator struct {
	once      sync.Once
	validate  *validator.Validate
	modifiers *mold.Transformer
}

type SliceValidationError []error

// Error concatenates all error elements in SliceValidationError into a single string separated by \n.
func (err SliceValidationError) Error() string {
	n := len(err)
	switch n {
	case 0:
		return ""
	default:
		var b strings.Builder
		if err[0] != nil {
			fmt.Fprintf(&b, "[%d]: %s", 0, err[0].Error())
		}
		if n > 1 {
			for i := 1; i < n; i++ {
				if err[i] != nil {
					b.WriteString("\n")
					fmt.Fprintf(&b, "[%d]: %s", i, err[i].Error())
				}
			}
		}
		return b.String()
	}
}

var _ binding.StructValidator = &CustomValidator{}

// ValidateStruct receives any kind of type, but only performed struct or pointer to struct type.
func (v *CustomValidator) ValidateStruct(obj any) error {
	if obj == nil {
		return nil
	}

	value := reflect.ValueOf(obj)
	switch value.Kind() {
	case reflect.Ptr:
		if false {
			a1 := value.Addr()
			a2 := a1.Interface()
			v.modifyStruct(&a2)
		}
		v.modifyStruct(obj)
		return v.ValidateStruct(value.Elem().Interface())
	case reflect.Struct:
		return v.validateStruct(obj)
	case reflect.Slice, reflect.Array:
		count := value.Len()
		validateRet := make(SliceValidationError, 0)
		for i := 0; i < count; i++ {
			if err := v.ValidateStruct(value.Index(i).Interface()); err != nil {
				validateRet = append(validateRet, err)
			}
		}
		if len(validateRet) == 0 {
			return nil
		}
		return validateRet

	// xyzzy - Map?

	default:
		return nil
	}
}

// validateStruct receives struct type
func (v *CustomValidator) modifyStruct(obj interface{}) (err error) {
	v.lazyinit()

	fmt.Printf("data orig:%+v \n", obj)
	if err = v.modifiers.Struct(context.Background(), obj); err != nil {
		fmt.Printf("mold chagned data modified:%+v error:%s\n", obj, err)
		return
	}
	fmt.Printf("mold chagned data modified:%+v\n", obj)

	// v.modifiers.Struct(context.Background(), obj)
	return
}

// validateStruct receives struct type
func (v *CustomValidator) validateStruct(obj any) (err error) {
	v.lazyinit()

	//	fmt.Printf("data orig:%+v \n", obj)
	//	if err = v.modifiers.Struct(context.Background(), obj); err != nil {
	//		fmt.Printf("mold chagned data modified:%+v error:%s\n", obj, err)
	//		return
	//	}
	//	fmt.Printf("mold chagned data modified:%+v\n", obj)

	// v.modifiers.Struct(context.Background(), obj)
	return v.validate.Struct(obj)
}

// Engine returns the underlying validator engine which powers the default
// Validator instance. This is useful if you want to register custom validations
// or struct level validations. See validator GoDoc for more info -
// https://pkg.go.dev/github.com/go-playground/validator/v10
func (v *CustomValidator) Engine() any {
	v.lazyinit()
	return v.validate
}

func (v *CustomValidator) lazyinit() {
	v.once.Do(func() {
		v.validate = validator.New()
		v.validate.SetTagName("binding")
		v.modifiers = mold.New()
		v.modifiers.SetTagName("mod")
	})
}
