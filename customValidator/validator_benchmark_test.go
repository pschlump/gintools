package customValidator

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"errors"
	"strconv"
	"testing"
)

func BenchmarkSliceValidationError(b *testing.B) {
	const size int = 100
	for i := 0; i < b.N; i++ {
		e := make(SliceValidationError, size)
		for j := 0; j < size; j++ {
			e[j] = errors.New(strconv.Itoa(j))
		}
		if len(e.Error()) == 0 {
			b.Errorf("error")
		}
	}
}
