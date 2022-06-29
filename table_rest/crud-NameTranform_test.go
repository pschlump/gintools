package table_rest

import "testing"

// func NameTransform(URIPath string) (rv string) {
func Test_NameTransform(t *testing.T) {

	//			t.Fatalf("Test %d: Could not create HTTP request: %v", ii, err)

	got := NameTransform("/aaa/bbb/ccc/")
	exp := "XAaaBbbCcc"
	if got != exp {
		t.Fatalf("Test  Expected %s got %s\n", exp, got)
	}
	got = NameTransform("/")
	exp = "X"
	if got != exp {
		t.Fatalf("Test  Expected %s got %s\n", exp, got)
	}
}
