package zed

import (
	"bytes"
	"testing"
)

// TestAbortKeepsOrdinalsUnique: aborting a file while a later one is open
// must not hand its ordinal out again, or two catalog entries would share
// the half-anonymous name File<n><ext>.
func TestAbortKeepsOrdinalsUnique(t *testing.T) {
	var buf bytes.Buffer
	w, err := Create(&buf, "pw")
	if err != nil {
		t.Fatal(err)
	}
	first, err := w.Create("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.Create("b.txt")
	if err != nil {
		t.Fatal(err)
	}
	first.(*fileWriter).abort()
	third, err := w.Create("c.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, c := second.(*fileWriter).e.ordinal, third.(*fileWriter).e.ordinal
	if b == c {
		t.Fatalf("b.txt and c.txt share ordinal %d after an abort", b)
	}
	for _, f := range []interface{ Close() error }{second, third} {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
