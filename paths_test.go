package zed

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// atTheCaps is a catalog at MaxEntries and at the depth and path caps: 255
// directories of 15 characters nested one in the other, then files in the
// deepest one, each with a path of 4095 bytes.
func atTheCaps(entries int) ([]Entry, map[[16]byte]int) {
	byID := make(map[[16]byte]int, entries)
	es := make([]Entry, entries)
	for i := range es {
		binary.BigEndian.PutUint32(es[i].ID[:], uint32(i)+1)
		byID[es[i].ID] = i
		switch {
		case i < 255:
			es[i].Name, es[i].Dir = strings.Repeat("d", 15), true
			if i > 0 {
				es[i].parent = es[i-1].ID
			}
		default:
			es[i].Name = fmt.Sprintf("f%014d", i)
			es[i].parent = es[254].ID
		}
	}
	return es, byID
}

func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// go-fde/zed#3: 100 000 entries, each with a path of 4095 bytes (all inside the
// depth and path caps), would hold 400 MB of path strings. The total is
// refused before any string is built.
func TestTotalPathBytesAreBoundedBeforeBuilding(t *testing.T) {
	es, byID := atTheCaps(100_000)
	lim := DefaultLimits()
	var err error
	grown := allocated(func() { err = buildPaths(es, byID, lim) })
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("got %v", err)
	}
	if grown > 16<<20 {
		t.Fatalf("refusing the catalog allocated %d MiB: the paths were built first", grown>>20)
	}
	for i := range es {
		if es[i].Path != "" {
			t.Fatalf("entry %d has a path although the catalog was refused", i)
		}
	}
}

// Just under the cap, the catalog opens and the memory is the paths' own,
// about the cap, not a multiple of it.
func TestPathMemoryIsAboutTheCap(t *testing.T) {
	const leaves = 1900 // 1900 * 4095 bytes plus the directories: under 8 MiB
	es, byID := atTheCaps(255 + leaves)
	lim := DefaultLimits()
	lim.MaxTotalPathBytes = 8 << 20
	var err error
	grown := allocated(func() { err = buildPaths(es, byID, lim) })
	if err != nil {
		t.Fatal(err)
	}
	var sum int
	for i := range es {
		sum += len(es[i].Path)
	}
	if sum > lim.MaxTotalPathBytes || sum < 7<<20 {
		t.Fatalf("paths hold %d bytes, cap %d", sum, lim.MaxTotalPathBytes)
	}
	if grown > uint64(2*lim.MaxTotalPathBytes) {
		t.Fatalf("%d MiB allocated for a cap of %d MiB", grown>>20, lim.MaxTotalPathBytes>>20)
	}
	if es[len(es)-1].Path != strings.Repeat(strings.Repeat("d", 15)+"/", 255)+es[len(es)-1].Name {
		t.Fatal("wrong path")
	}
}

// The cap counts bytes exactly: a, a/b and a/b/c are 1 + 3 + 5 = 9 bytes.
func TestTotalPathBytesBoundary(t *testing.T) {
	d := testDecryptor(t)
	blob := cat(halfEntry(0, -1, "a", true), halfEntry(1, 0, "b", true), halfEntry(2, 1, "c", false))
	lim := DefaultLimits()
	lim.MaxTotalPathBytes = 9
	if es, err := parseCatalog(blob, d, lim); err != nil || es[2].Path != "a/b/c" {
		t.Fatalf("cap of 9: %v", err)
	}
	lim.MaxTotalPathBytes = 8
	if _, err := parseCatalog(blob, d, lim); !errors.Is(err, ErrLimit) {
		t.Fatalf("cap of 8: %v", err)
	}
	if DefaultLimits().MaxTotalPathBytes != 64<<20 || (Limits{}).withDefaults().MaxTotalPathBytes != 64<<20 {
		t.Fatal("the default total is 64 MiB")
	}
}
