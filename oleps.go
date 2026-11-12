package zed

import (
	"encoding/binary"
	"fmt"
)

// MS-OLEPS, only as far as the metadata stream needs: the PropertySetStream
// header, the property sets, the Dictionary (property 0) that names the
// properties, the CodePage property (1), and VT_BLOB values.
//
// Beucler's document says "_ctlfile" is index 3 and "_catalog" index 4. In a
// ZED! Free 2024.4 container the dictionary maps _ctlfile to property ID 4,
// _catalog to 5 and _seal to 6, so the names are resolved through the
// dictionary; 3 and 4 are used only when a dictionary does not name them.
const (
	propDictionary = 0
	propCodePage   = 1
	vtI2           = 0x0002
	vtBlob         = 0x0041
	cpUTF16        = 1200

	nameCtlfile = "_ctlfile"
	nameCatalog = "_catalog"
	idCtlfile   = 3 // fallback, per the 2017 document
	idCatalog   = 4
)

// blobs returns the _ctlfile and _catalog VT_BLOB values.
func blobs(b []byte) (ctl, cat []byte, err error) {
	le := binary.LittleEndian
	if len(b) < 28 || le.Uint16(b) != 0xFFFE {
		return nil, nil, fmt.Errorf("%w: metadata is not a property set stream", ErrFormat)
	}
	nSets := le.Uint32(b[24:])
	if nSets == 0 || nSets > 2 || uint64(len(b)) < 28+20*uint64(nSets) {
		return nil, nil, fmt.Errorf("%w: %d property sets", ErrFormat, nSets)
	}
	for s := uint32(0); s < nSets; s++ {
		set, err := parseSet(b, le.Uint32(b[28+20*s+16:]))
		if err != nil {
			return nil, nil, err
		}
		ctl, cat = set.blob(nameCtlfile, idCtlfile), set.blob(nameCatalog, idCatalog)
		if ctl != nil && cat != nil {
			return ctl, cat, nil
		}
	}
	return nil, nil, fmt.Errorf("%w: no _ctlfile and _catalog properties", ErrFormat)
}

type propSet struct {
	blobs map[uint32][]byte
	names map[string]uint32
}

func (p *propSet) blob(name string, fallback uint32) []byte {
	if id, ok := p.names[name]; ok {
		return p.blobs[id]
	}
	return p.blobs[fallback]
}

// parseSet reads the property set at off: blobs by ID, and the dictionary.
func parseSet(b []byte, off uint32) (*propSet, error) {
	le := binary.LittleEndian
	if uint64(off)+8 > uint64(len(b)) {
		return nil, fmt.Errorf("%w: property set offset %d out of range", ErrFormat, off)
	}
	set := b[off:]
	n := le.Uint32(set[4:])
	if uint64(n)*8+8 > uint64(len(set)) {
		return nil, fmt.Errorf("%w: %d properties do not fit", ErrFormat, n)
	}
	out := &propSet{blobs: map[uint32][]byte{}, names: map[string]uint32{}}
	codepage := uint16(0)
	var dict []byte
	for i := uint32(0); i < n; i++ {
		id, po := le.Uint32(set[8+8*i:]), le.Uint32(set[12+8*i:])
		if uint64(po)+8 > uint64(len(set)) {
			return nil, fmt.Errorf("%w: property %d offset out of range", ErrFormat, id)
		}
		if id == propDictionary { // no type header: NumEntries follows directly
			dict = set[po:]
			continue
		}
		switch le.Uint16(set[po:]) {
		case vtI2:
			if id == propCodePage {
				codepage = le.Uint16(set[po+4:])
			}
		case vtBlob:
			size := le.Uint32(set[po+4:])
			if uint64(po)+8+uint64(size) > uint64(len(set)) {
				return nil, fmt.Errorf("%w: property %d blob of %d bytes does not fit", ErrFormat, id, size)
			}
			out.blobs[id] = set[po+8 : po+8+size]
		}
	}
	if dict != nil { // read last: the code page may come after it
		if err := out.dictionary(dict, codepage); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// dictionary reads NumEntries and then (ID, Length, name) entries. With code
// page 1200 the length counts UTF-16 units and each entry is padded to four
// bytes; otherwise it counts bytes.
func (p *propSet) dictionary(b []byte, codepage uint16) error {
	le := binary.LittleEndian
	n := le.Uint32(b)
	if uint64(n)*8+4 > uint64(len(b)) {
		return fmt.Errorf("%w: dictionary of %d entries does not fit", ErrFormat, n)
	}
	b = b[4:]
	for i := uint32(0); i < n; i++ {
		if len(b) < 8 {
			return fmt.Errorf("%w: truncated dictionary", ErrFormat)
		}
		id, length := le.Uint32(b), uint64(le.Uint32(b[4:]))
		unit := uint64(1)
		if codepage == cpUTF16 {
			unit = 2
		}
		size := length * unit
		if codepage == cpUTF16 {
			size = (size + 3) &^ 3
		}
		if size > uint64(len(b)-8) {
			return fmt.Errorf("%w: dictionary name of %d bytes does not fit", ErrFormat, size)
		}
		raw := b[8 : 8+length*unit]
		var name string
		if codepage == cpUTF16 {
			name = decodeUTF16(raw)
		} else {
			name = string(trimNUL(raw))
		}
		p.names[name] = id
		b = b[8+size:]
	}
	return nil
}

func trimNUL(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}
