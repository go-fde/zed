package zed

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
)

// TLV tags (Beucler, "TLV format", _ctlfile TLV and _catalog TLV).
const (
	tagFileProps      = 0x80110600
	tagExtraProps     = 0x001b0600
	tagAccessList     = 0x80140600
	tagArchivePath    = 0x00230400
	tagEncMode        = 0x80270200
	tagEncStrength    = 0x80260200
	tagFilesIV        = 0x80280500
	tagCreationTime   = 0x00c40500
	tagCreatedWith    = 0x00c00400
	tagPasswordUser   = 0x80610600
	tagRSAUser        = 0x80620600
	tagLogin          = 0x80710400
	tagFilesKeyCT     = 0x80740500
	tagPBESalt        = 0x80760500
	tagPBEIter        = 0x80770200
	tagHashFunc       = 0x80780200
	tagPBAChecksum    = 0x80790500
	tagPBASalt        = 0x807a0500
	tagPBAIter        = 0x807b0200
	tagFileID         = 0x80300500
	tagHalfAnon       = 0x80310400
	tagNameCiphertext = 0x00380500
	tagFileSize       = 0x80330500
	tagFileCreated    = 0x80340500
	tagFileWritten    = 0x80350500
	tagFileAccessed   = 0x80360500
	tagParentID       = 0x00370500
	tagIsDir          = 0x80320100
)

type item struct {
	tag uint32
	val []byte
}

type tlvs []item

// parseTLV splits b into type(4) length(4, big endian) value items.
func parseTLV(b []byte) (tlvs, error) {
	var out tlvs
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, fmt.Errorf("%w: truncated TLV header", ErrFormat)
		}
		n := binary.BigEndian.Uint32(b[4:])
		if uint64(n) > uint64(len(b)-8) {
			return nil, fmt.Errorf("%w: TLV %#08x claims %d bytes, %d remain", ErrFormat, binary.BigEndian.Uint32(b), n, len(b)-8)
		}
		out = append(out, item{binary.BigEndian.Uint32(b), b[8 : 8+n]})
		b = b[8+n:]
	}
	return out, nil
}

func (t tlvs) first(tag uint32) ([]byte, bool) {
	for _, it := range t {
		if it.tag == tag {
			return it.val, true
		}
	}
	return nil, false
}

// beUint reads a big-endian unsigned integer of 1 to 8 bytes.
func beUint(b []byte) (uint64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, fmt.Errorf("%w: integer field of %d bytes", ErrFormat, len(b))
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// u32 returns the integer under tag, or 0 and false when absent.
func (t tlvs) u32(tag uint32) (uint32, bool, error) {
	b, ok := t.first(tag)
	if !ok {
		return 0, false, nil
	}
	v, err := beUint(b)
	if err == nil && v > 0xFFFFFFFF {
		err = fmt.Errorf("%w: integer field above 32 bits", ErrFormat)
	}
	return uint32(v), true, err
}

// utf16le decodes a UTF-16LE string and drops trailing NULs.
func utf16le(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("%w: UTF-16 string of odd length %d", ErrFormat, len(b))
	}
	return decodeUTF16(b), nil
}

// decodeUTF16 decodes UTF-16LE code units, ignores an odd last byte and drops
// trailing NULs.
func decodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

// filetime converts a little-endian FILETIME field; zero is the zero time.
func filetime(b []byte) (time.Time, error) {
	if len(b) != 8 {
		return time.Time{}, fmt.Errorf("%w: FILETIME of %d bytes", ErrFormat, len(b))
	}
	v := binary.LittleEndian.Uint64(b)
	if v == 0 {
		return time.Time{}, nil
	}
	const epochDiff = 11644473600
	return time.Unix(int64(v/10_000_000)-epochDiff, int64(v%10_000_000)*100).UTC(), nil
}
