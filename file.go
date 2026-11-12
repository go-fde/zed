package zed

import (
	"compress/flate"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"github.com/go-fde/zed/internal/cfb"
)

const batchChunks = 64 // chunks decrypted per read of the container

// chunkReader decrypts a file stream: 512-byte chunks, each its own AES-CBC
// stream with an IV derived from the chunk number.
type chunkReader struct {
	d    *decryptor
	s    *cfb.Stream
	off  int64
	idx  uint64
	raw  []byte
	pend []byte
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.pend) == 0 {
		if c.off >= c.s.Size() {
			return 0, io.EOF
		}
		n := min(int64(len(c.raw)), c.s.Size()-c.off)
		got, err := c.s.ReadAt(c.raw[:n], c.off)
		if int64(got) != n { // the container reports its own damage as ErrFormat
			return 0, err
		}
		c.off += n
		for b := c.raw[:n]; len(b) > 0; c.idx++ {
			k := min(len(b), chunkSize)
			c.pend = append(c.pend, c.d.decryptChunk(c.idx, b[:k])...)
			b = b[k:]
		}
	}
	n := copy(p, c.pend)
	c.pend = c.pend[n:]
	return n, nil
}

// exact yields exactly size bytes of the decompressed data: more is a bomb,
// fewer is a damaged file.
type exact struct {
	r    io.Reader
	left int64
	zr   io.Closer
}

// corrupt maps what compress/zlib says of damaged data to ErrFormat.
func corrupt(err error) error {
	var ce flate.CorruptInputError
	if errors.Is(err, zlib.ErrChecksum) || errors.Is(err, zlib.ErrHeader) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &ce) {
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return err
}

func (x *exact) Read(p []byte) (int, error) {
	if x.left == 0 {
		// Reading on past the declared size must find the end of the zlib
		// stream (which also checks the Adler-32), not more data.
		var one [1]byte
		n, err := x.r.Read(one[:])
		if n > 0 {
			return 0, fmt.Errorf("%w: file is longer than its declared size", ErrFormat)
		}
		return 0, corrupt(err)
	}
	if int64(len(p)) > x.left {
		p = p[:x.left]
	}
	n, err := x.r.Read(p)
	x.left -= int64(n)
	if errors.Is(err, io.EOF) && x.left > 0 {
		err = fmt.Errorf("%w: file is shorter than its declared size", ErrFormat)
	}
	return n, corrupt(err)
}

func (x *exact) Close() error { return x.zr.Close() }

// Open returns the decompressed content of a file entry. The reader reports
// ErrFormat if the data does not match the declared size or zlib checksum.
func (a *Archive) Open(e *Entry) (io.ReadCloser, error) {
	if e.Dir {
		return nil, fmt.Errorf("zed: %q is a directory", e.Path)
	}
	if e.Size > a.lim.MaxFileSize {
		return nil, fmt.Errorf("%w: %q is %d bytes, limit %d", ErrLimit, e.Path, e.Size, a.lim.MaxFileSize)
	}
	ce := a.cf.Lookup(streamName(e.ID))
	if ce == nil || ce.IsDir() {
		return nil, fmt.Errorf("%w: no stream for %q", ErrFormat, e.Path)
	}
	s, err := a.cf.Open(ce)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	cr := &chunkReader{d: a.dec.withFile(e.ID), s: s, raw: make([]byte, batchChunks*chunkSize)}
	zr, err := zlib.NewReader(cr)
	if err != nil {
		return nil, corrupt(err)
	}
	return &exact{r: zr, left: e.Size, zr: zr}, nil
}

// ReadFile returns the decompressed content of a file entry.
func (a *Archive) ReadFile(e *Entry) ([]byte, error) {
	r, err := a.Open(e)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
