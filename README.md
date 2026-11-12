# zed

Pure-Go reader for Prim'X ZED! encrypted archives (`.zed`), for users who hold
a password.

```go
a, err := zed.OpenFile("archive.zed", password)
if err != nil { // zed.ErrPassword, zed.ErrUnsupported, zed.ErrLimit, zed.ErrFormat
	log.Fatal(err)
}
defer a.Close()
fmt.Println(a.Info().CreatedWith, a.Info().EncryptionMode)
for _, e := range a.Entries() { // name, path, dir, size, times
	if e.Dir {
		continue
	}
	data, err := a.ReadFile(&e) // or a.Open(&e) for an io.ReadCloser
	...
}
```

`Open(r io.ReaderAt, size int64, password string, opts ...Option)` takes any
reader; `WithLimits` replaces the defaults below.

## What it reads

* the MS-CFB container (an internal reader: v3 and v4 sectors, FAT, DIFAT,
  mini FAT, mini stream; see "The CFB reader" below);
* the metadata stream, as MS-OLEPS (only the dictionary, the code page and
  `VT_BLOB` values), and in it `_ctlfile` (static-key AES obfuscation, TLV)
  and `_catalog` (TLV);
* password users with PKCS#12 key derivation (RFC 7292 appendix B), SHA-1
  (`pkcs12_hashfunc` 21) and SHA-256 (22): PBA is the password check, PBE
  derives the key and IV that unwrap the archive key (AES-CBC, PKCS#7);
* AES-128/192/256 in the two end-of-stream modes, `STREAM` (103) and
  `CTS` (104, CBC-CS3), for file names and for the 512-byte chunks of file
  streams, whose IV is `AES-ECB(key, LE16(chunk) xor files_iv)`; then zlib.

Out of scope, and said so: **RSA users** (the archive still opens with a
password user; with none, `Open` returns `ErrUnsupported` naming the method),
**writing** archives, the optional streams (watermark picture, seal), and
the on-the-fly folder variant.

## Limits (untrusted input)

`DefaultLimits()`: 10 000 000 iterations for one user (ZED! Free writes 100 000
and 200 000) and 40 000 000 hash iterations for all users together (a user
costs its PBA count plus three times its PBE count, so one user at 10 000 000
costs 40 000 000 and fits; when `MaxTotalIterations` is left zero it is four
times `MaxIterations`), 64 users,
100 000 entries nested at most 256 deep with paths of at most 4096 bytes,
64 MiB of metadata, 4 GiB per decompressed file. Iteration counts, and the
lengths that set the cost of a derivation (`pba_checksum` between 1 byte and
one hash output, salts and the wrapped key at most 256 bytes), are checked
before any key derivation; a file size above the limit is refused too. The
catalog's paths are built in linear time, parents first, after the depth and
path caps are checked. A file is read through a reader that stops at its
declared size: a zlib bomb that inflates past it is refused with `ErrFormat`
after about that many bytes. `TestZlibBomb` (64 MiB of zeros in under 200 KiB)
asserts that refusing it allocates under 8 MiB; that `TotalAlloc` check is the
guard. The 128 MiB `debug.SetMemoryLimit` the test also sets is soft (the
collector works harder, nothing is killed), so it is not a guard. File names
containing `/`, `\`, `:` or NUL, and names that are exactly `.` or `..`, are
refused (`note.txt` is fine), as are the Windows reserved names CON, PRN, AUX,
NUL, COM1-9, LPT1-9 (with or without an extension) and two entries with one
path. CONIN$, CONOUT$, superscript COM/LPT digits and names ending in a dot or
a space still pass (go-fde/zed#5). Extracting by `Entry.Path` cannot escape a
directory. The CFB layer bounds every chain by the number of sectors the file
can hold, refuses cycles, refuses a mini stream shorter than its chains, and
indexes directory children once. The parsers (`FuzzOpen`, `FuzzControl`,
`FuzzCatalog`, `FuzzMetadata`, and the CFB `FuzzOpen`) run in CI; their
corpora are committed in `testdata/fuzz/` and replayed by `go test`.

## Tests

* Every test vector of Beucler's document is checked. The file name, chunk IV
  and chunked file stream vectors are read by the test from
  `testdata/beucler-zed-format.html` (a verbatim copy; see Credits); the TLV,
  PBA/PBE and stream name vectors are copied by hand into `vectors_test.go`.
  They are: TLV (single and nested, with the three FILETIMEs), PBA/PBE with SHA-1 and
  SHA-256 (7 vectors, including the 36-character password), file name
  decryption (4 vectors: 0.x, 1, 1.x and 31.x blocks, STREAM and CTS), the
  `file_id` to stream name shuffle, the chunk IV, and the 30 chunked file
  stream vectors (STREAM-256, CTS-128, CTS-256; 0.x block up to 2.x chunks).
* A test-only archive writer builds `.zed` files in every combination of
  version (0100/0200), mode (103/104), key size (128/192/256) and hash
  (SHA-1/SHA-256), with nested directories, Unicode names and files around the
  512-byte chunk and 32 KiB batch boundaries; the refusal cases (damaged TLV,
  OLEPS, CFB, zlib, limits) bring `zed` and the CFB reader to 100 % statement
  coverage.
* `TestTagsAsLiteralBytes` writes a whole `_ctlfile` and `_catalog` with the
  TLV tags as literal hex, independent of the constants the reader and the
  test writer share.
* Regression tests for review findings: deep and cyclic catalogs, derivation
  inputs (`pba_checksum`, salts), total derivation work, reserved names,
  duplicate paths, hostile CFB headers, a short mini stream.
* `ZED_CORPUS=<folder>` runs `TestCorpus` on real containers: every `*.zed`
  in the folder, with the password on the first line of the folder's
  `README.md`. Without it the test skips loudly. The containers are never
  committed.

### Real-container interoperability (ZED! Free 2024.4)

One container made by ZED! Free 2024.4 was opened (not committed): it opens
with its password and refuses a wrong one with `ErrPassword`, but it **holds no
file**, so the file-stream path (chunks, CTS on real data, the stream-name
shuffle with a real `file_id`) is still verified only by the 2017 vectors.
What the container showed, and where the 2017 document does not match:

| 2017 document | ZED! Free 2024.4 container |
| --- | --- |
| `_ctlfile` is property index 3, `_catalog` index 4 | The dictionary names `_ctlfile` = property **4**, `_catalog` = **5**, and a third blob `_seal` = 6 (264 bytes). The names must be resolved through the dictionary; 3 and 4 are only a fallback here. |
| delimiter followed by `0100` for the free version | `0200`. (John the Ripper's `zed2john` also reads `0100` as free and `0200` as paid.) The TLV layout is read the same. |
| archive created with `{00000188-1000-3CA8-8868-36F59DEFD14D}` (Zed! Free 1.0.188) | `{00000018-A040-3CA8-8868-36F59DEFD14D}` |
| `encryption_mode` 103 or 104, key 16 or 32 bytes | 104 (CTS), 16 bytes |
| `pbe_iter` typically 100000, `pba_iter` 200000 | both 200000, SHA-256 (22) |
| `archive_pathname` is the initial path | `(none)` |
| the length field before the trailer counts "all the above" | equals the blob length minus 36: delimiter, version, IV and ciphertext, as written. Not enforced when reading. |
| `_ctlfile` TLV items listed | more items exist: `80100200`, `00220300`, `80250300`, `80290200` in the archive properties; `80750200`, `807c0200`, `00840500` per user; `00c80200`, `00c90200` in the extra properties; `801c0600` and `001d0600` at the top. Unknown items are skipped. |
| `_catalog` is a series of `fileprops` | the empty container's catalog holds only header items `80100200`, `00120100`, `00130100`, `00140200`, `00150100` and no `fileprops`. Skipped the same way. |
| optional streams "not discussed" | `~zedCFSTG_PGI_SEAL_STREAM` (8192 bytes) and a storage `\x05RydaaaqaIekzeecnWj31zxh0Nc` holding `CONTENTS` (a property set) and `prop0005` (a PNG, the background picture). Ignored. |

A second erratum, in the vectors rather than the format: the two CTS "2.x
blocks" vectors say "'ABC...Z' 160 times", but the 34 ciphertext bytes decrypt
to a checksum-valid zlib stream holding one alphabet (the STREAM vector with
the same length says once). The test checks what the bytes hold.

Not yet verified on a real container: file streams, directories, several
users, SHA-1, mode 103, 24/32-byte keys, ZED! Free 2024.4 with files. A
container with a few files (one over 512 bytes, one in a folder) would close
the file-stream gap.

## The CFB reader

`internal/cfb` is a generic MS-CFB reader with no dependency on the rest of
the module: v3 and v4, FAT, DIFAT, mini FAT, mini stream, red-black directory
trees (walked iteratively, each entry reached once), `io.ReaderAt` streams.
It was written to live in `go-office/cfb`; creating that repository needs an
organisation admin, so it stays internal for now and can be moved unchanged.
Its tests use a test-only writer; no `.doc`/`.xls`/`.msg` produced by Word
or LibreOffice was available to generate, and no Microsoft-made sample is
committed.

## Performance

`go test -bench .` extracts a 10 MiB text file (AES-256-CBC-CTS, zlib) and
compares it with an "ideal" floor of one CBC decryption and one inflate. No
reference extractor could be run here: ZED! Free has no command line, and
the `zedie.py` proof of concept named in Beucler's document was not
available to run. The timings of the first run were taken at a 1-minute load
above 30 and are not published; allocation counts are exact: about 18 345 per
extraction of 10 MiB (about one per 512-byte chunk).

## Credits and licence

BSD-3-Clause. The format knowledge, and the test vectors in
`testdata/beucler-zed-format.html`, come from Sylvain Beucler's
".zed archive file format" (2017), <https://www.beuc.net/zed/>:

> Copyright (C) 2017 Sylvain Beucler. Copying and distribution of this file,
> with or without modification, are permitted in any medium without royalty
> provided the copyright notice and this notice are preserved. This file is
> offered as-is, without any warranty.

John the Ripper's `zed2john.py` (permissively licensed) confirmed the version
bytes; [MS-CFB], [MS-OLEPS], NIST SP 800-38A addendum (CBC-CS3), RFC 7292
appendix B and RFC 1950 are the other references.
