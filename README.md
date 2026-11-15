# zed

Pure-Go reader and writer for Prim'X ZED! encrypted archives (`.zed`), for
users who hold a password.

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

* the MS-CFB container (through go-filesystems/cfb: v3 and v4 sectors, FAT,
  DIFAT, mini FAT, mini stream; see "The CFB reader" below);
* the metadata stream, as MS-OLEPS (only the dictionary, the code page and
  `VT_BLOB` values), and in it `_ctlfile` (static-key AES obfuscation, TLV)
  and `_catalog` (TLV);
* password users with PKCS#12 key derivation (RFC 7292 appendix B), SHA-1
  (`pkcs12_hashfunc` 21) and SHA-256 (22), or PBKDF2-HMAC-SHA-512 with the
  password in UTF-8 (43, written by ZED! Free 2026.3): PBA is the password
  check, PBE derives the key and IV that unwrap the archive key (AES-CBC,
  PKCS#7);
* AES-128/192/256 in the two end-of-stream modes, `STREAM` (103) and
  `CTS` (104, CBC-CS3), for file names and for the 512-byte chunks of file
  streams, whose IV is `AES-ECB(key, LE16(chunk) xor files_iv)`; then zlib.

Out of scope, and said so: **RSA users** (the archive still opens with a
password user; with none, `Open` returns `ErrUnsupported` naming the method),
**modifying** an existing archive, reading the optional streams (watermark
picture, seal), and the on-the-fly folder variant.

## Writing (new archives): EXPERIMENTAL

> **Experimental.** Archives written by `Create` are read back by this
> package, but **ZED! Free 2026.3.6 opens them only after a "Corrupted
> encrypted container!" warning** (then read only), because the global seal
> hash and the per-file seal values are not reproduced. AES-256 archives are
> refused by ZEDFREE. Do not rely on `Create` where ZED! must accept the
> archive without the warning. Status, what is reproduced and what was tried:
> [issue #21](https://github.com/go-fde/zed/issues/21).
>
> | archive written by `Create` | ZEDFREE 2026.3.6 |
> |---|---|
> | AES-128, full seal (default), also seal property only | warning, then opens; tree and list right |
> | AES-128, empty | warning, then opens with an empty list |
> | AES-128, no seal, or no watermark | warning, then back to the start screen, not opened |
> | AES-256 (`WithStrength(32)`) | refused, [807A0103] |
> | extracting a file through the GUI | not tested |

```go
w, err := zed.Create(file, password) // AES-128, which ZED! Free writes; WithStrength(32) for AES-256
if err != nil { ... }
w.Mkdir("Documents")
err = w.AddFile("Documents/notes.txt", r) // or f, _ := w.Create(path); f.Write(...); f.Close()
err = w.Close() // the archive is held in memory and written here
```

`Create` writes a new archive with one password user in the layout ZED! Free
2026.3 writes: container version 4, `_ctlfile` version `0200`, hash 43
(PBKDF2-HMAC-SHA-512, 200 000 and 100 000 iterations), the per-file IV, CTS,
512-byte chunks, zlib, and the same TLV items in the same order (a test compares
the tag sequences with the ones read from two real containers, and with the real
containers themselves when `ZED_CORPUS` is set). Salts, IVs, the archive key and
the file identifiers come from `crypto/rand`. It refuses what the reader would
refuse (names, paths, depth, entry counts, sizes: the same `Limits`), with
`ErrArgument` or `ErrLimit`; what it writes is read back by `Open`. It does not
modify existing archives, and holds the archive in memory (1 GiB by default,
`WithMaxArchiveSize`).

**What is and is not known about ZED! opening these archives.** Tested by
driving ZEDFREE 2026.3.6 through the macOS Accessibility API (`cmd/zedgui`), with
no human involved:

- An AES-128 archive written by `Create` is **opened by ZED! Free 2026.3.6 only
  after a "Corrupted encrypted container!" warning** ("a modification
  unauthorized by the creator of the container was performed", Yes/No); after
  Yes, the tree and file list are right and the container is read only. **No
  archive written by `Create` opens without that warning yet.**
- **Without a seal the archive does not open**: with no `_seals` property and
  no seal stream (`SealNone`), or without the watermark storage, ZEDFREE shows
  the same warning and, after Yes, returns to its empty start screen with no
  message. With the `_seals` property only (`SealPropertyOnly`), or the full
  placeholder seal, it opens after the warning.
- **AES-256 is refused** by ZEDFREE 2026.3.6 with "Encrypted container open
  failed [807A0103]: A cryptographic key length is not compatible with a
  cryptographic operation". Whether ZED! Free supports AES-256 at all is unknown
  (it may be an Enterprise feature); the reader's 32-byte-key layout (IV after
  the key) is still inferred, not verified on a real container.
- **Extracting a file through the GUI was not tested**; only the tree and the
  list (names, sizes shown rounded) were compared with what was written. The
  content of files is checked by our own reader only.

The seal (a `_seals` property and the `~zedCFSTG_PGI_SEAL_STREAM` stream, which
real containers have) holds six 32-byte values. Reproduced on two real ZED! Free
containers, and written by `Create`: SHA-256 of `_ctlfile`, of `_catalog` and of
the watermark picture's stream, and, after each, **HMAC-SHA-256 of that digest
under the seal key** (the 16-byte key stored, encrypted with the archive key,
in the `_ctlfile`). Recomputing all six on a real container leaves it open
without a warning in ZEDFREE (checked). But changing any byte of a real
container (any stream, the CFB directory or its header) raises the warning even
when those six are recomputed, and so does a change in a byte nothing uses (the
slack after a stream, a free directory entry, a free FAT entry): something
covers the raw file. Most likely it is the hash in the seal stream (algorithm 2,
blocks of 4096 bytes in the stream's header), **which could not be reproduced**
(tested: SHA-256 and HMAC-SHA-256 with the seal key, the archive key and the IVs,
over the file with the hash or the whole seal stream zeroed or removed, its
4096-byte blocks numbered or not, chained, concatenated or as a tree, the
streams and their prefixes and suffixes; the stored value also decrypted under
five IVs; written random). Removing the three HMAC items from `_seals`, as
Mougey describes (SSTIC 2024, "Zed-Files", p. 19, remark 2), does not avoid the
warning either. The two per-file values in the catalog (`0x00400500`,
`0x00410500`) are, according to the same paper (fig. 11, p. 30), the
HMAC-SHA-256 of SHA-256(block number, encrypted block, file id) encrypted under
the archive key; about 2 million combinations (block size, number encoding and
base, field order, per block, chained or concatenated, five IVs, three modes)
did not reproduce either on a real container, so `Create` writes the SHA-256 of
the stream and random bytes, which ZED! does not accept as genuine. As in ZED!
itself, each catalog entry also
carries a half-anonymous name in clear, `File<n><ext>`, which reveals the file's
extension. The watermark picture is our own plain white one (the real one is
Prim'X's). `archive_createdwith` is ZED! Free 2026.3's by default
(`WithCreatedWith`). The archives are not ANSSI-qualified, and nothing here is a
Prim'X product.

## Limits (untrusted input)

`DefaultLimits()`: the key derivation budget is counted in PKCS#12 SHA-256
rounds, the unit of the iteration counts below. One PBKDF2-HMAC-SHA-512
iteration (hash 43) is charged as 5 of them: measured with `go test -bench
KDFRound` on an Apple M4 Max, one core, 1-minute load 7.8, a PKCS#12 SHA-256
round takes 46.4 ns (SHA-1 40.2 ns) and a PBKDF2-HMAC-SHA-512 iteration 225.3
ns, a ratio of 4.86. A user may declare up to 10 000 000 units (ZED! Free writes
100 000 and 200 000 iterations; hash 43 counts 5 each, so up to 2 000 000
iterations), and all users together 40 000 000. Each scheme is counted as it
derives: a user costs its check, plus (for the one user whose password is
tried right) its key and IV, which cost two PKCS#12 SHA-256 passes, three with
SHA-1, and one PBKDF2 pass. When `MaxTotalIterations` is left zero it is four
times `MaxIterations`. At the defaults a hostile header costs at most about
1.9 s of derivation on that core (40 000 000 × 46.4 ns), whichever hash it
names; the refusal comes before any derivation. 64 users,
100 000 entries nested at most 256 deep with paths of at most 4096 bytes and
64 MiB of paths in all (`MaxTotalPathBytes`: the paths are stored in full, so
100 000 entries at the per-path cap would otherwise hold 400 MB), 64 MiB of
metadata, 4 GiB per decompressed file. Iteration counts, and the
lengths that set the cost of a derivation (`pba_checksum` between 1 byte and
one hash output, salts and the wrapped key at most 256 bytes), are checked
before any key derivation; a file size above the limit is refused too. The
catalog's paths are built in linear time, parents first, after the depth, path
and total-path caps are checked (no string is built for a catalog that is
refused). A file is read through a reader that stops at its
declared size: a zlib bomb that inflates past it is refused with `ErrFormat`
after about that many bytes. `TestZlibBomb` (64 MiB of zeros in under 200 KiB)
asserts that refusing it allocates under 8 MiB; that `TotalAlloc` check is the
guard. The 128 MiB `debug.SetMemoryLimit` the test also sets is soft (the
collector works harder, nothing is killed), so it is not a guard. File names
containing `/`, `\`, `:` or NUL, and names that are exactly `.` or `..`, are
refused (`note.txt` is fine), on every OS, as are names ending in a dot or a
space and the Windows device names by the rules of Go's Windows
`filepath.IsLocal`: CON, PRN, AUX, NUL, COM1-9 and LPT1-9 (superscript digits
¹ ² ³ included), CONIN$ and CONOUT$, with or without an extension; two entries
with one path are refused too. Extracting by `Entry.Path` cannot escape a
directory. The CFB layer (go-filesystems/cfb) bounds every chain by the number
of sectors the file can hold, refuses cycles and a mini stream shorter than its
chains, and indexes directory children once. The parsers (`FuzzOpen`,
`FuzzControl`, `FuzzCatalog`, `FuzzMetadata`) run in CI; their corpora are
committed in `testdata/fuzz/` and replayed by `go test`. The CFB reader's own
fuzzer runs in its repository.

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
  OLEPS, zlib, limits, a damaged container) bring `zed` to 100 % statement
  coverage.
* `TestTagsAsLiteralBytes` writes a whole `_ctlfile` and `_catalog` with the
  TLV tags as literal hex, independent of the constants the reader and the
  test writer share.
* Regression tests for review findings: deep and cyclic catalogs, derivation
  inputs (`pba_checksum`, salts), total derivation work, reserved names,
  duplicate paths.
* `ZED_CORPUS=<folder>` runs `TestCorpus` on real containers: every `*.zed`
  in the folder, with the password on the last non-empty line of the folder's
  `README.md` (a line before it, such as the ZEDFREE version, is a note). It
  fails if any container does not open. Without it the test skips loudly. The containers are never
  committed. It extracts every entry and checks each file's length against
  the catalog, its path against `parent_directory_id`, and that images decode
  (`image.Decode`: random bytes from a wrong key, IV or chunk cannot). It
  fails if it extracted no file. With `ZED_CORPUS_REFERENCE=<folder>` it also
  compares each extracted file byte for byte with the file of the same name
  there (names compared after Unicode normalisation); the originals are read
  at run time and never copied anywhere.

### Real-container interoperability (ZED! Free 2024.4 and 2026.3)

Two containers were opened (not committed), one made by ZED! Free 2024.4 and
one by ZED! Free 2026.3 (`zed-2026.zed`). Each opens with its password, refuses
a wrong one with `ErrPassword`, and holds a folder with one PNG screen capture
(11 508 bytes, 292 × 234). Each file is extracted byte for byte equal to the
original, through the whole file-stream path: stream name from `file_id`,
512-byte chunks, CTS, zlib. What the containers showed, and where the 2017
document does not match (a row is for both unless it says otherwise; the
2026.3 container has version bytes `0200`, mode 104 (CTS), a 16-byte key,
200000 PBA and 100000 PBE iterations like the 2017 document's typical values,
and the same catalog and file layout as 2024.4):

| 2017 document | ZED! Free 2024.4 container |
| --- | --- |
| a file's name and chunks use the global `files_iv` ("the same key and IV") | the IV is `files_iv` **XOR the file's `file_id`** (raw bytes, not the shuffled stream name): `IV(file) = files_iv ^ file_id`, then the chunk IV is `AES-ECB(key, LE16(chunk) ^ IV(file))` as before. Found because the first 16 bytes of every name decrypted to garbage and the rest to text (a wrong CBC IV spoils one block), and `files_iv ^ file_id` was the value that makes the first block read "Capture ". Applied to archives whose version bytes are `0200`; `0100` archives (the 2017 ones) keep the global IV. Verified on one container; whether version `0200` or the 2024 release is what changed is not known. |
| `pkcs12_hashfunc` is 21 (SHA-1) or 22 (SHA-256) | **2026.3 writes 43**: PBA and PBE are not PKCS#12 any more but **PBKDF2-HMAC-SHA-512** (RFC 8018) with the password as **UTF-8** (not UTF-16BE with a NUL). PBA is 8 bytes of the derivation from `pba_salt` and `pba_iter`; PBE is one derivation from `pbe_salt` and `pbe_iter` of `encryption_strength + 16` bytes: the first `encryption_strength` bytes are the key that unwraps `files_key_ciphertext`, the next 16 the IV. Found by trying the hash families, block sizes and password encodings against `pba_checksum` (only PBKDF2-HMAC-SHA-512 matched), then the IV offsets against a readable catalog (offset 16, i.e. right after a 16-byte key). The IV position for 24- and 32-byte keys is inferred (right after the key), not seen. |
| created with `{00000188-1000-…}` (Zed! Free 1.0.188) | ZED! Free 2026.3: `{00000006-B030-3CA8-8868-36F59DEFD14D}` (2024.4: `{00000018-A040-…}`). |
| file names are filename_ciphertext, "may have a trailing NUL" | UTF-16LE in NFC form (macOS composes é and à the same way); no NUL seen. |
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

Not yet verified on a real container: several files, files under 16 bytes of
ciphertext, nested folders deeper than one, several users, SHA-1, mode 103,
24/32-byte keys (for 2026.3: where the IV sits), other hash identifiers than
21, 22 and 43, and any `0100` archive (so the rule that `0100` keeps the
global IV rests on the 2017 vectors only).

### Testing an archive in the real application: `cmd/zedgui`

`cmd/zedgui` (its own Go module, so this library keeps its dependencies) opens
an archive in `/Applications/ZEDFREE.app`, enters the password and prints what
ZEDFREE shows: the file and folder list, or the exact text of the message. It
drives the application through the macOS Accessibility API
([go-macos/accessibility](https://github.com/go-macos/accessibility)), so no
human clicks anything.

```
ZED_GUI=1 go run github.com/go-fde/zed/cmd/zedgui@latest check \
    --password-file README.md --expect hello.txt --expect Documents archive.zed
```

- The password is the last non-empty line of `--password-file` (or the first
  `` `quoted` `` token of the line holding `--password-marker`). It is read by
  the program, never printed, and every editable field's value is withheld from
  every dump.
- `--wrong-password` is the negative control (a refusal is expected).
  `--continue` answers Yes to a Yes/No warning and reports what follows.
- The terminal that runs it must be allowed in System Settings, Privacy &
  Security, Accessibility. The tool never prompts and never works around that.
- It refuses to run if ZEDFREE is already open, and quits what it started.
- The archives under test stay outside the repository.

## The CFB reader

The container is read by
[github.com/go-filesystems/cfb](https://github.com/go-filesystems/cfb) v0.1.0, a
generic MS-CFB reader (v3 and v4, FAT, DIFAT, mini FAT, mini stream, red-black
directory trees, `io.ReaderAt` streams) that was written for this module and
moved there unchanged; it was `internal/cfb` in zed v0.1.0 to v0.2.0. Its
chain bounds, cycle checks and fuzzing live in that repository, and zed's
tests still build their archives with its `cfbtest` writer.

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
