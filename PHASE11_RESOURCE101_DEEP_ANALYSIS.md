# PHASE11_RESOURCE101_FORMAT_ANALYSIS.md
========================================
Phase 9 Investigation B — Resource #101 (`IDR_BINARY`) format analysis from
the on-disk `neverlose.dll`. Read-only static analysis. No resources were
extracted or modified.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

Source file analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll
  SHA256: 529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253

========================================
1. RESOURCE IDENTIFICATION
========================================

Resource `IDR_BINARY` (= resource ID 101, type `L"BINARY"`) is defined in
`FemboyLose-main/neverlose/resource.h` as `#define IDR_BINARY 101` (CONFIRMED
from source). In the PE resource directory, it appears under the custom type
name `"BINARY"` at name 101, language 25/1.

Resource directory location:
  Type: "BINARY" (custom named type, not a standard Windows resource type)
  Name: 101
  Language: 25/1 (L25/S1 — non-standard language identifier)
  CodePage: 0

========================================
2. RESOURCE SIZE AND OFFSETS
========================================

| Property | Value |
|---|---|
| Resource RVA | 0x0006D170 |
| Resource file offset | 0x00066770 (in `.rsrc` section) |
| Resource size | 55,578,628 bytes (53.00 MB) |
| `.rsrc` section RVA | 0x0006D000 |
| `.rsrc` section size | 0x03557150 (55,578,672 bytes) |

Resource #101 accounts for ~99.99% of the `.rsrc` section. The next largest
resource (#102) is only 2,921 bytes.

Resource size vs. allocation size:
- Resource #101 size: 55,578,628 bytes (0x3501014)
- Observed allocation at `0x412a0000`: 0x3501000 = 55,578,624 bytes
- Difference: 4 bytes

The 4-byte difference corresponds to the first 4 bytes of the resource
(`a6 c0 4e c9`), which may be a header or key not written to the mapped
allocation. See Investigation D for details.

========================================
3. RESOURCE CONTENT ANALYSIS
========================================

First 64 bytes (raw):
  a6 c0 4e c9 43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32 36
  43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32 36 43 77

ASCII (first 64 bytes, non-printable as `.`):
  ..N.Cw!c4bb1t#nL.3nc-2026Cw!c4bb1t#nL.3nc-2026Cw

Magic number checks:
| Format | Magic | Match? |
|---|---|---|
| PE (MZ) | 4d 5a | No |
| Lua bytecode | 1b 4c 75 61 (`\x1bLua`) | No |
| PNG | 89 50 4e 47 0d 0a 1a 0a | No |
| JPEG | ff d8 | No |
| ZIP | 50 4b (`PK`) | No |
| ELF | 7f 45 4c 46 (`\x7fELF`) | No |

Entropy of full resource (55,578,628 bytes): **7.2576 bits/byte** (max 8.0).
This is high entropy, consistent with compressed, encrypted, or high-randomness
data. However, high entropy alone does not establish encryption.

Pattern analysis:
- Bytes 0x0004–0x0017: `43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32`
  = ASCII `Cw!c4bb1t#nL.3nc-202`
- Bytes 0x0018–0x001B: `36 43 77 21` = ASCII `6Cw!`
- Bytes 0x001C–0x002F: `34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32 36 43 77`
  = `4bb1t#nL.3nc-2026Cw`

The first ~44 bytes show a repeating pattern `Cw!c4bb1t#nL.3nc-2026` but the
pattern diverges after offset 0x18, where a `36` (`6`) byte appears to be
inserted, shifting subsequent bytes. The resource is NOT a simple repeating
pattern throughout.

SHA256: `c219ed6b999bfcc1346160b8f574278460c2ae1aaf04a2a8c1da02151b02d21d`
MD5:    `b4bb428272383534e664c8ccfacb0d3e`

========================================
4. FORMAT ASSESSMENT
========================================

Resource #101 does not match any known file format (PE, Lua bytecode, PNG,
JPEG, ZIP, ELF). Its structure is:

| Offset range | Content | Assessment |
|---|---|---|
| 0x0000–0x0003 | `a6 c0 4e c9` | 4-byte header/key/prefix — UNKNOWN purpose |
| 0x0004–0x0017 | `43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32` | `Cw!c4bb1t#nL.3nc-202` — start of repeating pattern |
| 0x0018+ | Pattern diverges; inserts `36` bytes at intervals | NOT a simple repeating pattern |

The first 4 bytes (`a6 c0 4e c9`) differ from all subsequent content. They
could be:
- A XOR key or decryption key
- A header/magic number
- A checksum or length field
- Part of an encoded container

No recognizable container format, executable image header, or structured
metadata was identified. The format is **UNKNOWN**.

========================================
5. LIMITATIONS
========================================

- The resource was not extracted to disk or decoded (53 MB; creating such a
  file is unnecessary for architectural documentation).
- No decompression or decryption was attempted on the resource bytes.
- The meaning of the first 4 bytes and the repeating pattern is UNKNOWN.
- Whether the resource is encrypted, encoded, compressed, or plaintext with
  an unusual format cannot be determined from static analysis alone.

========================================
END
========================================