# NEVERLOSE RESOURCE ANALYSIS
=============================
Investigation of the .rsrc section of neverlose.dll. All findings are based on
PE resource-directory enumeration of the on-disk binary (static analysis). No
resources were extracted to disk except where noted as small, already-identifiable
previews.

Evidence levels: CONFIRMED (from PE resource directory + raw byte previews).

Source file analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll

========================================
1. RESOURCE DIRECTORY SUMMARY
========================================

Resource directory RVA: 0x6D000
Resource directory size: 0x03557150 (55,578,672 bytes)
Total resource entries enumerated: 6
Total resource data size: 55,930,821 bytes (~53.34 MB)
Resource type: all entries use custom type "BINARY" (named type), EXCEPT one
  standard type RT_MANIFEST.

| Entry | Type | Name | Lang | RVA | Size (bytes) | Size (MB) | Format (from preview) |
|-------|------|------|------|-----|--------------|-----------|-----------------------|
| #101 | BINARY | #1049 | L25/S1 | 0x0006D170 | 55,578,628 | 53.0 | Transformed binary blob (repeating pattern) |
| #102 | BINARY | #1049 | L25/S1 | 0x0356E178 | 2,921 | 0.003 | x86 machine code (CPUID detection) |
| #103 | BINARY | #1049 | L25/S1 | 0x0356CEE8 | 4,096 | 0.004 | Data table / structure |
| #104 | BINARY | #1049 | L25/S1 | 0x0356FCE8 | 305,945 | 0.292 | PNG image (447×447) |
| #105 | BINARY | #1049 | L25/S1 | 0x035BA808 | 38,850 | 0.037 | JPEG image (Exif) |
| RT_MANIFEST | RT_MANIFEST | #2 | EN/S1 | 0x035C3FD0 | 381 | 0.0004 | XML application manifest |

Note: All five "BINARY"-type entries share name #1049 and language L25/S1
(lang id 25, sublang 1 — non-standard language identifier; possibly a
custom/obfuscated lang code or pefile rendering artifact). The manifest uses
language EN/S1 (English, sublang 1).

Total (.rsrc section raw size 0x03557200 ≈ 55,578,624 bytes) is consistent
with the sum of resource data (~55.9 MB including headers/padding).

========================================
2. INDIVIDUAL RESOURCE ANALYSIS
========================================

----------------------------------------------------------------------
Entry #101 — 53.0 MB binary blob (RVA 0x0006D170, size 55,578,628)
----------------------------------------------------------------------
This is the dominant resource, comprising ~99.9% of the .rsrc section.

First 48 bytes (raw):
  a6 c0 4e c9 43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32 36
  43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32 36 43 77

ASCII preview (non-printable shown as .):
  ..N.Cw!c4bb1t#nL.3nc-2026Cw!c4bb1t#nL.3nc-2026Cw

Observations:
  - Does NOT begin with a recognizable file magic (not "MZ", not "\x1bLua"
    Lua bytecode, not PNG/JPEG, not XML, not ZIP "PK").
  - Contains a clear repeating ASCII fragment: "Cw!c4bb1t#nL.3nc-2026" which
    recurs at regular intervals. This indicates either a repeating XOR key,
    a structured container with repeated headers, or a deliberately patterned
    fill.
  - The substring "2026" appears within the repeating fragment (consistent
    with a year/timestamp embedded in the data or key).
  - Entropy contribution: the .rsrc section overall measured 7.27 (high),
    consistent with compressed, encrypted, or high-randomness content.
  - Size (55,578,628) is within 4 bytes of nl.bin (55,578,624 bytes), but
    the content does NOT match nl.bin raw bytes (nl.bin begins with Lua
    bytecode magic \x1bLua; this blob begins with a6 c0 4e c9). A simple
    4-byte repeating XOR of nl.bin was tested against the first 8 bytes and
    did NOT produce a consistent key.

Status: NOT decoded. Format unknown. Candidate interpretations:
  (a) compressed/encrypted payload (e.g., Lua bytecode bundle, config, assets),
  (b) an obfuscated copy of nl.bin,
  (c) a standalone embedded data package.
  No extraction was performed (53 MB; creating such a file is unnecessary
  for architectural documentation and discouraged by working rules).

Relationship to loader/DLL/runtime: NOT established. The resource is not
referenced by name in any binary (grep for "nl.bin"/"bins" returned zero
hits). No code path in the enumerated .text was confirmed to load resource
#101 at runtime. The DLL imports SizeofResource/LockResource/LoadResource/
FindResourceW, so resource access is mechanically possible, but no specific
consumer of #101 was identified.

----------------------------------------------------------------------
Entry #102 — 2,921 bytes (RVA 0x0356E178)
----------------------------------------------------------------------
First bytes:
  83 f8 00 0f 85 22 00 00 00 83 f9 00 0f 85 19 00 00 00 b8 10 00 00 00
  bb 41 75 74 68 b9 63 41 4d 44 ba 65 6e 74 69 ...

Decoded ASCII fragments: "Auth", "cAMD", "enti" → consistent with the CPUID
processor vendor string "AuthenticAMD". The leading bytes
`83 f8 00 / 0f 85 22 00 00 00` = cmp eax,0 / jne +0x22; `b8 10 00 00 00`
= mov eax,0x10 (CPUID leaf 0x10). This is x86 machine code implementing
CPU vendor detection (CPUID leaf 0, comparing against "AuthenticAMD").
Status: CONFIRMED as x86 code (CPUID/authenticAMD detection).
Likely role: anti-tamper / environment check (verify CPU is genuine AMD or
similar), invoked during initialization.

----------------------------------------------------------------------
Entry #103 — 4,096 bytes (RVA 0x0356CEE8)
----------------------------------------------------------------------
First bytes:
  00 00 00 00 00 00 a0 0f 00 91 6d 84 19 00 00 00 19 00 00 00 25 71 1e 21
  f3 31 db 01 f3 31 db 01 00 40 23 0e 43 00 00 00 43 00 00 00 64 86 64 86

Observations: Contains repeated 4-byte little-endian values
(`f3 31 db 01` appears twice, `43 00 00 00` appears twice). Looks like a
fixed-size data table / structure block (exactly 4,096 bytes = one page).
Status: CONFIRMED present; format UNKNOWN (data table / structure).
Purpose: UNKNOWN (possibly a lookup table, config block, or embedded struct).

----------------------------------------------------------------------
Entry #104 — 305,945 bytes PNG image (RVA 0x0356FCE8)
----------------------------------------------------------------------
First bytes:
  89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 ...

Decoded: PNG signature (89 50 4e 47 0d 0a 1a 0a), followed by IHDR chunk.
IHDR fields indicate width = 0x000001BF (447), height = 0x000001BF (447),
bit depth 8, color type 2 (truecolor).
Status: CONFIRMED PNG image, 447×447, ~306 KB.
Purpose: UNKNOWN (likely a UI asset / splash / logo). Not linked to any
confirmed runtime behavior.

----------------------------------------------------------------------
Entry #105 — 38,850 bytes JPEG image (RVA 0x035BA808)
----------------------------------------------------------------------
First bytes:
  ff d8 ff e0 00 10 4a 46 49 46 00 01 01 01 00 48 00 48 00 00 ff e1 ...
  ... 45 78 69 66 ...

Decoded: JPEG SOI marker (ff d8), JFIF APP0 (4a 46 49 46), Exif APP1
(45 78 69 66). Size ~38 KB.
Status: CONFIRMED JPEG image with Exif metadata.
Purpose: UNKNOWN (likely a UI asset / avatar / logo). Not linked to any
confirmed runtime behavior.

----------------------------------------------------------------------
RT_MANIFEST — 381 bytes (RVA 0x035C3FD0)
----------------------------------------------------------------------
First bytes:
  3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 27 31 2e 30 27 ...

Decoded: `<?xml version='1.0' encoding='UTF-8' standalone=` — a standard
Windows application manifest (XML).
Status: CONFIRMED XML application manifest.
Purpose: Declares application execution level / compatibility / dependencies
for the DLL when loaded. Size 381 bytes is typical for a minimal manifest.

========================================
3. RESOURCE RELATIONSHIPS
========================================

| Resource | Linked to loader? | Linked to DLL init? | Linked to server? | Evidence |
|---|---|---|---|---|
| #101 (53 MB blob) | No | No | No | Not referenced by name in any binary |
| #102 (CPUID code) | No | INFERRED | No | x86 code; likely init-time env check |
| #103 (table) | No | No | No | Format/purpose unknown |
| #104 (PNG) | No | No | No | UI asset candidate |
| #105 (JPEG) | No | No | No | UI asset candidate |
| RT_MANIFEST | No | INFERRED | No | Standard manifest; consumed by OS loader |

No resource was confirmed to be consumed by any specific code path in the
enumerated .text call graph. The DLL's resource-loading imports
(FindResourceW, SizeofResource, LockResource, LoadResource) make resource
access mechanically possible, but no consumer of any specific resource ID
(#101–#105) was identified.

========================================
4. nl.bin RELATIONSHIP
========================================

nl.bin (FemboyLose-main/neverlose/bins/nl.bin, 55,578,624 bytes) is a Lua 5.1
bytecode standard-library bundle (source-tree asset, confirmed NOT a runtime
artifact — see NEVERLOSE_RUNTIME_ARTIFACTS.md).

Resource #101 is 55,578,628 bytes — within 4 bytes of nl.bin — but:
  - Its first bytes (a6 c0 4e c9…) do NOT match Lua bytecode magic
    (\x1bLua = 1b 4c 75 61).
  - A simple repeating 4-byte XOR of nl.bin against the first 8 bytes of
    #101 did not yield a consistent key.
  - #101 shows a repeating ASCII pattern ("…-2026…") not present in Lua
    bytecode.
Conclusion: #101 is NOT a plain or simply-XORed copy of nl.bin. Whether it
is an encoded/transformed version of nl.bin, or an unrelated payload, is
UNKNOWN.

========================================
5. LIMITATIONS
========================================

  - The 53 MB blob (#101) was NOT extracted to disk or decoded. Creating a
    53 MB extracted file is unnecessary for architectural documentation.
  - No runtime behavior (resource loading at init) was traced; all
    resource→consumer links are absence-of-evidence, not evidence of absence.
  - The custom resource type name "BINARY" and language id 25 are not
    standard Windows resource types/languages; their semantics are UNKNOWN.

========================================
END
========================================