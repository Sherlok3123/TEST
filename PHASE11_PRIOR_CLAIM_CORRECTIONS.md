# PHASE11_PRIOR_CLAIM_CORRECTIONS.md
========================================
Phase 12 — Prior Claim Corrections
========================================
Corrections to prior phase findings based on direct source code and binary
analysis of `neverlose.dll` and its source tree
(`FemboyLose-main/neverlose/`).

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. PRIOR CLAIM: "nl.bin is not referenced by any binary"
========================================
Status: CORRECTED

Previous claim: `nl.bin` is NOT referenced by name in any binary
(grep of `neverlose.dll`, `neverlose-server.exe`, `loader.exe` returned
zero hits for "nl.bin" and "bins").

Correction (CONFIRMED): The resource script `neverlose.rc` explicitly contains:
```
IDR_BINARY              BINARY                  "bins\nl.bin"
```
This confirms that `nl.bin` IS embedded as resource ID 101 in `neverlose.dll`.
The earlier grep for "nl.bin" in binary files did not find the string because
resource names in PE resources are stored as resource IDs (integers), not as
filename strings. The resource ID 101 corresponds to `IDR_BINARY` which
references `bins\nl.bin` in the .rc file.

IMPORTANT CORRECTION: While `nl.bin` IS referenced in the resource script,
the actual bytes of `nl.bin` in the workspace do NOT match resource #101 in
the built DLL. They are completely different files (0% byte match in the
common 55,578,624-byte range). This means either:
- The `nl.bin` file was REPLACED after the DLL was built (nl.bin mtime
  7/14/2026 predates DLL mtime 9/8/2026, so it is older, not newer), OR
- The build used a DIFFERENT `nl.bin` file that has since been replaced, OR
- The `.rc` file used at build time referenced a different file than the
  current `bins\nl.bin`.

---

========================================
2. PRIOR CLAIM: "nl.bin is not a runtime-generated artifact"
========================================
Status: CONFIRMED (with clarification)

`nl.bin` is a source-tree build artifact at
`FemboyLose-main/neverlose/bins/nl.bin` (mtime 7/14/2026). It is embedded
as resource #101 (`IDR_BINARY`) in `neverlose.dll` via the .rc file. It is
NOT created at runtime by any component. This part of the prior claim
remains correct.

HOWEVER: The `nl.bin` file in the workspace is NOT the same data as resource
#101 in the built DLL. They are completely different files (0% byte match in
the common 55,578,624-byte range). This means either:
- The `nl.bin` file was REPLACED after the DLL was built, OR
- The build used a DIFFERENT `nl.bin` file that has since been replaced, OR
- The `.rc` file used at build time referenced a DIFFERENT file than the
  current `bins\nl.bin`.

---

========================================
3. PRIOR CLAIM: "Resource #101 is a 53 MB blob — format unknown"
========================================
Status: CONFIRMED (with refinement)

Resource #101 is confirmed as 55,578,628 bytes with high entropy
(7.2576 bits/byte). First 4 bytes: `a6 c0 4e c9`. It does NOT match any
known file format (PE, Lua, PNG, JPEG, ZIP, ELF). It does NOT match
`nl.bin` (completely different content).

However, the source code (`neverlose.rc`, line 52) explicitly identifies
it as `IDR_BINARY BINARY "bins\nl.bin"`. So it IS intended to be the
`nl.bin` payload, but the actual bytes in the built DLL do NOT match the
workspace `nl.bin` file.

---

========================================
4. PRIOR CLAIM: "Source/binary revision match — STRONGLY SUPPORTED"
========================================
Status: PARTIALLY CORRECTED

The source addresses (`0x41xxxxxx–0x44xxxxxx`) match the live memory
addresses, strongly suggesting the source corresponds to the running binary.
However, `imageSize` in source (`0x3501000`) differs from resource #101
size (`55,578,628` bytes = `0x3501014`) by exactly 4 bytes — revision
mismatch cannot be ruled out. The complete content mismatch between
`nl.bin` and resource #101 further supports revision mismatch.

Status: **PARTIALLY CORRECTED** — Source and binary share the same architecture
and address layout, but may be from different revisions. The resource #101
content mismatch confirms they are NOT exact matches.

---

========================================
5. PRIOR CLAIM: "Lua-side prediction exists but is fragmented"
========================================
Status: UNCHANGED

This finding from Phase 4/5 remains valid. No change based on Phase 12
investigation.

---

========================================
6. PRIOR CLAIM: "No engine forward-prediction routine located"
========================================
Status: UNCHANGED

This finding remains valid. The static analysis of the source code confirms
no forward-prediction routine in the native code. The Lua-side prediction
(`extrapolate_pos`, `rebelion v751`) is separate from the engine.

---

========================================
7. PRIOR CLAIM: "MUST UPDATE.txt unchanged"
========================================
Status: CONFIRMED

SHA256 `6929460819DC7B5A4087B73DAAF7C8F6580D0B4122046D637A222FA7EEA6BB29`
verified unchanged across all phases.

---

========================================
8. SUMMARY OF CORRECTIONS
========================================

| # | Previous Claim | New Status | Correction |
|---|---|---|---|
| 1 | `nl.bin` not referenced by any binary | CORRECTED | `nl.bin` IS resource #101 per `neverlose.rc`, but content differs |
| 2 | `nl.bin` not a runtime artifact | CONFIRMED | Still correct — source-tree build artifact |
| 3 | Resource #101 is a 53 MB blob — format unknown | CONFIRMED (refined) | Resource #101 IS `IDR_BINARY` from `bins\nl.bin`, but content differs from workspace `nl.bin` |
| 4 | Source/binary revision match — STRONGLY SUPPORTED | PARTIALLY CORRECTED | Addresses match but resource content mismatch suggests revision difference |
| 5 | `nl.bin` not referenced anywhere | CORRECTED | `nl.bin` IS referenced in `neverlose.rc` as resource ID 101 |

========================================
END OF REPORT
========================================