# NEVERLOSE ADDRESS MAPPING CORRECTIONS
=======================================
Phase 7 corrections to address/RVA claims made in earlier reports
(NEVERLOSE_COMPLETE_ARCHITECTURE.md, NEVERLOSE_COMPONENT_ANALYSIS.md,
NEVERLOSE_SOURCE_RECOVERY.md, NEVERLOSE_NATIVE_FUNCTION_INVENTORY.md,
NEVERLOSE_RUNTIME_IMAGE_RECONCILIATION.md). Corrections are made here
rather than silently carried forward.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

All addresses are file RVAs (on-disk) unless explicitly labeled "runtime".

========================================
1. ENTRY POINT ARITHMETIC — CORRECTED (CONFIRMED)
=================================================

Earlier reports stated: neverlose.dll entry point at runtime `0x412A15560`
(i.e., base `0x412A0000` + `0x15560` mis-added).

Correction (CONFIRMED):
  `0x412A0000 + 0x15560 = 0x412B5560`, NOT `0x412A15560`.
  The PE entry-point RVA is `0x15560`; added to base `0x412A0000` the result
  is `0x412B5560`.

Live-byte check at `0x412B5560`: `00 00 8d 46 24 50 89 cf` — does NOT match
on-disk entry bytes `55 8b ec 83 7d 0c 01 75`. So even the corrected address
does not yield the DllMain prologue, reinforcing that the runtime image is
not a simple rebasing of the on-disk DLL (see reconciliation report).

All prior references to entry point `0x412A15560` are CONTRADICTED; use
`0x412B5560` as the corrected (but still unverified) candidate, or treat the
entry point location as UNKNOWN at runtime.

========================================
2. MAPPING BASE `0x412A0000` — CONTRADICTED AS A PE IMAGE BASE
==============================================================

Earlier reports treated `0x412A0000` as the manual-mapping base of a PE
image containing `neverlose.dll`.

Correction (CONFIRMED): The allocation base `0x412A0000` contains all zeros
(first 64 bytes); `e_lfanew` at `0x412A003C` is `0`; there is no `MZ`/`PE`
signature at the base or at `base + e_lfanew`. It is NOT the base of a
mapped PE module.

Therefore any address computation of the form `0x412A0000 + <on-disk RVA>`
is invalid for locating `neverlose.dll` code in memory. All function
attributions that relied on this base are downgraded to UNVERIFIED.

========================================
3. REPORTED FUNCTION ADDRESSES — ALL DOWNGRADED TO UNVERIFIED
==============================================================

The following addresses were reported as `neverlose.dll` functions. Live
memory contains real x86 code at each, but NONE match any byte sequence in
the on-disk `neverlose.dll` (SHA256 529c59bd…). Offsets from base
`0x412A0000` land inside `.rsrc` (not `.text`). Attributions are therefore
UNVERIFIED, not CONFIRMED.

| Address | Earlier role | Status now | Reason |
|---------|--------------|------------|--------|
| 0x413F94D0 | lag-comp acceptability gate | UNVERIFIED | live code real; not in on-disk DLL |
| 0x413F9E00 | record freshness gate | UNVERIFIED | live code real; not in on-disk DLL |
| 0x4148F180 | record selection | UNVERIFIED | live code real; not in on-disk DLL |
| 0x41496DB0 | lag-comp orchestrator | UNVERIFIED | live code real; not in on-disk DLL |
| 0x4140C710 | aim consumer entry | UNVERIFIED | live code real; not in on-disk DLL |
| 0x4140CB75 | aim position computation | UNVERIFIED | live code real; not in on-disk DLL |
| 0x41573930 | vector->angle | UNVERIFIED | live code real; not in on-disk DLL |
| 0x41573E80 | angle normalize | UNVERIFIED | live code real; not in on-disk DLL |
| 0x41408800 | aim-struct apply | UNVERIFIED | live code real; not in on-disk DLL |
| 0x41B6C700 | origin apply | UNVERIFIED | live code real; not in on-disk DLL |

Internal call consistency (e.g., `0x4140CB75` calls `0x41B6C700`) is
CONFIRMED within live memory, but that only proves the addresses form a
coherent code region — it does NOT prove they belong to `neverlose.dll`.

========================================
4. MAPPED-IMAGE SIZE — CORRECTED (CONFIRMED)
=============================================

Earlier reports stated Block 1 `0x412A0000–0x4205A000` (size `0x00DBA000`)
and Block 2 `0x4205A000–0x42239000` (size `0x001DF000`), combined `0x00F99000`.

Correction (CONFIRMED): The combined reported range `0x00F99000` (~15.7 MB)
is substantially smaller than PE SizeOfImage `0x035CA000` (~53.8 MB). The
`.rsrc` section alone (`0x03557150` ≈ 53 MB) exceeds the entire combined
reported range. Therefore the reported ranges cannot accommodate the full
on-disk `neverlose.dll` image, and the described "two-block mapping" is
INCOMPLETE / INVALID as a description of the DLL image.

The digit-transpose error (`0x4134BA000` instead of `0x4205A000`) noted in
earlier corrections is superseded: the base itself is not a PE image base
(see §2), so the whole range description is unreliable.

========================================
5. FUNCTION-TO-DLL ATTRIBUTIONS — SUMMARY OF DOWNGRADES
========================================================

| Previously claimed | New status | Basis |
|--------------------|------------|-------|
| neverlose.dll entry point at `0x412A15560` | CONTRADICTED | bad arithmetic; corrected `0x412B5560`; no match in live memory |
| `0x412A0000` = manual-mapping PE base | CONTRADICTED | base is all zeros; no PE header |
| Reported 10 function addresses = neverlose.dll functions | UNVERIFIED | live code real; zero byte matches to on-disk DLL |
| `.text` maps to `0x412A1000–0x412D907A` | UNVERIFIED | depends on invalid base |

No function in the range `0x413F0000–0x41B60000` can be attributed to the
on-disk `neverlose.dll` based on current evidence.

========================================
6. WHAT REMAINS CONFIRMED (unaffected by these corrections)
==========================================================

The following are NOT changed by this phase, because they rest on different
evidence:

  - On-disk `neverlose.dll` PE headers, sections, entropy, and SHA256
    (verified directly from the file).
  - The `.rsrc` enumeration (6 entries; #101 53 MB blob undecoded; #102
    CPUID code; #104 PNG; #105 JPEG; RT_MANIFEST) — verified from the file.
  - `neverlose-server.exe` is running (PID 11468) and listens on
    `127.0.0.1:30031` (verified by connect test).
  - `csgo.exe` was running (PID 21580) and readable.
  - `loader.exe` imports (injection APIs, WININET) and strings — from the
    on-disk loader binary.
  - `neverlose.dll` imports (WINHTTP, Nt* manual-mapping primitives) — from
    the on-disk DLL.

What IS changed: any claim that tied a specific live runtime address to a
specific function in the on-disk `neverlose.dll`. Those are now UNVERIFIED.

========================================
END
========================================