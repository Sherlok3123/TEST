# PHASE11_FINAL_ASSESSMENT.md
========================================
Phase 12 — Final Assessment Report
========================================
Evidence-based assessment of the Neverlose.dll source/resource/runtime
correlation investigation.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. OVERALL VERDICT
========================================

**PARTIALLY RESOLVED**

The relationship between `neverlose.dll` resource #101 (`IDR_BINARY`) and the
source file `nl.bin` has been definitively established: they are COMPLETELY
DIFFERENT files. However, the transformation from resource #101 bytes to live
executable memory remains UNKNOWN.

========================================
2. SOURCE/BUILD IDENTITY ASSESSMENT
========================================

2.1 Source Tree
- Location: `C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\`
- Source timestamp: 7/14/2026 8:10:33 PM (all files share this timestamp)
- Build configuration: Release | x86, MSVC v145 toolset
- Build outputs: `neverlose.dll`, `injector.exe`, `neverlose-server.exe`

2.2 Binary Identity
- `neverlose.dll`: SHA256 `529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253`
- Mtime: 9/8/2026 9:15:15 PM (AFTER source timestamp of 7/14/2026)

2.3 Source/Binary Relationship
- Source addresses (`0x41xxxxxx–0x44xxxxxx`) match live memory addresses
  (**STRONGLY SUPPORTED**)
- However, resource #101 content does NOT match workspace `nl.bin`
  (**CONTRADICTED**)
- Source revision may differ from running binary revision (**UNKNOWN**)

========================================
3. CORRECTIONS TO PREVIOUS PHASES
====================================

| # | Previous Claim | New Status | Correction | Evidence |
|---|---|---|---|---|
| 1 | `nl.bin` not referenced by any binary | CORRECTED | `nl.bin` IS resource #101 per `neverlose.rc` line 52, but content differs completely | `neverlose.rc` line 52; byte comparison |
| 2 | `nl.bin` not a runtime artifact | CONFIRMED | Still correct — source-tree build artifact | Filesystem metadata |
| 3 | Resource #101 is a 53 MB blob — format unknown | CONFIRMED (refined) | Resource #101 IS `IDR_BINARY` from `bins\nl.bin`, but content differs from workspace `nl.bin` | `neverlose.rc`; byte comparison |
| 4 | Source/binary revision match — STRONGLY SUPPORTED | PARTIALLY CORRECTED | Addresses match but resource content mismatch suggests revision difference | Source/disassembly comparison; resource content mismatch |
| 5 | `nl.bin` not referenced anywhere | CORRECTED | `nl.bin` IS referenced in `neverlose.rc` as resource ID 101 | `neverlose.rc` line 52 |

---

## 4. WHAT IS NOW DEFINITELY UNDERSTOOD
====================================

4.1 Build Pipeline (CONFIRMED)
- `neverlose.rc` embeds `bins\nl.bin` as resource ID 101 (`IDR_BINARY`)
- `neverlose::map()` reads resource #101 via `FindResource`/`LoadResource`/`LockResource`
- `map()` allocates `MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE` at hardcoded base `0x412A0000`
- `map()` copies resource bytes via `NtWriteVirtualMemory` to the allocation
- Allocation size is `0x3501000` (55,578,624 bytes) per `neverlose.h:28`
- `SizeofResource` returns 55,578,628 bytes (`0x3501014`) per PE resource directory

4.2 Resource #101 vs nl.bin (CONFIRMED DIFFERENCE)
- Resource #101: 55,578,628 bytes, SHA256 `c219ed6b...`, starts `a6 c0 4e c9`
- nl.bin: 55,578,624 bytes, SHA256 `682ce73b...`, starts `00 00 00 00`
- 0% byte match in 55,578,624-byte common range
- First difference at offset 0x00000000

4.3 Four-Byte Size Discrepancy (UNRESOLVED)
- Resource #101: 55,578,628 bytes (`0x3501014`)
- Allocation: 55,578,624 bytes (`0x3501000`)
- Difference: 4 bytes
- If `SizeofResource` returns 0x3501014, `NtAllocateVirtualMemory` would round UP to 0x3502000, but observed allocation is 0x3501000
- If `SizeofResource` returns 0x3501000, allocation matches, but pefile reports 0x3501014
- Either source/binary revision mismatch or `SizeofResource` behavior differs at runtime

========================================
5. WHAT REMAINS UNKNOWN
====================================

5.1 Resource #101 Format (UNKNOWN)
- Not PE, Lua, PNG, JPEG, ZIP, ELF
- First bytes `a6 c0 4e c9` do not match any known magic
- Contains repeating pattern `Cw!c4bb1t#nL.3nc-2026` but diverges after offset 0x18
- Entropy 7.2576 bits/byte (consistent with compressed/encrypted data)
- Decoding method UNKNOWN

5.2 Resource #101 → Live Memory Transformation (UNKNOWN)
- `neverlose::map()` does straight `NtWriteVirtualMemory` copy
- Live memory at `0x412a0000` is all zeros, but resource #101 starts with `a6 c0 4e c9`
- NO source function decrypts/decompresses/transforms the mapped image
- Either source/binary revision mismatch, or transformation occurs in unreviewed code

5.3 Source/Binary Revision Match (UNKNOWN)
- Addresses match live memory layout
- But resource content mismatch suggests different revision
- No git history or version stamps available to confirm

5.4 Actual Source of Resource #101 (UNKNOWN)
- Resource #101 does NOT match workspace `nl.bin`
- Source of the actual resource content in the built DLL is unknown
- Either `nl.bin` was replaced after build, or a different file was used at build time

---

## 6. EVIDENCE CLASSIFICATION TABLE
====================================

| Claim | Classification | Evidence |
|-------|---------------|----------|
| `neverlose::map()` reads resource #101 | SOURCE-CONFIRMED | `neverlose.cpp:19-30` |
| `neverlose::map()` allocates at `0x412a0000` | SOURCE-CONFIRMED | `neverlose.h:28` |
| `neverlose::map()` writes resource via `NtWriteVirtualMemory` | SOURCE-CONFIRMED | `neverlose.cpp:45-46` |
| Resource #101 size = 55,578,628 bytes | CONFIRMED | PE resource directory |
| Allocation total = 55,578,624 bytes (`0x3501000`) | RUNTIME-OBSERVED | VirtualQueryEx walk |
| Allocation base = `0x412a0000` | CONFIRMED | `neverlose.h:28` + VirtualQueryEx |
| Live memory at `0x412a0000` = `00 00 00 00` | RUNTIME-OBSERVED | ReadProcessMemory |
| Resource #101 at offset 0 = `a6 c0 4e c9` | CONFIRMED | PE resource extraction |
| Live bytes match on-disk `neverlose.dll` | CONTRADICTED | 0/10 live 16-byte sequences matched (Phase 7) |
| Resource bytes match live bytes at base | CONTRADICTED | `a6 c0 4e c9` vs `00 00 00 00` |
| `fix_dump()` decrypts mapped image | NOT SUPPORTED | Full source review — no such step |
| `install_crypto_capture()` transforms mapped image | NOT SUPPORTED | Hooks `0x41D9F3F0`, does not touch mapped image |
| Function role assignments | INFERRED | Disassembly patterns, no symbols |
| Source/binary revision match | STRONGLY SUPPORTED | Addresses match; size mismatch suggests possible difference |
| Resource → live-code transformation | UNKNOWN | Not explained by source or runtime evidence |

---

## 7. WHAT WOULD RESOLVE THE REMAINING UNKNOWN
====================================

1. **Memory dump of `0x412a0000` immediately after `neverlose::map()` completes** — before `fix_dump()`/`set_veh()`/`setup_hooks()`/`spoof()`/`entry()` run. This would show whether resource bytes are written correctly and then transformed, or never written at all.

2. **Complete source review of unexamined files**: `fix_interfaces.cpp`, `fix_cvars.cpp`, `fix_signatures.cpp`, `fix_mem_dispatcher.cpp`, `spoof.cpp`, `spoof_peb.cpp`, `spoof_kusd.cpp`, `spoof_cpuid.cpp`, `HookFn.cpp`, `VEH.cpp`, `missingent.cpp` — any of these could contain a transformation step.

3. **Resource #101 decoding** — Determine whether the resource is encrypted, compressed, or encoded, and with what algorithm/key.

4. **Build metadata verification** — Confirm whether the source tree matches the exact binary revision that was built.

---

## 8. FINAL ASSESSMENT
====================================

The Neverlose.dll architecture is now well-documented at the structural level:
- Loader (`loader.exe`) injects `neverlose.dll` via `CreateRemoteThread` + `LoadLibraryA`
- DLL self-maps at `0x412a0000` via `neverlose::map()`, which reads resource #101 (`IDR_BINARY`) and copies it via `NtWriteVirtualMemory`
- `fix_dump()` performs import fixing, anti-tamper spoofing, hook installation, and byte patching
- `entry()` starts the cheat runtime at `0x412A0A00`

The engine-side code (record selection, lag compensation, aim pipeline) exists only in the manually mapped region at `0x412a0000+`, NOT in the on-disk `neverlose.dll`. The Lua-side prediction (`extrapolate_pos`, `rebelion v751`) is separate from the engine.

**The resource-to-runtime transformation remains UNKNOWN** — this is the single most important unresolved question in the entire investigation.

---  
*End of PHASE11_FINAL_ASSESSMENT.md*