# PHASE11_EVIDENCE_MANIFEST.md
========================================
Phase 12 — Evidence Manifest
========================================
Every file inspected during Phase 12, with its path, role, hash (where
applicable), and source (workspace vs. source tree).

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

========================================
1. BINARY FILES (Analyzed)
========================================

| File | Path | Size | SHA256 | Role | Source |
|------|------|------|--------|------|--------|
| neverlose.dll | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll | 56,370,688 | 529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253 | Target binary (injected cheat core) | Local workspace |
| loader.exe | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\loader.exe | 490,496 | — | Loader/injector | Local workspace |
| neverlose-server.exe | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose-server.exe | 9,728,512 | — | Local server | Local workspace |
| nl.bin | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose\bins\nl.bin | 55,578,624 | 682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e | Resource payload source | Source tree |
| cpuid_emu.bin | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose\bins\cpuid_emu.bin | 2,921 | — | Resource #102 source | Source tree |
| kuser_shared_data.bin | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose\bins\kuser_shared_data.bin | 4,096 | — | Resource #103 source | Source tree |

========================================
2. SOURCE FILES (Analyzed)
========================================

| File | Path | Size | Role | Source |
|------|------|------|------|--------|
| neverlose.rc | FemboyLose-main/neverlose/neverlose.rc | 3,324 | Resource script; defines IDR_BINARY = 101 → bins\nl.bin | Source tree |
| resource.h | FemboyLose-main/neverlose/resource.h | 527 | #define IDR_BINARY 101 | Source tree |
| neverlose.cpp | FemboyLose-main/neverlose/neverlose.cpp | 1,984 | neverlose::map() — reads resource #101, allocates memory, writes to 0x412a0000 | Source tree |
| neverlose.h | FemboyLose-main/neverlose/neverlose.h | 1,128 | Defines baseAddr = 0x412A0000, imageSize = 0x3501000 | Source tree |
| main.cpp | FemboyLose-main/neverlose/main.cpp | 816 | DllMain → MainThread → map() entry point | Source tree |
| fix_dump.cpp | FemboyLose-main/neverlose/fix_dump.cpp | 3,013 | fix_imports, spoof_*, fix_*, last_resort_fixes | Source tree |
| fix_imports.cpp | FemboyLose-main/neverlose/fix_imports.cpp | 54,010 | g_imports array — IAT fix-up table | Source tree |
| fix_interfaces.cpp | FemboyLose-main/neverlose/fix_interfaces.cpp | 47,046 | Interface fixing | Source tree |
| fix_cvars.cpp | FemboyLose-main/neverlose/fix_cvars.cpp | 6,924 | Cvar fixing | Source tree |
| setup_hooks.cpp | FemboyLose-main/neverlose/setup_hooks.cpp | 3,493 | Detour hook installation | Source tree |
| fix_sha256.cpp | FemboyLose-main/neverlose/sha256.cpp | 2,925 | SHA256 fixing | Source tree |
| crypto_capture.cpp | FemboyLose-main/neverlose/crypto_capture.cpp | 391 | Hooks 0x41D9F3F0 | Source tree |
| spoof.cpp | FemboyLose-main/neverlose/spoof.cpp | 4,938 | Anti-tamper spoofing | Source tree |
| spoof_peb.cpp | FemboyLose-main/neverlose/spoof_peb.cpp | 1,082 | PEB spoofing | Source tree |
| spoof_kusd.cpp | FemboyLose-main/neverlose/spoof_kusd.cpp | 1,130 | KUSER_SHARED_DATA spoofing | Source tree |
| spoof_cpuid.cpp | FemboyLose-main/neverlose/spoof_cpuid.cpp | 951 | CPUID spoofing | Source tree |
| setup_hooks.cpp | FemboyLose-main/neverlose/setup_hooks.cpp | 3,493 | Detour hook installation | Source tree |
| HookFn.cpp | FemboyLose-main/neverlose/HookFn.cpp | 3,190 | Detour hook trampoline implementation | Source tree |
| HookFn.h | FemboyLose-main/neverlose/HookFn.h | 281 | Hook function header | Source tree |
| entry.cpp | FemboyLose-main/neverlose/entry.cpp | 1,657 | Entry point at 0x412A0A00 | Source tree |
| missingent.cpp | FemboyLose-main/neverlose/missingent.cpp | 4,967 | Missing entity fix | Source tree |
| mem_dispatcher.cpp | FemboyLose-main/neverlose/mem_dispatcher.cpp | 3,910 | Memory dispatcher | Source tree |
| neverlosesdk.hpp | FemboyLose-main/neverlose/neverlosesdk.hpp | 1,280 | SDK header | Source tree |
| json.hpp | FemboyLose-main/neverlose/json.hpp | 919,974 | JSON library | Source tree |

========================================
3. ANALYSIS SCRIPTS (Created in this phase)
========================================

| File | Path | Role | Source |
|------|------|------|--------|
| phase12_resource_compare.py | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\_audit\phase12_resource_compare.py | Compares resource #101 with nl.bin | Created this phase |

========================================
4. DELIVERABLE DOCUMENTS (Created in this phase)
========================================

| File | Path | Role | Source |
|------|------|------|--------|
| PHASE11_SOURCE_PAYLOAD_PROVENANCE.md | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\PHASE11_SOURCE_PAYLOAD_PROVENANCE.md | Main provenance report | Created this phase |
| PHASE11_BINARY_COMPARISON.txt | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\PHASE11_BINARY_COMPARISON.txt | Machine-readable comparison | Created this phase |
| PHASE11_PRIOR_CLAIM_CORRECTIONS.md | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\PHASE11_PRIOR_CLAIM_CORRECTIONS.md | Corrections to previous phases | Created this phase |
| PHASE11_EVIDENCE_MANIFEST.md | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\PHASE11_EVIDENCE_MANIFEST.md | Evidence manifest | Created this phase |

========================================
5. EXISTING DOCUMENTS (Referenced but not modified)
========================================

| File | Path | Role |
|------|------|------|
| MUST UPDATE.txt | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\MUST UPDATE.txt | Original target; SHA256 verified unchanged |
| NEVERLOSE_DLL_DEEP_ANALYSIS.md | .../MIAUSTAFF/NEVERLOSE_DLL_DEEP_ANALYSIS.md | Phase 6 analysis |
| PREDICTION_PIPELINE.md | .../MIAUSTAFF/PREDICTION_PIPELINE.md | Phase 6 prediction pipeline |
| PREDICTION_FUNCTION_MAP.md | .../MIAUSTAFF/PREDICTION_FUNCTION_MAP.md | Phase 6 function map |
| PREDICTION_DATA_FLOW.md | .../MIAUSTAFF/PREDICTION_DATA_FLOW.md | Phase 6 data flow |
| PREDICTION_API_GAPS.md | .../MIAUSTAFF/PREDICTION_API_GAPS.md | Phase 6 API gaps |
| EXTRAPOLATION_ANALYSIS.md | .../MIAUSTAFF/EXTRAPOLATION_ANALYSIS.md | Extrapolation analysis |
| DISCREPANCY_REPORT.md | .../MIAUSTAFF/DISCREPANCY_REPORT.md | Post-audit review |
| PHASE10_SOURCE_RUNTIME_RECONCILIATION.md | .../MIAUSTAFF/PHASE10_SOURCE_RUNTIME_RECONCILIATION.md | Phase 10 reconciliation |

========================================
6. SUMMARY OF EVIDENCE GRADES
========================================

| Claim | Grade | Evidence |
|-------|-------|----------|
| `nl.bin` is resource #101 source | CONFIRMED | `neverlose.rc` line 52: `IDR_BINARY BINARY "bins\nl.bin"` |
| Resource #101 size = 55,578,628 bytes | CONFIRMED | PE resource directory |
| `nl.bin` size = 55,578,624 bytes | CONFIRMED | Filesystem stat |
| Resource #101 and nl.bin are DIFFERENT files | CONFIRMED | 0% byte match in 55,578,624-byte common range |
| Source/binary addresses match | STRONGLY SUPPORTED | `0x41xxxxxx–0x44xxxxxx` in both |
| Source/binary revision match | UNKNOWN | Resource content mismatch suggests different revision |
| `SizeofResource` returns 0x3501014 | CONFIRMED | PE resource directory |
| Allocation size is 0x3501000 | CONFIRMED | VirtualQueryEx read |
| `NtWriteVirtualMemory` copies `imageSize` bytes | SOURCE-CONFIRMED | `neverlose.cpp:45-46` |
| Resource #101 and `nl.bin` are same file | CONTRADICTED | 0% byte match in common range |

========================================
END OF MANIFEST
========================================