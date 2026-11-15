# NEVERLOSE SOURCE-BINARY COVERAGE
==================================
Comparison of the available FemboyLose-main/neverlose/ C++ source tree
against the compiled neverlose.dll binary. Identifies which compiled
subsystems have corresponding source and which exist only in the binary.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

Source tree analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/
Binary analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll

========================================
1. SOURCE FILES PRESENT (CONFIRMED)
========================================

| Source file | Apparent responsibility | Status in binary |
|-------------|------------------------|------------------|
| main.cpp | DllMain + MainThread (entry, map, fix_dump, set_veh, setup_hooks, spoof, entry) | CONFIRMED — entry point 0x15560 = DllMain; bootstrap cluster present |
| entry.cpp | neverlose::entry() — suspended thread at 0x412A0A00, resume + wait | CONFIRMED (lifecycle) |
| fix_dump.cpp | fix_imports, spoof_peb/kusd/cpuid, fix_interfaces, fix_cvars, fix_signatures, NOP pads, flow fixes (~110 addrs), fix_sha256, hijack_requestor, last_resort_fixes, install_crypto_capture | CONFIRMED (imports + Nt* primitives present) |
| fix_imports.cpp | IAT fix-up table (0x43236000+) mapping ntdll/kernel32/user32/gdi32/winmm/v8/ws2_32/advapi32/ole32/combase/imm32/iphlpapi/bcrypt/crypt32 | CONFIRMED — import table present; out-of-region "[data]" call targets consistent with IAT thunks |
| fix_interfaces.cpp | Interface fixing | Not individually located in .text |
| fix_signatures.cpp | Signature fixing | Not individually located |
| fix_cvars.cpp | Cvar fixing | Not individually located |
| fix_mem_dispatcher.cpp | Memory dispatcher fix | Not individually located |
| fix_sha256.cpp | SHA256 fixing | Not individually located |
| spoof.cpp | Anti-tamper spoofing | Not individually located |
| spoof_peb.cpp | PEB spoofing | Not individually located |
| spoof_kusd.cpp | KUSER_SHARED_DATA spoofing | Not individually located |
| spoof_cpuid.cpp | CPUID spoofing | STRONGLY SUPPORTED — resource #102 is x86 CPUID code ("AuthenticAMD") |
| setup_hooks.cpp | Detour hook installation | STRONGLY SUPPORTED — .detourc/.detourd sections present |
| mem_dispatcher.cpp | Memory dispatcher | Not individually located |
| VEH.cpp | Vectored exception handler | STRONGLY SUPPORTED — set_veh() in lifecycle; SEH-wrapped functions observed (0x41496DB0, 0x4140C710) |
| HookFn.cpp | Hook trampoline | STRONGLY SUPPORTED — trampoline 0x39C21170 observed in live memory |
| Requestor.cpp | QueryLuaLibrary / GetSerial / MakeRequest (WinHTTP to 127.0.0.1:30031) | CONFIRMED — WINHTTP imports + "1:30031" strings + live server on 30031 |
| neverlose.h | Main header (g_neverlose object) | N/A (header) |
| internal_fixes.h, token.h, nops.h | Support headers | N/A (headers) |

========================================
2. SOURCE-TO-BINARY COVERAGE TABLE
========================================

Subsystem | Source present? | Binary evidence present? | Coverage level | Notes
----------|-----------------|--------------------------|----------------|------
DllMain / MainThread | YES (main.cpp) | YES (entry point 0x15560 + bootstrap cluster) | HIGH | Confirmed via PE header + live memory |
Manual self-mapping | YES (main.cpp g_neverlose.map) | YES (Nt* imports; live mapped at 0x412A0000) | HIGH | Confirmed via imports + live memory |
Import reconstruction | YES (fix_imports.cpp) | YES (import table; out-of-region call targets) | HIGH | IAT table at 0x43236000+ |
Anti-tamper / spoof | YES (spoof_*.cpp, fix_sha256.cpp) | PARTIAL (flow-fix 0xEB patches; .detourc) | MEDIUM | Individual spoof functions not located |
Detour hooks | YES (setup_hooks.cpp, HookFn.cpp) | YES (.detourc/.detourd sections; trampoline 0x39C21170) | HIGH | Sections present; hook targets not enumerated |
VEH | YES (VEH.cpp) | YES (SEH-wrapped functions: 0x41496DB0, 0x4140C710) | MEDIUM | VEH install confirmed; handler scope unknown |
HTTP / Lua request | YES (Requestor.cpp) | YES (WINHTTP imports; "1:30031"; live server) | HIGH | QueryLuaLibrary = GET /lua/<name> |
CPUID / env check | YES (spoof_cpuid.cpp) | YES (resource #102 = x86 CPUID code) | STRONG | Resource #102 confirmed as CPUID code |
Record / lag-comp | NO dedicated source | YES (0x413F9E00, 0x413F94D0, 0x4148F180, 0x41496DB0) | PARTIAL | Native-only; no matching source file identified |
Aim pipeline | NO dedicated source | YES (0x4140C710…0x41408800) | PARTIAL | Native-only; no matching source file identified |
Geometry helpers | NO dedicated source | YES (0x41400BF0, 0x413F6B40 → trampoline) | PARTIAL | Dead-end at obfuscated trampoline |
Lua VM / bindings | NO dedicated source | PARTIAL (FFI imports; lagrecord Lua lib server-side) | LOW | VM entry point not located in binary |

========================================
3. SUBSYSTEMS IN BINARY WITHOUT IDENTIFIED SOURCE
========================================

The following native subsystems were observed in the binary (via live
disassembly and/or .text analysis) but have NO corresponding source file
in FemboyLose-main/neverlose/:

| Subsystem | Key addresses (live mapped) | Evidence |
|-----------|----------------------------|----------|
| Record freshness gate | 0x413F9E00 | cmp ecx,2 at 0x413F9EC0 (extrapolation_limit patch site) |
| Lag-comp acceptability gate | 0x413F94D0 | al=1 accept default; horizontal distance vs 0x4206CDC0 |
| Record selection | 0x4148F180 | 3D distance search; single caller 0x4149789F |
| Lag-comp orchestrator | 0x41496DB0 | SEH-wrapped; origin assembly out = A[i]+B[i] |
| Origin apply | 0x41B6C700 | 10 direct callers; fn ptr [0x424B0408] |
| Small getter | 0x41B70930 | mov eax,[ecx+0x9960]; ret |
| Aim consumer entry | 0x4140C710 | SEH-wrapped; iterates entity list [0x424AFD68] |
| Aim position computation | 0x4140CB75 | Writes globals 0x425023C8/23D0/23EC |
| Vector->angle | 0x41573930 | Calls atan2 at 0x4202F7D0 |
| Angle normalize | 0x41573E80 | Calls 0x42026D1B x3 |
| Aim-struct apply | 0x41408800 | memcpy 0x71c bytes; ret 4 |
| Geometry helpers | 0x41400BF0, 0x413F6B40 | Dead-end at trampoline 0x39C21170 |

Conclusion: The compiled DLL contains substantial native logic (record
selection, lag-comp, aim pipeline, geometry helpers) for which no source
file is present in the workspace. These are either implemented in source
files not yet read (e.g., portions of fix_dump.cpp or main.cpp not fully
inspected) or exist only in the compiled binary.

========================================
4. LUA-SIDE SOURCE (SEPARATE FROM NATIVE CORE)
========================================

Lua sources present (workspace + server tree) execute INSIDE the DLL's Lua
VM; they are NOT part of the native DLL core:

| Group | Location | Count | Role |
|-------|----------|-------|------|
| Workspace scripts (*.lua / *.txt) | C:\…\MIAUSTAFF\*.lua, *.txt | ~20 | User scripts (prediction, aim, anti-aim, UI) |
| Server Lua libraries | cabbitwin\server\scripts\libraries\*.lua | ~100 | API surface served via /lua/<name> |
| Per-user scripts | cabbitwin\server\users/<hash>/scripts/ | varies | User-specific Lua scripts |

The native DLL exposes these to Lua via FFI (scan_nl, byte_patch,
VirtualProtect, FlushInstructionCache) and require("neverlose/…"). The Lua
VM entry point and the set of scripts auto-loaded at init were NOT located
in the binary or source.

========================================
5. COVERAGE SUMMARY
========================================

| Aspect | Coverage | Basis |
|--------|----------|-------|
| Bootstrap / entry / DllMain | HIGH | Source + PE header + live memory |
| Manual mapping / import fix | HIGH | Source + imports + live memory |
| Anti-tamper / spoof / hooks | MEDIUM–HIGH | Source + sections + trampoline |
| HTTP / Lua request path | HIGH | Source (Requestor.cpp) + imports + live server |
| Record / lag-comp native logic | PARTIAL | Live disassembly only; no source |
| Aim pipeline native logic | PARTIAL | Live disassembly only; no source |
| Geometry helpers | PARTIAL | Live disassembly; dead-end at trampoline |
| .rsrc (53 MB) | PARTIAL (directory only) | Resource enumeration; blob undecoded |
| .data / .rdata globals | LOW | Headers read; contents not catalogued |
| Lua VM entry / auto-load scripts | LOW | Not located in binary or source |

Overall: roughly half of the DLL's native behavior (bootstrap, mapping,
imports, hooks, HTTP/Lua request) is source-backed; the other half (record
selection, lag-comp, aim pipeline, geometry helpers) exists only in the
compiled binary with no identified source.

========================================
END
========================================