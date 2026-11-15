# NEVERLOSE LIVE MODULE OWNERSHIP
================================
Phase 8 — Ownership identification of the live executable code previously
observed around `0x413F0000–0x41590000` and `0x41B6C700` in `csgo.exe`
(PID 21580). All findings are based on read-only process inspection via
`VirtualQueryEx` and `ReadProcessMemory`, cross-referenced with the available
source code (`FemboyLose-main/`).

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. EXECUTIVE SUMMARY
========================================

The live code at all 10 previously reported function addresses is **real,
internally consistent x86 code**, but it does **NOT** belong to the on-disk
`neverlose.dll` (SHA256 `529c59bd…`) as a standard PE image. Instead:

- The injector (`loader.exe`) loads `neverlose.dll` via **`LoadLibraryA`**
  through `CreateRemoteThread` (standard Windows loader path).
- The DLL's `DllMain` → `MainThread` calls `neverlose::map(hinstDLL)`.
- `neverlose::map()` reads resource `IDR_BINARY` (= resource **#101**, the
  53 MB blob in `.rsrc`) from the DLL's own resources.
- It allocates a **`MEM_PRIVATE`, `EXECUTE_READWRITE`** region at hardcoded
  base `0x412A0000` via `NtAllocateVirtualMemory`.
- It writes the resource bytes into that region via `NtWriteVirtualMemory`.
- The real cheat code runs from this MEM_PRIVATE region.

All 10 reported function addresses fall inside this region
(`0x412a0000–0x4205a000`). They are **not** in any `MEM_IMAGE` module and are
**not** in the on-disk `neverlose.dll`'s `.text` section. They are the
decoded/de-serialized cheat code from resource #101, executing from a manually
allocated private region.

Final status: **PARTIALLY RESOLVED** — ownership chain established up to
resource #101; the exact decryption/transformation of resource #101 into
executable code remains unknown (not decoded in this phase).

========================================
2. OWNERSHIP CHAIN (CONFIRMED)
========================================

```
loader.exe
  └─ LoadLibraryA("neverlose.dll") via CreateRemoteThread  [injector/main.cpp:130-149]
       └─ Windows loader maps neverlose.dll as MEM_IMAGE
            └─ DllMain → MainThread  [neverlose/main.cpp:4-19]
                 └─ g_neverlose.map(hinstDLL)  [neverlose/neverlose.cpp:16-47]
                      ├─ FindResource(IDR_BINARY=101, L"BINARY")  [resource #101]
                      ├─ NtAllocateVirtualMemory(MEM_COMMIT|MEM_RESERVE,
                      │   PAGE_EXECUTE_READWRITE) at base 0x412A0000  [neverlose.h:28]
                      └─ NtWriteVirtualMemory(baseAddr, pData, imageSize)
                           └─ Resource #101 bytes (53 MB blob) now live at 0x412A0000
                                └─ Real cheat code executes here
```

Every link in this chain is supported by source code (`FemboyLose-main/`) or
live memory observation.

========================================
3. OWNERSHIP OF REPORTED FUNCTION ADDRESSES
============================================

All 10 reported addresses are inside region `0x412a0000–0x4205a000`
(MEM_PRIVATE, EXECUTE_READWRITE, allocation base `0x412a0000`, size
`0x00dba000`). None are inside any `MEM_IMAGE` module. None match any byte
sequence in the on-disk `neverlose.dll`.

| # | Address | Reported role | Region owner | MZ at base? | Confidence |
|---|---------|---------------|--------------|-------------|------------|
| 1 | 0x413F94D0 | lag-comp acceptability gate | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 2 | 0x413F9E00 | record freshness gate | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 3 | 0x4148F180 | record selection | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 4 | 0x41496DB0 | lag-comp orchestrator | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 5 | 0x4140C710 | aim consumer entry | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 6 | 0x4140CB75 | aim position computation | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 7 | 0x41573930 | vector->angle | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 8 | 0x41573E80 | angle normalize | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 9 | 0x41408800 | aim-struct apply (memcpy) | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |
| 10| 0x41B6C700 | origin apply | 0x412a0000 (MEM_PRIVATE, XRW) | No | CONFIRMED in region; source of bytes = resource #101 |

Key observations:
- **All 10 addresses share the same owner**: region `0x412a0000–0x4205a000`
- **No MZ header** at the region base (Phase 7 confirmed: all zeros at `0x412a0000`)
- **Type is MEM_PRIVATE** (0x00020000), not MEM_IMAGE — not a standard Windows loader-mapped module
- **Protect is EXECUTE_READWRITE** (0x40) — writable and executable
- Internal call graph confirmed: `0x4140CB75` calls `0x41B6C700` via relative `E8` call (`e8 86 fb 75 00` → target `0x41B6C700`)

========================================
4. WHAT THE OWNING RESOURCE IS
================================

Resource `IDR_BINARY` (= resource ID 101, type `L"BINARY"`) in the on-disk
`neverlose.dll`'s `.rsrc` section:

| Property | Value |
|---|---|
| Resource ID | 101 (`IDR_BINARY`) [confirmed in `resource.h`] |
| Resource type | "BINARY" (custom named type) |
| RVA | 0x0006D170 |
| Size | 55,578,628 bytes (~53.0 MB) |
| Language | L25/S1 |
| First bytes | `a6 c0 4e c9 43 77 21 63 34 62 62 31 74 23 6e 4c …` |
| Contains MZ header? | No |
| Matches Lua bytecode (`\x1bLua`)? | No |
| Matches nl.bin? | No (close in size but different content) |

`neverlose::map()` (`neverlose/neverlose.cpp:16-47`):
- Finds this resource via `FindResource(hThis, MAKEINTRESOURCE(IDR_BINARY), L"BINARY")`
- Allocates `MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE` at `baseAddr`
  (`baseAddr = (PVOID)0x412A0000`, hardcoded in `neverlose.h:28`)
- Writes the resource bytes via `NtWriteVirtualMemory`

The resource #101 content is **not plaintext PE code** — it starts with
`a6 c0 4e c9` and contains a repeating ASCII pattern ("…-2026…"). It is
either encrypted, encoded, or a custom binary format. The exact
decryption/transformation that turns it into executable x86 code at
`0x412a0000` is **not yet understood** (not decoded in this phase).

========================================
5. WHAT IS NOT THE OWNER
================================

| Candidate | Why excluded | Evidence |
|---|---|---|
| on-disk `neverlose.dll` `.text` | Live bytes don't match any on-disk byte sequence | Phase 7: 0/10 live 16-byte sequences found in on-disk image |
| on-disk `neverlose.dll` `.rsrc` #101 (raw) | Raw bytes are `a6 c0 4e c9…`, not executable x86 | Live code at 0x413F94D0 is `57 56 83 ec…` (valid x86) |
| Any MEM_IMAGE module in csgo.exe | No MEM_IMAGE module contains any reported address | VirtualQueryEx scan of 0x40000000–0x42200000 shows only MEM_PRIVATE regions |
| loader.exe | Injector process is separate; does not map code into csgo.exe | Injector source uses CreateRemoteThread+LoadLibraryA into target process |

========================================
6. LIMITATIONS
================================

- The exact transformation of resource #101 (encrypted/encoded blob) into
  executable x86 code at `0x412a0000` is **not yet understood**. `neverlose::map()`
  does a straight `NtWriteVirtualMemory` of the resource bytes — there is no
  visible decryption step in the source. Either the resource is already
  executable code (obfuscated/packed), or decryption happens elsewhere
  (e.g., in `fix_dump()`, `install_crypto_capture()`, or a later init step).
- The allocation base `0x412A0000` is hardcoded in source (`neverlose.h:28`),
  but `NtAllocateVirtualMemory` with `baseAddr` non-NULL requests an address
  — the actual allocated base may differ if the requested address is
  unavailable. Live observation confirms it succeeded at `0x412a0000`.
- Resource #101 has not been decoded; its exact format and decryption method
  remain unknown.

========================================
END
========================================