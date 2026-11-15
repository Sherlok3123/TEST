# PHASE11_SOURCE_PAYLOAD_PROVENANCE.md
========================================
Phase 12 — Source Payload & Resource #101 Reconciliation
========================================
Evidence-based investigation of the relationship between the on-disk
neverlose.dll (SHA256: 529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253),
its embedded resource #101 (IDR_BINARY), and the workspace source file
FemboyLose-main/neverlose/bins/nl.bin.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. REPOSITORY AND BUILD IDENTITY
========================================

1.1 Source Tree Location
--------------------------
The FemboyLose source tree is located at:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\

The tree contains:
- neverlose/          — Neverlose cheat DLL source (Visual C++ project)
- injector/           — Loader/injector source
- libraries/          — Lua runtime libraries
- server/             -- Server component (Rust + Lua)
- neverlose.sln       — Visual Studio solution file
- README.md           — Build instructions

Build instructions (from README.md):
- Build neverlose.dll as Release | x86 with v145 toolset
- Build Rust server separately with cargo build --release --locked
- Output: neverlose.dll, injector.exe, neverlose-server.exe

The source tree timestamp is 7/14/2026 8:10:33 PM (all files share this
timestamp).

Source-to-binary relationship: STRONGLY SUPPORTED. The source code
addresses (0x41xxxxxx–0x44xxxxxx range) match the live memory addresses
observed in csgo.exe, indicating the source corresponds to the running
binary's general layout. However, exact revision match cannot be confirmed
without git history or version stamps.

1.2 Repository Revision Status
------------------------------
The source tree contains no .git directory or version control metadata.
The README.md references:
- https://gs.femboy.tw
- https://git.femboy.tw/users/root/
- Official releases built by GitHub Actions from the public source repo
- "Local builds are useful for auditing, modifying, or running your own copy"
- "Local builds are NOT guaranteed to be byte-for-byte identical to the
  official GitHub Actions release artifacts."

CONCLUSION: The source may be from a different revision than the running
binary. The resource #101 content mismatch (see §4) supports this
possibility.

========================================
2. BUILD INPUT CHAIN
========================================

2.1 Source Files and Roles
---------------------------

| File | Role | Size | Evidence |
|------|------|------|----------|
| neverlose.cpp | Main DLL implementation; contains neverlose::map() | 1,984 | Source file |
| neverlose.h | Class definition; hardcodes baseAddr=0x412A0000, imageSize=0x3501000 | 1,128 | Source file |
| neverlose.rc | Resource script; defines IDR_BINARY → "bins\\nl.bin" | 3,324 | Source file |
| resource.h | Defines #define IDR_BINARY 101 | 527 | Source file |
| bins/nl.bin | Payload resource | 55,578,624 | Source tree asset |
| main.cpp | DllMain → MainThread → map() entry point | 816 | Source file |
| fix_dump.cpp | fix_imports, spoof_*, fix_*, last_resort_fixes | 3,013 | Source file |
| fix_imports.cpp | Import address table (IAT) fix-up table | 54,010 | Source file |
| fix_interfaces.cpp | Interface fixing | 47,046 | Source file |
| fix_cvars.cpp | Cvar fixing | 6,924 | Source tree |
| setup_hooks.cpp | Detour hook installation | 3,493 | Source tree |
| fix_sha256.cpp | SHA256 fixing | 2,925 | Source tree |
| crypto_capture.cpp | Hooks 0x41D9F3F0 | 391 | Source tree |
| spoof.cpp | Anti-tamper spoofing | 4,938 | Source tree |
| spoof_peb.cpp | PEB spoofing | 1,082 | Source tree |
| spoof_kusd.cpp | KUSER_SHARED_DATA spoofing | 1,130 | Source tree |
| spoof_cpuid.cpp | CPUID spoofing | 951 | Source tree |
| VEH.cpp | Vectored exception handler | 7,568 | Source tree |
| HookFn.cpp / HookFn.h | Detour hook trampoline implementation | 3,190 / 281 | Source tree |
| entry.cpp | Entry point at 0x412A0A00 | 1,657 | Source tree |

2.2 Resource Definition Chain
-----------------------------

neverlose.rc (line 52):
```
IDR_BINARY              BINARY                  "bins\nl.bin"
```

resource.h:
```
#define IDR_BINARY 101
```

neverlose.cpp:16-47 (neverlose::map()):
```cpp
void neverlose::map(HMODULE hModule)
{
    hThis = hModule;
    HRSRC hRes = FindResource(hModule, MAKEINTRESOURCE(IDR_BINARY), L"BINARY");
    ...
    HGLOBAL hResData = LoadResource(hModule, hRes);
    LPVOID pData = LockResource(hResData);
    DWORD Size = SizeofResource(hModule, hRes);
    if (Size)
        imageSize = Size;   // overwrites constructor value 0x3501000
    NtAllocateVirtualMemory(NtCurrentProcess(), &baseAddr, NULL, &imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    NtWriteVirtualMemory(NtCurrentProcess(), baseAddr, pData, imageSize, NULL);
};
```

Key observations:
- `baseAddr` initialized to `0x412A0000` (neverlose.h:28) — hardcoded
- `imageSize` initialized to `0x3501000` (55,578,624 bytes) (neverlose.h:28)
- `SizeofResource` returns 55,578,628 bytes (0x3501014) per PE repodata
- `imageSize` is overwritten by `SizeofResource` result in map()
- `NtAllocateVirtualMemory` receives `&imageSize` (passed by reference)
- `NtWriteVirtualMemory` copies `imageSize` bytes from `pData` to `baseAddr`

2.3 Build Configuration
-------------------------

The project builds as Release | x86 with v145 MSVC toolset (per README.md).
The neverlose.vcxproj project file compiles all .cpp files in the neverlose/
directory into a single DLL. No separate build steps transform or encode
nl.bin — it is embedded as-is via the .rc file.

No pre-build or post-build steps modify nl.bin. The resource is embedded
verbatim from the file on disk at build time.

========================================
3. RESOURCE #101 vs NL.BIN: BYTE-BY-BYTE COMPARISON
==================================================

3.1 Resource #101 (from on-disk neverlose.dll)

| Property | Value |
|----------|-------|
| Resource ID | 101 (IDR_BINARY) |
| Resource Type | "BINARY" (custom named type) |
| RVA | 0x0006D170 |
| File Offset | 0x00066770 (in .rsrc section) |
| Size | 55,578,628 bytes (0x3501014) |
| SHA256 | c219ed6b999bfcc1346160b8f574278460c2ae1aaf04a2a8c1da02151b02d21d |
| First 4 bytes | a6 c0 4e c9 |
| First 64 bytes | a6 c0 4e c9 43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32 36 43 77 21 63 34 62 62 |
| Last 32 bytes | 74 29 24 6a 75 77 75 71 04 30 66 24 73 25 25 76 33 64 29 0b 69 74 29 24 6a 75 77 75 71 04 30 66 |
| Known magic | NONE (not PE, Lua, PNG, JPEG, ZIP, ELF) |
| Entropy | 7.2576 bits/byte (high) |

3.2 nl.bin (source tree)

| Property | Value |
|----------|-------|
| Path | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose\bins\nl.bin |
| Size | 55,578,624 bytes (0x3501000) |
| SHA256 | 682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e |
| First 32 bytes | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |
| Last 32 bytes | 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 47 |
| First differing offset | 0x00000000 (byte 0) |
| Differing bytes in common range | 55,578,624 (100% of nl.bin length) |
| nl.bin is prefix of resource #101 | NO |
| Resource #101 is prefix of nl.bin | NO |

3.3 Comparison Conclusion

| Comparison Result | Value |
|-------------------|-------|
| Size difference | 4 bytes (resource #101 larger) |
| Matching bytes in common range | 0 of 55,578,624 |
| Differing bytes in common range | 55,578,624 |
| Relationship | Completely different files |

Resource #101 and nl.bin are COMPLETELY DIFFERENT files. They share no bytes
in common across the entire common range. This is not a header/trailer
difference — it is a complete content mismatch.

========================================
4. FOUR-BYTE SIZE DISCREPANCY: EXPLANATION STATUS
=================================================

5.1 Observed Discrepancy
------------------------

| Measurement | Value | Hex | Source |
|-------------|-------|-----|--------|
| Resource #101 size | 55,578,628 | 0x3501014 | PE resource directory |
| nl.bin size | 55,578,624 | 0x3501000 | Filesystem |
| `imageSize` initial (neverlose.h:28) | 55,578,624 | 0x3501000 | Source code |
| `SizeofResource` return value | 55,578,628 | 0x3501014 | PE resource directory |

The four-byte difference between resource #101 (55,578,628) and nl.bin
(55,578,624) is real and confirmed by direct measurement.

5.2 Possible Explanations

| Hypothesis | Evidence Status | Notes |
|------------|-----------------|-------|
| Source/binary revision mismatch | STRONGLY SUPPORTED | Source addresses match live memory, but resource content differs entirely; `imageSize` in source (0x3501000) differs from `SizeofResource` result (0x3501014) |
| `SizeofResource` returns different value at runtime | UNKNOWN | `SizeofResource` may return a different value in the built binary than what pefile reports |
| Resource #101 modified after build | UNKNOWN | nl.bin mtime (7/14/2026) predates DLL mtime (9/8/2026), suggesting nl.bin could have been replaced after build |
| Different `nl.bin` used at build time | UNKNOWN | The build may have used a different nl.bin that has since been replaced |

The four-byte difference cannot be fully explained by the available source
code alone. `neverlose.cpp:34` sets `imageSize = Size` where
`Size = SizeofResource(hThis, hRes)`. If `SizeofResource` returns 0x3501014,
then `NtAllocateVirtualMemory` would round up to page granularity (0x1000 =
4096 bytes), producing 0x3502000 — but the observed allocation is 0x3501000.
This mismatch indicates either the source code we have is not the exact
version used to build the running DLL, or `SizeofResource` returns a
different value in the built binary than what pefile reports.

========================================
6. RESOURCE #101 vs NL.BIN: NOT THE SAME FILE
=============================================

CONCLUSION: Resource #101 and nl.bin are COMPLETELY DIFFERENT files.
This has been verified by byte-by-byte comparison:

- nl.bin starts with 32 zero bytes; resource #101 starts with `a6 c0 4e c9`
- nl.bin ends with repeating `47` ('G') bytes; resource #101 ends with
  varied bytes `74 29 24 6a...`
- SHA256 hashes are completely different
- 0 bytes match in the 55,578,624-byte common range

This means either:
1. The `nl.bin` file in the workspace was replaced after the DLL was built
   (nl.bin mtime 7/14/2026 predates DLL mtime 9/8/2026, so it is older,
   not newer — meaning the DLL was built from a DIFFERENT nl.bin that has
   since been replaced)
2. The build used a different `nl.bin` file that has since been replaced
3. The `.rc` file used at build time referenced a different file than the
   current `bins\nl.bin`

========================================
7. RESOURCE #101 CONTENT ANALYSIS
=================================

Resource #101 does not match any known file format:
- Not PE (no MZ header)
- Not Lua bytecode (no \x1bLua magic)
- Not PNG, JPEG, ZIP, or ELF
- High entropy (7.2576 bits/byte) — consistent with compressed,
  encrypted, or high-randomness data

First bytes: `a6 c0 4e c9 43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32 36`
Contains a repeating pattern `Cw!c4bb1t#nL.3nc-2026` but diverges after
offset 0x18.

The format and purpose of resource #101 remain UNKNOWN.

========================================
END OF REPORT
========================================