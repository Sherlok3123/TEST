# NEVERLOSE RESOURCE RUNTIME CORRELATION
========================================
Phase 9 Investigation D — Relationship between resource #101 (`IDR_BINARY`)
inside the on-disk `neverlose.dll` and the live executable code observed in
`csgo.exe` memory at `0x412a0000+`.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

Source files analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll (on-disk)
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/neverlose.cpp
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/neverlose.h
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/main.cpp

Runtime process: `csgo.exe` PID 21580

========================================
1. RESOURCE #101 (ON-DISK) — SUMMARY
====================================

| Property | Value |
|---|---|
| Resource ID | 101 (`IDR_BINARY`) |
| Resource type | `L"BINARY"` (custom named type) |
| RVA | 0x0006d170 |
| File offset | 0x00066770 |
| Size | 55,578,628 bytes (53.00 MB) |
| First 4 bytes | `a6 c0 4e c9` |
| Bytes 4–23 | `43 77 21 63 34 62 62 31 74 23 6e 4c 2e 33 6e 63 2d 32 30 32` |
| | = ASCII `Cw!c4bb1t#nL.3nc-202` |
| Entropy | 7.2576 bits/byte (high) |
| Known magic | None (not PE, Lua, PNG, JPEG, ZIP, ELF) |

CONFIRMED from PE resource enumeration + raw byte analysis.

========================================
2. LIVE ALLOCATION — SUMMARY
==============================

| Property | Value |
|---|---|
| Allocation base | 0x412a0000 |
| Total size | 0x3501000 (55,578,624 bytes) |
| Type | MEM_PRIVATE (all 7 regions) |
| Region 1 | 0x412a0000–0x4205a000, EXECUTE_READWRITE, 0xdba000 |
| Region 2 | 0x4205a000–0x42239000, READONLY, 0x1df000 |
| Region 3 | 0x42239000–0x4252b000, EXECUTE_READWRITE, 0x2f2000 |
| Region 4 | 0x4252b000–0x42553000, EXECUTE_READ, 0x28000 |
| Region 5 | 0x42553000–0x42559000, READWRITE, 0x6000 |
| Region 6 | 0x42559000–0x43236000, EXECUTE_READ, 0xcdd000 |
| Region 7 | 0x43236000–0x447a1000, EXECUTE_READWRITE, 0x156b000 |
| MZ header at base | NO (all zeros) |

CONFIRMED from VirtualQueryEx region walk + ReadProcessMemory.

========================================
3. RESOURCE-TO-RUNTIME BYTE COMPARISON
=======================================

`neverlose::map()` (`neverlose.cpp:16-47`) performs:

```cpp
NtAllocateVirtualMemory(NtCurrentProcess(), &baseAddr, NULL, &imageSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
NtWriteVirtualMemory(NtCurrentProcess(), baseAddr, pData, imageSize, NULL);
```

This is a **straight memory copy** of the entire resource #101 to the
allocation base. No decryption, decompression, or transformation is visible
in the source code for `map()`.

However, the live bytes do NOT match the resource bytes:

| Location | First bytes | Match? |
|---|---|---|
| Resource #101 offset 0 | `a6 c0 4e c9 43 77 21 63...` | N/A (source) |
| Live memory at 0x412a0000 | `00 00 00 00 00 00 00 00...` | NO — all zeros |
| Live memory at 0x413f94d0 | `57 56 83 ec 0c 8b 15 28 f4 23 42...` | NO — not in on-disk DLL |

CONFIRMED: Live memory at `0x412a0000` is all zeros, but resource #101 starts
with `a6 c0 4e c9`. If `map()` wrote the resource starting at byte 0 to
`baseAddr`, the first 4 bytes at `0x412a0000` would be `a6 c0 4e c9`, not
zeros.

CONFIRMED: Live code at `0x413f94d0` (`0x412a0000 + 0x1594d0`) is `57 56 83 ec...`
(valid x86: `push edi; push esi; sub esp,0xc; ...`), but this byte sequence
does NOT appear anywhere in the on-disk `neverlose.dll`.

========================================
4. SIZE DISCREPANCY
===================

| Value | Bytes | Hex |
|---|---|---|
| Resource #101 size (`SizeofResource`) | 55,578,628 | 0x3501014 |
| Observed allocation total size | 55,578,624 | 0x3501000 |
| Difference | 4 | 0x4 |

CONFIRMED from resource enumeration + VirtualQueryEx region walk.

The 4-byte difference exactly matches the first 4 bytes of the resource
(`a6 c0 4e c9`). Two interpretations:

1. **The first 4 bytes are NOT copied** — `map()` might skip the header and
   write only bytes 4..end (55,578,624 bytes) to the allocation. But the
   source code shows `NtWriteVirtualMemory(baseAddr, pData, imageSize, ...)`
   where `imageSize` = `SizeofResource` = full resource size, which would
   include the first 4 bytes. Unless `imageSize` is modified between
   `SizeofResource` and `NtWriteVirtualMemory`, which the source does not
   show.

2. **The first 4 bytes ARE copied but then zeroed** — Some later step
   (`fix_dump()`, `entry()`, or another function) zeroes the first 4 bytes
   of the allocation. No such step is visible in the source we reviewed.

3. **The source code revision does not match the running binary** — The
   source might be from a different version where `map()` behaves differently
   (e.g., skips the header, or applies a transformation).

All three are possible; none can be confirmed from the available evidence.

========================================
5. INTERNAL CALL CONSISTENCY (LIVE)
====================================

Despite the byte mismatch with on-disk `neverlose.dll`, the live code at the
reported addresses forms a coherent, internally consistent call graph:

| Address | Instruction | Target |
|---|---|---|
| 0x4140cb75 | `e8 86 fb 75 00` (`call rel32`) | 0x4140cb75 + 5 + 0x75fb86 = **0x41b6c700** |

CONFIRMED: The call from `0x4140cb75` to `0x41B6C700` is internally consistent
within live memory. Both addresses are within Block 1 of the allocation.

Additionally, `0x413f94d0` shows a clean function boundary:
- `0x413f94c6–0x413f94cb`: `add esp,0x14; pop ebp; ret` (end of previous function)
- `0x413f94cc–0x413f94cf`: `cc cc cc cc` (int3 padding)
- `0x413f94d0`: `57 56 83 ec 0c...` (`push edi; push esi; sub esp,0xc` — function start)

CONFIRMED: These are real function boundaries in live code.

========================================
6. TRANSFORMATION ANALYSIS
===========================

The relationship between resource #101 and live code can be explained by
several hypotheses:

**Hypothesis 1: Straight copy, no transformation (SOURCE-CONFIRMED for map(),
but contradicted by live bytes)**
- `map()` copies resource bytes directly to `0x412a0000`
- Predicted: `0x412a0000` = `a6 c0 4e c9...`
- Observed: `0x412a0000` = `00 00 00 00...`
- Status: **CONTRADICTED** by live memory

**Hypothesis 2: First 4 bytes skipped, rest copied directly**
- `map()` writes resource bytes [4..end] to `0x412a0000`
- Predicted: `0x412a0000` = `43 77 21 63...`
- Observed: `0x412a0000` = `00 00 00 00...`
- Status: **CONTRADICTED** by live memory

**Hypothesis 3: Resource is encrypted/encoded, decrypted at runtime**
- `map()` copies encrypted resource to `0x412a0000`
- A later step (not in reviewed source) decrypts it in place
- Predicted: Live code ≠ resource bytes (consistent with observation)
- Status: **PLAUSIBLE but UNVERIFIED** — no decryption routine found in reviewed source

**Hypothesis 4: Source code revision mismatch**
- The source code we have is from a different version than the running binary
- The running binary's `map()` or `fix_dump()` includes a transformation step
  not present in the source we reviewed
- Status: **PLAUSIBLE but UNVERIFIED**

**Hypothesis 5: Resource #101 is not executable code**
- Resource #101 is encrypted/compressed data that gets decompressed/decrypted
  into a different memory region (not `0x412a0000`)
- The live code at `0x412a0000` comes from a different source
- Status: **UNLIKELY** — `map()` explicitly writes resource #101 to `0x412a0000`,
  and the live code at `0x412a0000+` is x86 code

========================================
7. WHAT THE SOURCE PROVES vs. RUNTIME EVIDENCE
===============================================

| Claim | Source-proven? | Runtime-observed? | Classification |
|---|---|---|---|
| `map()` reads resource #101 | YES (`neverlose.cpp:19`) | N/A (static) | SOURCE-CONFIRMED |
| `map()` allocates at `0x412a0000` | YES (`neverlose.h:28`) | YES (VirtualQueryEx) | CONFIRMED |
| `map()` writes resource via `NtWriteVirtualMemory` | YES (`neverlose.cpp:45`) | N/A (static) | SOURCE-CONFIRMED |
| Resource #101 is 55,578,628 bytes | YES (PE resource dir) | N/A (static) | CONFIRMED |
| Allocation is 55,578,624 bytes | N/A | YES (VirtualQueryEx) | RUNTIME-OBSERVED |
| Live code at reported addresses is valid x86 | N/A | YES (ReadProcessMemory) | RUNTIME-OBSERVED |
| Live bytes match on-disk DLL | N/A | NO (0/10 matches) | CONTRADICTED |
| Resource bytes match live bytes at `0x412a0000` | N/A | NO (zeros vs `a6 c0 4e c9`) | CONTRADICTED |
| `fix_dump()` decrypts mapped image | NO (no such code in source) | N/A | NOT SUPPORTED BY SOURCE |
| `install_crypto_capture()` transforms mapped image | NO (it hooks `0x41d9f3f0`) | N/A | NOT SUPPORTED BY SOURCE |

========================================
8. BOUNDARY OF KNOWLEDGE
=========================

The available source code and runtime evidence establish:

1. **SOURCE-CONFIRMED**: `neverlose::map()` reads resource #101 and writes it
   via `NtWriteVirtualMemory` to a MEM_PRIVATE EXECUTE_READWRITE region at
   `0x412a0000`.

2. **RUNTIME-OBSERVED**: The live code at `0x412a0000+` is valid, internally
   consistent x86 code, but does NOT match any byte sequence in the on-disk
   `neverlose.dll`.

3. **UNKNOWN (boundary)**: How the resource bytes are transformed into the
   live executable code. The source shows a straight copy, but the bytes
   don't match. The transformation (if any) happens either:
   - In source code we haven't fully read (e.g., `entry()`,
     `setup_hooks()`, or parts of `fix_dump()` we haven't examined)
     OR
   - In a different binary/revision than the source we have

The transformation boundary is at the point between `NtWriteVirtualMemory`
(completing the copy) and the first execution of code from the mapped region.
What happens in that interval is not established by the available evidence.

========================================
END
========================================