# NEVERLOSE RUNTIME IMAGE RECONCILIATION
========================================
Phase 7 — Resolution of whether the native functions previously observed
around `0x413F0000–0x41590000` belong to the analyzed `neverlose.dll`, and
how (or whether) their runtime addresses correspond to its on-disk PE layout.

Read-only investigation. No binaries, source files, or runtime behavior were
modified. Resource #101 decoding was deliberately NOT performed.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. OBJECTIVE AND METHOD
========================================

The prior phases reported native function addresses inside a live
`csgo.exe` process (PID 21580) in the range `0x413F0000–0x41B60000`, and
asserted those addresses belonged to a manually-mapped `neverlose.dll` at
allocation base `0x412A0000`. This phase re-examines that claim by:

  (a) Re-verifying the on-disk `neverlose.dll` PE headers and sections
      (SHA256 529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253).
  (b) Reading live memory at each reported function address from the running
      `csgo.exe` process.
  (c) Searching the entire on-disk `neverlose.dll` image for the live 16-byte
      sequences observed at each address, to test whether a simple base delta
      maps runtime -> on-disk.
  (d) Inspecting the allocation base `0x412A0000` for a PE header (MZ/PE
      signature, e_lfanew).
  (e) Reconstructing the reported allocation ranges and comparing their total
      size to PE SizeOfImage.

========================================
2. ON-DISK neverlose.dll — RE-VERIFIED (CONFIRMED)
==================================================

File: `C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll`
SHA256: `529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253`

| Field | Value |
|---|---|
| Architecture | x86 PE32 (MACHINE 0x14c) |
| Preferred ImageBase | 0x10000000 |
| EntryPoint RVA | 0x15560 |
| SizeOfImage | 0x035CA000 (56,401,920 bytes) |
| NumberOfSections | 8 |

| Section | RVA | VirtSize | RawOffset | RawSize |
|---------|-----|----------|-----------|---------|
| .text | 0x00001000 | 0x0003807A | 0x00000400 | 0x00038200 |
| .rdata | 0x0003A000 | 0x0002B20E | 0x00038600 | 0x0002B400 |
| .data | 0x00066000 | 0x000029E8 | 0x00063A00 | 0x00001600 |
| .detourc | 0x00069000 | 0x00001190 | 0x00065000 | 0x00001200 |
| .detourd | 0x0006B000 | 0x0000000C | 0x00066200 | 0x00000200 |
| .fptable | 0x0006C000 | 0x00000080 | 0x00066400 | 0x00000200 |
| .rsrc | 0x0006D000 | 0x03557150 | 0x00066600 | 0x03557200 |
| .reloc | 0x0035C500 | 0x00004C24 | 0x035BD800 | 0x00004E00 |

On-disk entry bytes at RVA 0x15560: `55 8b ec 83 7d 0c 01 75` (`push ebp; mov ebp,esp; ...`).

========================================
3. LIVE MEMORY READS — ALL 10 REPORTED ADDRESSES (CONFIRMED)
============================================================

The running `csgo.exe` (PID 21580) was opened with `PROCESS_VM_READ |
PROCESS_QUERY_INFORMATION` and 16 bytes were read at each reported address.
Every address returned valid x86 code (no read failures), and several are
internally consistent with each other:

| Runtime address | Reported role | Live bytes (16) | Interpretation |
|-----------------|---------------|-----------------|----------------|
| 0x413F94D0 | lag-comp acceptability gate | `57 56 83 ec 0c 8b 15 28 f4 23 42 8b b1 84 00 00` | `push edi; push esi; sub esp,0xc; mov edx,[0x4223f428]` — reads ctx global `[0x4223f428]` |
| 0x413F9E00 | record freshness gate | `55 89 e5 53 57 56 83 e4 f0 81 ec 10 01 00 00` | SEH-wrapped prologue (`push ebp/mov ebp,esp; push ebx/edi/esi; and esp; sub esp,0x110`) |
| 0x4148F180 | record selection | `55 57 56 83 ec 10 8b 4c 24 24 a1 00 27 26 42` | SEH prologue; `mov eax,[0x42262700]` (stack cookie) |
| 0x41496DB0 | lag-comp orchestrator | `55 89 e5 53 57 56 83 e4 f0 81 ec 60 01 00 00` | SEH prologue; sub esp,0x160 |
| 0x4140C710 | aim consumer entry | `55 89 e5 53 57 56 83 ec 34 89 65 e4 ...` | SEH prologue; sub esp,0x34 |
| 0x4140CB75 | aim position computation | `e8 86 fb 75 00 f2 0f 10 45 d0 f2 0f 11 05 c8 23` | `call 0x75FB86` (relative) → target = 0x41B6C700 |
| 0x41573930 | vector->angle | `56 83 ec 48 8b 74 24 50 8b 44 24 54 8b 4c 24 58` | `push esi; sub esp,0x48; ...` |
| 0x41573E80 | angle normalize | `56 83 ec 38 8b 44 24 40 8b 4c 24 44 8b 15 00 27` | `push esi; sub esp,0x38; ...` |
| 0x41408800 | aim-struct apply | `89 c8 8b 4c 24 04 f2 0f 10 01 f2 0f 11 00 f3 0f` | `mov eax,ecx; ... movsd xmm0,[ecx]` |
| 0x41B6C700 | origin apply | `55 89 e5 53 57 56 83 ec b0 00 00 00 89` | SEH prologue; sub esp,0xb0 |

Notable internal consistency (CONFIRMED): at `0x4140CB75`, the relative call
`e8 86 fb 75 00` resolves to `0x4140CB75 + 5 + 0x75FB86 = 0x41B6C700` —
exactly another reported address (origin apply). So the live addresses form a
coherent, internally-consistent call graph in the running process.

However, this internal consistency does NOT establish that the code is
`neverlose.dll`. It only establishes that SOMETHING at those addresses is
real, running code.

========================================
4. MAPPING TEST — LIVE BYTES vs ON-DISK BYTES (CONFIRMED NEGATIVE)
===================================================================

The entire on-disk `neverlose.dll` image (all sections) was searched for each
live 16-byte sequence. Result: **NO MATCH at any address**.

| Runtime address | Live 16 bytes matched in on-disk neverlose.dll? |
|-----------------|-------------------------------------------------|
| 0x413F94D0 | No |
| 0x413F9E00 | No |
| 0x4148F180 | No |
| 0x41496DB0 | No |
| 0x4140C710 | No |
| 0x4140CB75 | No |
| 0x41573930 | No |
| 0x41573E80 | No |
| 0x41408800 | No |
| 0x41B6C700 | No |

This is decisive: **none of the live code at the reported addresses exists
anywhere in the on-disk `neverlose.dll` image.** A simple base delta
(runtime_addr − file_rva) cannot map these addresses to the on-disk DLL.

Additional checks:
  - Corrected entry point = `0x412A0000 + 0x15560 = 0x412B5560` (the earlier
    reported `0x412A15560` is incorrect arithmetic). Live bytes at
    `0x412B5560`: `00 00 8d 46 24 50 89 cf` — NOT the on-disk entry bytes
    `55 8b ec 83 7d 0c 01 75`. No match.
  - The previously-reported (wrong) entry `0x412A15560`: no read (unreadable
    or not present).

========================================
5. ALLOCATION BASE INSPECTION (CONFIRMED)
=========================================

The allocation base `0x412A0000` was read:

  - First 64 bytes: all `00` (zero-filled).
  - `e_lfanew` at `0x412A003C`: `00 00 00 00` (= 0).
  - No `MZ`/`PE` signature at the base or at `base + e_lfanew`.

Conclusion (CONFIRMED): **`0x412A0000` is NOT the base of a mapped PE
module.** It contains no DOS header, no PE signature, no section table. It is
either a zero-filled reservation, a guard page region, or the start of a
region whose actual code begins elsewhere. The reported "mapping base" does
not correspond to a PE image header.

========================================
6. RANGE / SIZE COMPARISON (CONFIRMED)
=======================================

Reported allocation blocks:
  Block 1: `0x412A0000–0x4205A000` (size `0x00DBA000`)
  Block 2: `0x4205A000–0x42239000` (size `0x001DF000`)
  Combined total: `0x00F99000` (~15.7 MB)

On-disk `neverlose.dll` SizeOfImage: `0x035CA000` (~53.8 MB).

The combined reported blocks (`0x00F99000`) are **substantially smaller**
than PE SizeOfImage (`0x035CA000`) — by a factor of ~3.4. A manually mapped
PE image should reserve at least SizeOfImage bytes of address space. The
reported ranges cannot accommodate the full on-disk image (in particular,
the `.rsrc` section alone is 0x03557150 bytes ≈ 53 MB, which already exceeds
the entire combined reported range).

========================================
7. OFFSET / SECTION COMPARISON
================================

Using the reported base `0x412A0000`, the reported function addresses resolve
to these "RVAs":

| Runtime address | Minus base 0x412A0000 | Result | Falls in which on-disk section? |
|-----------------|----------------------|--------|---------------------------------|
| 0x413F94D0 | − 0x412A0000 | 0x001594D0 | **.rsrc** (0x0006D000–0x0035C4150) |
| 0x413F9E00 | − 0x412A0000 | 0x00159E00 | **.rsrc** |
| 0x4148F180 | − 0x412A0000 | 0x001EF180 | **.rsrc** |
| 0x41496DB0 | − 0x412A0000 | 0x001F6DB0 | **.rsrc** |
| 0x4140C710 | − 0x412A0000 | 0x0016C710 | **.rsrc** |
| 0x4140CB75 | − 0x412A0000 | 0x0016CB75 | **.rsrc** |
| 0x41573930 | − 0x412A0000 | 0x002D3930 | **.rsrc** |
| 0x41573E80 | − 0x412A0000 | 0x002D3E80 | **.rsrc** |
| 0x41408800 | − 0x412A0000 | 0x00168800 | **.rsrc** |
| 0x41B6C700 | − 0x412A0000 | 0x002CC700 | **.rsrc** |

Every reported address, subtracted from the reported base, lands inside the
on-disk `.rsrc` section (RVA 0x0006D000–0x0035C4150) — NOT `.text`
(0x00001000–0x0003907A). Yet the live bytes at those addresses are clearly
executable x86 code, while `.rsrc` on disk is a high-entropy (7.27) data blob
starting with `a6 c0 4e c9…` (not executable code).

This is a direct contradiction: the reported addresses cannot simultaneously
(1) be at base + an `.rsrc` RVA and (2) contain executable code matching
`.rsrc` contents — because `.rsrc` on disk is NOT executable code.

Therefore the simple base-delta mapping is INVALID.

========================================
8. POSSIBLE EXPLANATIONS (ranked by evidence)
============================================

(a) The running `csgo.exe` has a DIFFERENT build of `neverlose.dll` injected
    than the one present on disk in the workspace. The workspace DLL
    (SHA256 529c59bd…) may be an older or different build. The live code is
    real and internally consistent, but corresponds to a different binary
    whose bytes we do not have. → Consistent with all evidence.

(b) The manual mapper applies a runtime transformation (decryption /
    decompression / rebasing) to the on-disk image, so in-memory bytes differ
    from on-disk bytes. The `fix_sha256`, `install_crypto_capture`, and the
    high-entropy `.rsrc` blob hint at crypto/obfuscation. However, the
    fix_dump steps described in source (fix_imports, NOP pads, 0xEB flow
    patches) are targeted byte patches, not a wholesale byte transformation;
    the majority of code bytes should be identical on disk and in memory.
    The fact that ZERO of ten 16-byte sequences match makes wholesale
    transformation plausible but UNVERIFIED. → Plausible, not confirmed.

(c) The reported addresses belong to a DIFFERENT module entirely (not
    `neverlose.dll`) that happens to be mapped in `csgo.exe`. No module
    enumeration was performed to confirm this. → Possible, unconfirmed.

(d) The previous analysis misattributed addresses or used an incorrect base.
    → Supported by the confirmed zero-filled base and incorrect entry-point
    arithmetic.

No single explanation is proven. Explanations (a), (b), and (c) remain open;
(d) is confirmed for the specific entry-point arithmetic error but does not
by itself explain the byte mismatch.

========================================
9. STATUS
=====================================

**UNRESOLVED.**

Existing evidence cannot establish that the previously reported native
function addresses belong to the on-disk `neverlose.dll` (SHA256
529c59bd…). The live code is real and internally consistent, but:
  - The allocation base `0x412A0000` has no PE header.
  - No live byte sequence matches the on-disk image.
  - The reported ranges are smaller than SizeOfImage.
  - Offsets from the base land in `.rsrc`, which is not executable code.

Consequently, **every function-to-DLL attribution made in earlier phases for
addresses `0x413F94D0`, `0x413F9E00`, `0x4148F180`, `0x41496DB0`,
`0x4140C710`, `0x4140CB75`, `0x41573930`, `0x41573E80`, `0x41408800`,
`0x41B6C700` is downgraded to UNVERIFIED.** These addresses contain real
running code, but their relationship to `neverlose.dll` is not established.

To resolve this, one would need: (1) the DLL build that is actually running
(or a memory dump of its mapped image), (2) module enumeration in `csgo.exe`
to identify which module owns those addresses, or (3) a trace of the manual
mapper to see how bytes are transformed from on-disk to memory.

========================================
END
========================================