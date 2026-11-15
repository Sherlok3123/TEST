# NEVERLOSE PE SECTION INVENTORY
================================
Complete section-by-section inventory of neverlose.dll, including virtual/raw
sizes, permissions, entropy, and coverage notes.

Evidence levels: CONFIRMED (from PE header + raw byte analysis).

Source file analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll

========================================
1. EXACT BINARY IDENTIFICATION
========================================

| Field | Value |
|---|---|
| Path | C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll |
| Size (bytes) | 56,370,688 (53.76 MB) |
| MD5 | 6419c781156a70631cc92ddf84ac9c08 |
| SHA1 | b84438884434275101bc2ad4349d5102f3aaedca |
| SHA256 | 529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253 |
| Architecture | x86 PE32 (MACHINE 0x14c) |
| ImageBase (PE header) | 0x10000000 |
| EntryPoint (RVA) | 0x15560 |
| SizeOfImage | 0x035CA000 |
| SizeOfHeaders | 0x400 |
| SectionAlignment | 0x1000 |
| FileAlignment | 0x200 |
| NumberOfSections | 8 |
| TimeDateStamp | 1788894915 |
| Subsystem | 0x3 (WINDOWS_CUI) |
| Characteristics | 0x2102 (EXECUTABLE_IMAGE \| 32BIT_MACHINE \| DLL) |
| DOS Magic | 4d 5a ("MZ") |
| e_lfanew | 0x108 |
| PE Signature | 50 45 00 00 ("PE\0\0") at file offset 0x108 |

Runtime mapping note (from live-process observation, PID 21580):
  The DLL is NOT loaded at its PE ImageBase (0x10000000). It is manually
  mapped at allocation base 0x412A0000 with a separate read-only continuation
  block at 0x4205A000. The PE header ImageBase is therefore not the runtime
  base. File RVAs below are on-disk RVAs; add the appropriate mapping delta
  to derive runtime addresses (the manual mapper may not preserve a constant
  delta).

========================================
2. SECTION INVENTORY
========================================

| # | Name | VirtAddr | VirtSize | RawOffset | RawSize | Entropy | Perms | Contents |
|---|------|----------|----------|-----------|---------|---------|-------|----------|
| 1 | .text | 0x00001000 | 0x0003807A | 0x00000400 | 0x00038200 | 6.66 | CODE | Executable code (229 KB) |
| 2 | .rdata | 0x0003A000 | 0x0002B20E | 0x00038600 | 0x0002B400 | 6.37 | RD | Read-only data: constants, strings, import names, vtables |
| 3 | .data | 0x00066000 | 0x000029E8 | 0x00063A00 | 0x00001600 | 3.44 | RW | Writable initialized data (low entropy = structured) |
| 4 | .detourc | 0x00069000 | 0x00001190 | 0x00065000 | 0x00001200 | 4.01 | RD | Detour hook code stubs |
| 5 | .detourd | 0x0006B000 | 0x0000000C | 0x00066200 | 0x00000200 | 0.07 | RW | Detour hook data (near-zero entropy = padding/zeros) |
| 6 | .fptable | 0x0006C000 | 0x00000080 | 0x00066400 | 0x00000200 | 0.00 | RD | Function-pointer table (all zeros / NULL-initialized) |
| 7 | .rsrc | 0x0006D000 | 0x03557150 | 0x00066600 | 0x03557200 | 7.27 | RD | Resources (~53 MB) — see resource analysis |
| 8 | .reloc | 0x0035C500 | 0x00004C24 | 0x035BD800 | 0x00004E00 | 6.45 | R | Base-relocation table |

Permissions legend: CODE = executable; RD = read-only data; RW = read/write;
R = read-only.

Entropy scale: 0.0 (uniform/empty) to 8.0 (maximally random).
  - ~6.4–6.7: typical compiled code / mixed data
  - ~3.4: structured writable data (low entropy)
  - ~0.0–0.1: zero-filled / padding
  - 7.27: high-entropy blob (compressed, encrypted, or high-randomness data)

========================================
3. SECTION COVERAGE ASSESSMENT
========================================

| Section | Fraction of file | Status | Examined? |
|---|---|---|---|
| .text | 0x38200 / 0x35CA000 ≈ 3.1% | CODE | Partially — function prologues + call graph mapped (see native function inventory) |
| .rdata | 0x2B400 / 0x35CA000 ≈ 2.5% | DATA | Partially — strings/imports reviewed; full constant table not enumerated |
| .data | 0x1600 / 0x35CA000 ≈ 0.1% | DATA | Not enumerated (globals not individually catalogued) |
| .detourc | 0x1200 / 0x35CA000 ≈ 0.1% | CODE | Not disassembled |
| .detourd | 0x200 / 0x35CA000 ≈ 0.0% | DATA | Not analyzed |
| .fptable | 0x200 / 0x35CA000 ≈ 0.0% | DATA | Not analyzed (NULL-initialized pointer table) |
| .rsrc | 0x3557200 / 0x35CA000 ≈ 94.1% | RESOURCES | Enumerated (6 entries); 53 MB blob content not decoded |
| .reloc | 0x4E00 / 0x35CA000 ≈ 0.4% | DATA | Not parsed |

Coverage summary:
  - Executable code (.text): ~229 KB, of which a function-boundary + call-graph
    skeleton was recovered (1,027 prologue candidates, 4,463 direct call sites).
    Full decompilation was NOT performed.
  - Resources (.rsrc): ~53 MB dominates the file. Enumerated at the resource-directory
    level (6 entries) but the 53 MB blob was NOT decoded.
  - Read-only/writable data (.rdata/.data/.reloc): headers read; contents not
    individually catalogued.
  - Detour stubs (.detourc/.detourd/.fptable): present; not disassembled.

Overall: the DLL is NOT comprehensively analyzed. Approximately 97% of the file
(by byte count) is either unexamined resources or unexamined data sections; only
the .text code skeleton and resource directory were mapped.

========================================
4. NOTABLE ADDRESSES (FILE RVAs)
========================================

| RVA | Role | Evidence |
|---|---|---|
| 0x000015560 | PE EntryPoint (DllMain) | PE OptionalHeader.AddressOfEntryPoint |
| 0x00001040–0x00038FF0 | Function prologue candidates | .text prologue scan (1,027 total) |

The 53 MB .rsrc blob sits at file offset 0x66600 (RVA 0x6D000) and extends
to approximately RVA 0x35C4150 (end of .rsrc). The single largest resource
(entry #101) is at RVA 0x6D170, size 55,578,628 bytes.

========================================
END
========================================