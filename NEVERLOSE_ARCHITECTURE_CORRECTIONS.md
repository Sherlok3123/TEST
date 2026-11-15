# NEVERLOSE ARCHITECTURE CORRECTIONS
====================================
Corrections and confidence-level changes to earlier reports
(NEVERLOSE_COMPLETE_ARCHITECTURE.md, NEVERLOSE_COMPONENT_ANALYSIS.md,
NEVERLOSE_RUNTIME_ARTIFACTS.md, NEVERLOSE_SOURCE_RECOVERY.md,
NEVERLOSE_FINAL_UNKNOWNS.md, NATIVE_REVERSE_ENGINEERING_DUMP.txt).
Corrections are made here rather than silently carried forward.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. MAPPED-IMAGE SIZE ARITHMETIC (PREVIOUSLY CORRECTED, RE-AFFIRMED)
====================================================================

Previous (incorrect) statement: base 0x412A0000 + size 0x00DBA000 =
0x4134BA000 (digit-transpose error).

Correction (CONFIRMED): 0x412A0000 + 0x00DBA000 = 0x4205A000.

The manually mapped image is TWO blocks:
  Block 1 (WCX, executable): 0x412A0000 – 0x4205A000 (0x00DBA000 bytes)
  Block 2 (RO continuation): 0x4205A000 – 0x42239000 (0x001DF000 bytes)

All function addresses cited (0x412Axxxx–0x4159xxxx) fall within Block 1.
Global data addresses (0x42xxxxxx) fall in Block 2 / adjacent pages.

This does NOT change any function-address or global-value finding.
Status: CONFIRMED (re-verified via PE SizeOfImage 0x035CA000 and live
memory observation).

========================================
2. nl.bin IS NOT A RUNTIME-GENERATED ARTIFACT (CONFIRMED CORRECTION)
=====================================================================

Previous assumption: nl.bin is "created after injection" / a generated
runtime artifact.

Correction (CONFIRMED): nl.bin lives ONLY in the source tree at
FemboyLose-main/neverlose/bins/nl.bin (55,578,624 bytes, mtime 7/14/2026).
It is:
  - NOT referenced by name in any binary (grep for "nl.bin"/"bins" in
    neverlose.dll, neverlose-server.exe, loader.exe returned zero hits).
  - NOT created at runtime by any component.
  - NOT read or modified at runtime (no observed file handle).
  - A Lua 5.1 standard-library bytecode bundle (source-tree build asset).

Status: CONFIRMED — nl.bin is a static source-tree asset, NOT a generated
runtime artifact. NEVERLOSE_RUNTIME_ARTIFACTS.md already reflects this.

Relationship to resource #101 (53.0 MB blob in .rsrc): #101 is 55,578,628
bytes (within 4 bytes of nl.bin) but its first bytes (a6 c0 4e c9…) do NOT
match Lua bytecode magic (\x1bLua), and a simple 4-byte repeating XOR of
nl.bin against #101's first 8 bytes did not yield a consistent key. Whether
#101 is an encoded/transformed nl.bin or an unrelated payload is UNKNOWN.

========================================
3. AIM CONSUMER IS NATIVE, NOT LUA (CONFIRMED / CLARIFIED)
==========================================================

Previous Phase 5 conclusion: "no aim consumer found in inspected Lua."

Correction/clarification (CONFIRMED): The aim consumer exists in NATIVE
code inside neverlose.dll:
  - 0x4140C710 — aim consumer entry (SEH-wrapped; iterates entity list
    [0x424AFD68]; single caller 0x41596AA9)
  - 0x4140CB75 — aim position computation (writes globals
    0x425023C8/23D0/23EC)
  - 0x41573930 — vector->angle (calls atan2 at 0x4202F7D0)
  - 0x41573E80 — angle normalize (calls 0x42026D1B x3)
  - 0x41408800 — memcpy-style aim-struct apply (copies 0x71c bytes)

Lua-side prediction (extrapolate_pos, rebelion v751) is render/telemetry-only
and NOT an aim consumer. Lua has NO verified binding to the native aim
consumer.

Status: CONFIRMED via live disassembly of the mapped image.

========================================
4. AIM OUTPUT GLOBALS AND ENGINE-STATE RELATIONSHIP (DOWNGRADED TO INFERRED)
============================================================================

Previous claim implied the aim output globals (0x425023C8/23D0/23EC) feed
directly into engine aim state.

Correction (INFERRED → not confirmed): 0x4140CB75 writes these globals, and
0x41408800 copies a 0x71c-byte aim struct, but the relationship between these
globals and the final engine aim state was NOT established. No consumer of
0x425023C8/23D0/23EC was identified in the .text call graph.

Status: INFERRED (globals exist and are written; their downstream consumer is
UNKNOWN).

========================================
5. 0x71c-BYTE STRUCTURE COPY — SEMANTIC ROLE UNKNOWN (DOWNGRADED)
=================================================================

Previous claim treated the 0x41408800 memcpy (0x71c bytes) as an understood
"aim result apply."

Correction (INFERRED → UNKNOWN for semantics): The memcpy at 0x41408800 is
CONFIRMED (copies 0x71c bytes, ret 4), but the semantic role of the 0x71c
structure (aim result, entity state, config blob, etc.) is NOT established.

Status: The copy operation is CONFIRMED; the structure's meaning is UNKNOWN.

========================================
6. FILE OWNERSHIP UNDER cabbitwin\ (CLARIFIED)
=============================================

Previous reports attributed all cabbitwin\ files to neverlose-server.exe.

Correction (STRONGLY SUPPORTED → refined): The files under
cabbitwin\server\ (state.json, accounts.json, users/<hash>/*, scripts/
libraries/*.lua, certs/*) are created and owned by neverlose-server.exe.
session.txt and token.txt at cabbitwin\ root are also server-owned. This is
supported by the server's file I/O imports (NtCreateFile/NtReadFile/
NtWriteFile) and the presence of TLS certs + per-user state. No evidence
shows neverlose.dll writing back to cabbitwin\ (client→server direction
observed only as WinHTTP GET requests).

Status: STRONGLY SUPPORTED (server ownership); client write-back UNKNOWN.

========================================
7. SERVER STARTUP ORDER (DOWNGRADED FROM CONFIRMED to UNKNOWN)
==============================================================

Previous reports stated the order "server starts first → loader injects
→ DLL connects" as CONFIRMED.

Correction (UNKNOWN): neverlose-server.exe (PID 11468) was observed running
independently of csgo.exe (PID 21580), but there is NO evidence that
loader.exe starts it. loader.exe imports ShellExecuteW and CreateProcessW
so it COULD start the server, but no link was established. The server's
mtime (9/8/2026) predates the observed session.

Status: UNKNOWN whether loader.exe starts neverlose-server.exe or whether
the server is started independently.

========================================
8. RESOURCE #101 IS NOT nl.bin (NEW CONFIRMED FINDING)
======================================================

Previous possibility: .rsrc resource #101 might be nl.bin.

Correction (CONFIRMED negative): Resource #101 (55,578,628 bytes) does NOT
match nl.bin:
  - First bytes a6 c0 4e c9… vs Lua bytecode magic 1b 4c 75 61.
  - Repeating ASCII pattern "Cw!c4bb1t#nL.3nc-2026" not present in Lua bytecode.
  - Simple 4-byte repeating XOR of nl.bin vs #101's first 8 bytes: no
    consistent key.

#101 is a distinct transformed/compressed/encrypted blob. Format UNKNOWN.

========================================
9. RESOURCE TYPE NAME (CLARIFIED)
=================================

Previous reports did not document resource type names.

Correction (CONFIRMED): All five large resources (#101–#105) use the custom
(named) resource type "BINARY" with name #1049 and language L25/S1. The
standard type RT_MANIFEST (#2, name #1033, EN/S1) is separate.

========================================
10. SOURCE COVERAGE — NATIVE SUBSYSTEMS WITHOUT SOURCE (NEW)
============================================================

Previous reports implied the full DLL was source-recoverable.

Correction (CONFIRMED): Substantial native logic exists only in the compiled
binary with no identified source file: record freshness gate, lag-comp
acceptability gate, record selection, lag-comp orchestrator, origin apply,
aim pipeline, geometry helpers. Source is present only for bootstrap,
mapping, imports, hooks, VEH, and HTTP/Lua request path.

========================================
END
========================================