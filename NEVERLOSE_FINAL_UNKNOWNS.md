# NEVERLOSE FINAL UNKNOWNS
============================
Only genuinely unresolved questions from the Neverlose architecture
investigation. For each: why it remains unresolved, and what specific
evidence would resolve it.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

========================================
1. COMPONENT-LEVEL UNKNOWNs
========================================

1.1 loader.exe remote download URL
----------------------------------
Status: UNKNOWN.
Why unresolved: loader.exe source is absent; the only network-related
evidence is its WININET imports (InternetOpenA, InternetOpenUrlA,
HttpOpenRequestA, HttpSendRequestA, InternetReadFile) and the "1:30031"
port string. No URL string was located in the binary.
What would resolve it: a strings dump or disassembly of loader.exe
revealing the download host/path; or observation of loader.exe's network
traffic (e.g., via a packet capture) showing the remote host it contacts.

1.2 Whether loader.exe starts neverlose-server.exe
--------------------------------------------------
Status: UNKNOWN.
Why unresolved: neverlose-server.exe runs as a standalone process (PID
11468, independently of csgo PID 21580). loader.exe imports ShellExecuteW
and CreateProcessW, so it *could* start the server, but no evidence links
them. The server's mtime (9/8/2026) predates the observed session.
What would resolve it: process ancestry (parent PID of neverlose-server
.exe) at startup; or a strings/disassembly reference in loader.exe to
"neverlose-server.exe".

1.3 neverlose-server.exe exact HTTP routes beyond /lua/<name>
------------------------------------------------------------
Status: UNKNOWN.
Why resolved only partially: Requestor.cpp confirms GET /lua/<name> for
QueryLuaLibrary. The server binary has HTTP/WebSocket strings
(HTTPRe, EHTTPMe, SECURITYCOOKIE, TRANSPORT, DESERIALIZE, EXPORT) but
no route table was extracted. x64 disassembly was not performed.
What would resolve it: x64 disassembly of neverlose-server.exe around
its request handler; or observation of actual HTTP requests/responses
between neverlose.dll and the server.

1.4 neverlose-server.exe auth handshake details
-----------------------------------------------
Status: UNKNOWN.
Why unresolved: accounts.json stores username, dir (token hash), tokens,
password hash, hwid, uid — confirming an auth model exists — but the
protocol (how client proves token/HWID to server) is not documented in
any available source or observable without a traffic capture.
What would resolve it: capture of the WinHTTP exchange at client init;
or server source.

1.5 Whether neverlose.dll writes any file back to cabbitwin\
----------------------------------------------------------
Status: UNKNOWN.
Why unresolved: observed client->server direction is HTTP requests only
(WinHTTP GET /lua/<name>). No file-handle activity from neverlose.dll
into cabbitwin\ was observed. But the server writes per-user state
(state.json 2.4 MB) — source of writes not attributed.
What would resolve it: file-system monitoring of cabbitwin\ during a
runtime session; or neverlose.dll source showing file writes.

========================================
2. RUNTIME / BEHAVIOR UNKNOWNs
========================================

2.1 Full list of Lua scripts loaded at runtime init
---------------------------------------------------
Status: UNKNOWN.
Why unresolved: workspace scripts call require("neverlose/...") and the
server serves scripts/libraries/*.lua, but no runtime require() trace was
captured. REFRACTED.lua, rebelion.txt, Aesthetic BETA.txt etc. are
present as files but it is UNKNOWN which are auto-loaded at init vs.
loaded manually by the user.
What would resolve it: a Lua require() trace from inside the running
csgo.exe process (PID 21580); or neverlose.dll source showing its
startup require() list.

2.2 Whether nl.bin (or a runtime copy) is loaded by the Lua VM
-------------------------------------------------------------
Status: UNKNOWN (leaning NO).
Why unresolved: nl.bin exists only in FemboyLose-main/neverlose/bins/
(source tree), is NOT referenced by name in any binary, and is NOT created
at runtime. It may be bundled into neverlose.dll's .rsrc (~53 MB) instead
of being a separate file — but that was not verified.
What would resolve it: search neverlose.dll's .rsrc for the Lua bytecode
signature; or a Lua VM module load trace.

2.3 Behavior of obfuscated helpers past trampoline 0x39C21170
-------------------------------------------------------------
Status: UNKNOWN.
Why unresolved: 0x41400BF0 and 0x413F6B40 (geometry/visibility helpers)
jump to trampoline 0x39C21170 containing junk bytes + opaque predicates +
indirect jumps. Static tracing cannot continue past them. They are reached
from the record-selection loop (0x4148F3EC, 0x4148F5B4).
What would resolve it: dynamic instrumentation (x64dbg/x64dbg-style
tracer) of the running csgo.exe (PID 21580) stepping through the helpers;
or de-obfuscation of the trampoline region.

2.4 Relationship between record+0x00 and record+0x18
----------------------------------------------------
Status: UNKNOWN.
Why unresolved: both are used as positions (0x00 in record-selection
distance at 0x4148F180; 0x18 in lag-comp acceptability distance at
0x413F94D0). They are not shown being copied into each other in the
regions examined. Whether +0x18 is a duplicate, simulation origin, or
corrected origin is not established.
What would resolve it: a runtime struct dump of a live record; or
disassembly showing both fields written from the same source.

2.5 Write sites for global 0x424F4B18 (tick correction)
-------------------------------------------------------
Status: UNKNOWN.
Why unresolved: 86 read-only xrefs were found in the mapped image; no
write sites were located. It is read at 0x413F9ECA and written to
record+0xAC by 0x413F9E00, but who writes 0x424F4B18 itself is unknown.
What would resolveit: a write watchbreakpoint on 0x424F4B18 during a
runtime session; or a fuller xref scan including indirect writes.

2.6 Ordering of the two paths inside 0x41496DB0 (lag-comp orchestrator)
------------------------------------------------------------------------
Status: UNKNOWN.
Why unresolved: two paths exist (guarded by [0x424B03C0], [0x424B03D4],
[0x424B03B4]); the relative execution order was not determined from the
disassembly regions examined.
What would resolve it: a control-flow trace of 0x41496DB0 during runtime.

2.7 How 0x41596AA9 (aim-consumer caller) is entered
---------------------------------------------------
Status: UNKNOWN.
Why unresolved: 0x41596AA9 calls into the aim pipeline
(0x41367250, 0x41412FE0, 0x41427FA0, 0x41428C40, 0x41395030) then reaches
0x4140C710, but it has NO direct E8 callers — it is reached via jump,
indirect call, or is a hook entry point.
What would resolve it: a caller scan including indirect calls (call [reg]);
or a traceback from 0x4140C710 during runtime.

========================================
3. ARCHITECTURE-LEVEL UNKNOWNs
========================================

3.1 Is there a single final aim position?
-----------------------------------------
Status: UNKNOWN (leaning NO — no verified aim consumer in Lua; the native
aim consumer exists at 0x4140C710 but its Lua controllability is unknown).
Why unresolved: Lua-side prediction (extrapolate_pos, rebelion v751) is
render/telemetry-only; no Lua script reads engine aim output or feeds a
computed aim position back. The native aim consumer (0x4140C710) exists
but no Lua binding to it was found.
What would resolve it: a Lua binding that reads 0x425023C8/23D0/23EC
(aim output globals); or a script that sets aim angles.

3.2 Can Lua influence native aim at all?
----------------------------------------
Status: UNKNOWN.
Why unresolved: Lua->native is FFI patches only (byte_patch,
VirtualProtect). No patch point for aim injection was identified. The
native aim consumer reads entity state directly; Lua has no verified
handle on it.
What would resolve it: identification of a native->Lua callback or a
verified memory-patch location that alters aim behavior (beyond the
existing lag-comp patches).

3.3 The .rsrc section (~53 MB) of neverlose.dll
-----------------------------------------------
Status: UNKNOWN.
Why unresolved: .rsrc is the largest section (0x03557150 bytes) but its
contents were not analyzed. It may contain embedded Lua scripts, assets,
or the nl.bin bytecode.
What would resolve it: resource enumeration/extraction of neverlose.dll's
.rsrc section.

========================================
4. CORRECTIONS TO PREVIOUS FINDINGS
========================================

4.1 Mapped-image size arithmetic (CONFIRMED correction)
-------------------------------------------------------
  Incorrect earlier statement: base 0x412A0000 + size 0x00DBA000 =
  0x4134BA000.
  Correct: 0x412A0000 + 0x00DBA000 = 0x4205A000.
  The mapped image is TWO blocks:
    Block 1 (WCX): 0x412A0000 – 0x4205A000 (0x00DBA000 bytes)
    Block 2 (RO):  0x4205A000 – 0x42239000 (0x001DF000 bytes)
  All function addresses (0x412Axxxx–0x4159xxxx) are in Block 1; global
  data (0x42xxxxxx) is in Block 2 / adjacent pages.

4.2 nl.bin is NOT a runtime-generated artifact (CONFIRMED correction)
---------------------------------------------------------------------
  Earlier assumption: nl.bin is created after injection.
  Corrected: nl.bin lives only in FemboyLose-main/neverlose/bins/ (source
  tree, mtime 7/14/2026), is not referenced by any binary, and is not
  created at runtime. It is a build asset, not a runtime artifact.

4.3 Aim consumer is NATIVE, not Lua (CONFIRMED)
-----------------------------------------------
  Earlier Phase 5 conclusion: no aim consumer found in inspected Lua.
  Corrected/refined: the aim consumer exists in NATIVE code at
  0x4140C710 (entity iteration), 0x4140CB75 (aim position), 0x41573930
  (vector->angle), 0x41573E80 (normalize), 0x41408800 (apply). Lua has
  no verified binding to it.

========================================
5. WHAT WOULD COMPLETE THE INVESTIGATION
========================================

  1. A network capture of neverlose.dll <-> neverlose-server.exe
     (port 30031) to confirm routes, auth, and the /lua/<name> exchange.
  2. A Lua require() trace from inside csgo.exe (PID 21580) to enumerate
     scripts loaded at init.
  3. x64 disassembly of neverlose-server.exe for route/auth details.
  4. Dynamic instrumentation of the obfuscated helpers (0x41400BF0 /
     0x413F6B40) past trampoline 0x39C21170.
  5. Resource extraction of neverlose.dll's .rsrc section (~53 MB).
  6. Parent-PID check of neverlose-server.exe to determine whether
     loader.exe starts it.

========================================
END
========================================