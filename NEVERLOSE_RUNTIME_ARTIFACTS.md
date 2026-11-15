# NEVERLOSE RUNTIME ARTIFACTS
=============================
Complete inventory of generated/runtime files associated with Neverlose,
with creation, consumption, format, and purpose evidence.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

========================================
1. CORRECTION: nl.bin IS NOT A RUNTIME-GENERATED ARTIFACT
========================================

The earlier working assumption that `nl.bin` is a file "created after
Neverlose is injected" is NOT supported by evidence.

nl.bin location (CONFIRMED):
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\
  neverlose\bins\nl.bin
  Size: 55,578,624 bytes
  mtime: 7/14/2026 8:10:33 PM (source-tree build timestamp)

nl.bin content (CONFIRMED via byte analysis):
  Lua 5.1 standard-library bytecode. Readable strings include:
  "typeDnextEpairs@FipairsgetmetatableLsetmetatable",
  "getfenv", "setfenv", "rawget", "rawset", "rawequal", "rawlen", …
  It is a precompiled Lua 5.1 standard library bundle.

nl.bin runtime status (CONFIRMED):
  - NOT referenced by name in any binary. Grep of neverlose.dll,
    neverlose-server.exe, and loader.exe for "nl.bin" and "bins"
    returned ZERO hits.
  - NOT created at runtime by any component.
  - NOT read or modified at runtime (no observed file handle).
  - It is a SOURCE-TREE / BUILD artifact, part of FemboyLose-main, not a
    generated runtime file.

Conclusion (CONFIRMED): nl.bin does NOT belong in a runtime-artifacts
inventory as a generated file. It is a static source-tree asset.

========================================
2. CONFIRMED RUNTIME / GENERATED ARTIFACTS
========================================

All files under C:\Users\Intel i7 10700k\AppData\Roaming\cabbitwin\ are
created and owned by neverlose-server.exe. They are persistent (survive
restarts), regenerated/updated by the server, and read by the client via
the local HTTP connection.

----------------------------------------------------------------------
2.1 cabbitwin\session.txt
----------------------------------------------------------------------
Creator: neverlose-server.exe (CONFIRMED — server data dir)
When created: at server initialization (file mtime 10/20/2026)
Read by: client auth flow (INFERRED — client presents token)
Modified by: server at login/session refresh (INFERRED)
Persistence: persistent
Format: plain text, two lines:
  token=bd6ed9102799195bcf2accfcca0d4e501d067d258a065f13d1f3cd0c7ffd76ba
  username=Sherlok
Content type: configuration / session identity
Purpose: stores the active user's auth token and username so the client
         can re-authenticate to the local server without re-entering.
Participates in initialization: STRONGLY SUPPORTED (client sends token
to server via WinHTTP to 127.0.0.1:30031).

----------------------------------------------------------------------
2.2 cabbitwin\token.txt
----------------------------------------------------------------------
Creator: neverlose-server.exe
When created: at server initialization / login (mtime 11/15/2026)
Read by: client auth (INFERRED)
Modified by: server on token change (INFERRED)
Persistence: persistent
Format: plain text, raw token:
  bd6ed9102799195bcf2accfcca0d4e501d067d258a065f13d1f3cd0c7ffd76ba
Content type: authentication token
Purpose: bearer token presented to the local server.
Participates in initialization: STRONGLY SUPPORTED.

----------------------------------------------------------------------
2.3 cabbitwin\server\state.json
----------------------------------------------------------------------
Creator: neverlose-server.exe
When created: at server startup (mtime 9/8/2026 in server/; the per-user
copy under users/<hash>/ is 2,457,583 bytes, mtime 10/20/2026)
Read by: server (itself); possibly client (INFERRED)
Modified by: server (writes log, next_entry_id, serial)
Persistence: persistent
Format: JSON:
  {"username":"local","next_entry_id":3,"log":[],"serial":"",
   "created_at":"2026-09-08T21:14:53Z"}
Content type: server runtime state
Purpose: tracks next entry id, log entries, serial, creation time.
Participates in initialization: STRONGLY SUPPORTED (server state).

----------------------------------------------------------------------
2.4 cabbitwin\server\accounts.json
----------------------------------------------------------------------
Creator: neverlose-server.exe
When created: at account registration / first run (mtime 11/15/2026)
Read by: server at auth (CONFIRMED structure); client (INFERRED)
Modified by: server on registration/login
Persistence: persistent
Format: JSON array:
  [{"username":"Sherlok","dir":"bd6ed910…",
    "tokens":["bd6ed910…76ba"],
    "password":"6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
    "hwid":"f708b80705aa8aaec981bc371afd4cfe886ccc8941f94c94838995a09c2bee17",
    "uid":1}]
Content type: user account database
Purpose: maps username -> directory token hash, tokens, password hash,
         HWID, uid. Used for client authentication.
Participates in initialization: STRONGLY SUPPORTED (auth).

----------------------------------------------------------------------
2.5 cabbitwin\server\users/<hash>/  (per-user directory)
----------------------------------------------------------------------
Example: users/bd6ed9102799195bcf2accfcca0d4e501d067d258a065f13/
Creator: neverlose-server.exe (per user)
When created: at user registration (mtime 11/15/2026)
Read by: server; client scripts (INFERRED)
Modified by: server and client features
Persistence: persistent
Subcontents (observed):
  - libraries/   (Lua libraries copied/served per user)
  - scripts/     (per-user Lua scripts)
  - configs/     (user config files, e.g. 14_Config.cfg 13 KB,
                  17_OrangeFIG.cfg 155 KB, 3_OrangeFIG.cfg 459 KB)
  - languages/   (localization)
  - styles/      (UI styles, e.g. 23_Style.style)
  - state.json   (2,457,583 bytes — large per-user state)
  - avatar.png   (1,151 bytes)
  - .spam_purged_v2 (1 byte flag)
  - .trash/      (trash directory)
Format: mixed — Lua source (.lua), config (.cfg), style (.style),
        JSON (state.json), PNG (avatar.png)
Content type: per-user configuration, scripts, UI state, assets
Purpose: isolates each user's config, scripts, and state.
Participates in initialization: STRONGLY SUPPORTED (per-user Lua scripts
         and configs are loaded by the client).

----------------------------------------------------------------------
2.6 cabbitwin\server\certs\{cert.pem, key.pem}
----------------------------------------------------------------------
Creator: neverlose-server.exe (at install)
When created: 9/8/2026
Read by: server (TLS handshake)
Modified by: never (regenerated only on reinstall)
Persistence: persistent
Format: PEM (cert.pem 552 bytes, key.pem 246 bytes)
Content type: TLS certificate and private key
Purpose: TLS encryption for the local HTTP server.
Participates in initialization: STRONGLY SUPPORTED (server TLS setup).

----------------------------------------------------------------------
2.7 cabbitwin\server\scripts\libraries\*.lua  (~100 files)
----------------------------------------------------------------------
Creator: neverlose-server.exe (distributed with server; source in
  cabbitwin tree)
When created: at server install (mtime 9/8/2026)
Read by: neverlose.dll via QueryLuaLibrary -> WinHTTP GET /lua/<name>
         (CONFIRMED mechanism; specific files loaded at runtime UNKNOWN)
Modified by: server updates only
Persistence: persistent
Format: Lua 5.1 source
Content type: Lua standard + Neverlose API libraries:
  aa_handler, aes, animations, anti_aim, base64, bomb, cbor, circuit,
  crc32, csgo_weapons, debugoverlay, dkjson, drag_lib, easing,
  easy_hook, ent_c, events, events_extended, exploits, file, file_system,
  get_defensive, gradient, hashing, inspect, integrity, lagrecord,
  mtools, mui, nl_json, panel, pui, renderer, rich_presence, sha, sha1,
  smoothy, strings, surface, timer, tween, uix, utils, vmt_hook,
  voice_listener, websockets, windows, window_system, wndproc, …
Purpose: the Lua API surface available to scripts executing inside
         neverlose.dll.
Participates in initialization: CONFIRMED (QueryLuaLibrary fetches these).

========================================
3. FILES THAT ARE NOT RUNTIME ARTIFACTS
========================================

----------------------------------------------------------------------
3.1 nl.bin (FemboyLose-main/neverlose/bins/nl.bin)
----------------------------------------------------------------------
Why excluded: source-tree build artifact (mtime 7/14/2026), not created
at runtime, not referenced by any binary, not read/modified at runtime.
Content: Lua 5.1 bytecode stdlib (55 MB).
Status: CONFIRMED not a generated runtime artifact.

----------------------------------------------------------------------
3.2 Dumper\ and Dumper.v2\
----------------------------------------------------------------------
Why excluded: third-party analysis tools (Il2CppDumper, Ghidra/IDA
scripts, il2cpp.h, script.json, dump.cs), not produced by Neverlose at
runtime and not consumed by it.
Status: CONFIRMED not runtime artifacts.

----------------------------------------------------------------------
3.3 neverlose-last.rar (6 MB) and 08.09.2026.rar (33 MB)
----------------------------------------------------------------------
Why excluded: distribution archives containing copies of the binaries
(neverlose.dll, neverlose-server.exe, loader.exe, snowfall.lua), not
runtime-generated files.
Status: CONFIRMED distribution packages, not runtime artifacts.

----------------------------------------------------------------------
3.4 SaveSlot_1.es3 (151,584 bytes)
----------------------------------------------------------------------
Why excluded: appears to be a Unity/SaveSlot file unrelated to Neverlose
(C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\SaveSlot_1.es3). No evidence
of Neverlose creating or reading it.
Status: UNKNOWN relevance to Neverlose; not attributed to Neverlose.

========================================
4. ARTIFACT CREATION / CONSUMPTION SUMMARY
========================================

Component       Creates                          Reads/Consumes
--------------  ---------------------------------  ----------------------------------------------
loader.exe      (downloads DLL to temp — not       neverlose.dll (injects into csgo.exe)
                observed as a persistent file)
neverlose.dll   (no files created; patches memory  cabbitwin session/token via WinHTTP;
   in its own address space)                        Lua scripts via GET /lua/<name>
neverlose-server  session.txt, token.txt,          none from client (server is the source)
.exe              state.json, accounts.json,
                    users/<hash>/{libraries,scripts,
                    configs,languages,styles,state.json,
                    avatar.png}, certs/{cert,key}.pem,
                    scripts/libraries/*.lua

Data flow of artifacts:
  neverlose-server.exe owns all artifacts in cabbitwin\.
  neverlose.dll reads them indirectly: it connects to the server
  (WinHTTP 127.0.0.1:30031) and fetches Lua scripts via /lua/<name>;
  session/token are sent up during auth.
  No artifact is written back from the client to the server's disk in the
  observed evidence (client->server direction is HTTP requests only).

========================================
5. TEMPORARY vs PERSISTENT vs REGENERATED
========================================

  Persistent (server-owned, survive restart):
    session.txt, token.txt, state.json, accounts.json,
    users/<hash>/*, certs/{cert,key}.pem, scripts/libraries/*.lua
  Temporary / in-memory only:
    none observed on disk (all Neverlose state is either in the mapped
    DLL process memory or in the persistent cabbitwin files)
  Regenerated:
    state.json (log/next_entry_id/serial updated by server),
    accounts.json (on registration/login),
    per-user state.json (2.4 MB — actively written)
  Not regenerated / static:
    cert.pem, key.pem, the *.lua libraries (unless server updated)

========================================
6. LIMITATIONS
========================================

  - The exact set of Lua scripts fetched via /lua/<name> at runtime init
    is UNKNOWN (no require() trace observed; require() calls in workspace
    scripts reference "neverlose/..." but runtime loading is server-driven).
  - Whether the client writes any file back to cabbitwin\ is UNKNOWN
    (client->server direction observed only as HTTP requests).
  - nl.bin is never loaded at runtime per current evidence; if a runtime
    copy exists elsewhere it was not located.
  - SaveSlot_1.es3 relevance to Neverlose is UNKNOWN (not attributed).

========================================
END
========================================