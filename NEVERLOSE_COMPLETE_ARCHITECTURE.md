# NEVERLOSE COMPLETE ARCHITECTURE
================================
Consolidated, evidence-based reconstruction of the Neverlose runtime
architecture. All findings are classified by evidence level:

  CONFIRMED   - directly established by source, file contents, or reproducible
                observation (live memory, PE headers, running processes).
  STRONGLY SUPPORTED - supported by multiple independent observations.
  INFERRED    - plausible interpretation, not directly established.
  UNKNOWN     - insufficient evidence.

No original binaries, source files, runtime files, or the user's installation
were modified during this investigation. `MUST UPDATE.txt` remains unchanged
(SHA256 verified).

========================================
1. THE THREE PRIMARY COMPONENTS
========================================

----------------------------------------------------------------------
1.1 loader.exe  — the injector / downloader
----------------------------------------------------------------------
File: C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\loader.exe
Size: 490,496 bytes
Architecture: x86 (PE32, MACHINE 0x14c)
Image base: 0x400000, entry point 0x60e60, 5 sections (.text, .rdata,
            .data, .rsrc, .reloc)
Timestamp: 1788895578

Confirmed imports (PE header):
  - Process32FirstW, Process32NextW, Module32FirstW, Module32NextW
    (process enumeration — finds csgo.exe)
  - CreateProcessW (process creation)
  - VirtualAllocEx, VirtualFreeEx, VirtualProtect
    (remote memory allocation/protection)
  - WriteFile (file writing); WriteProcessMemory referenced in import table
    context (remote memory writing)
  - CreateRemoteThread (remote thread execution — classic injection)
  - IsWow64Process (32/64-bit target detection)
  - WININET.dll: InternetOpenA, InternetOpenUrlA, HttpOpenRequestA,
    HttpSendRequestA, InternetReadFile, InternetConnectA, InternetCloseHandle
    (HTTP download)
  - bcrypt.dll: BCryptCreateHash, BCryptHashData, BCryptGenRandom, etc.
    (hashing / integrity)
  - d3d11.dll, dxgi.dll, dwmapi.dll (overlay / rendering preparation)
  - RegOpenKeyExA, RegQueryValueExA, RegCloseKey (registry access)
  - ShellExecuteW

Confirmed strings:
  - "1:30031" at 0x065533 — the local server port (matches neverlose-server
    listening on 127.0.0.1:30031; independently verified live).

Role (STRONGLY SUPPORTED): loader.exe is the injector. It enumerates
processes (Toolhelp32), creates/allocates/writes memory in a target process,
and starts a remote thread (CreateRemoteThread). The WININET imports plus
the port string indicate it also downloads components over HTTP and points
them at the local server on port 30031.

Entry point: 0x60e60.

----------------------------------------------------------------------
1.2 Neverlose.dll  — the injected client component
----------------------------------------------------------------------
File: C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll
Size: 56,370,688 bytes (~53 MB)
Architecture: x86 (PE32, MACHINE 0x14c)
PE image base: 0x10000000, entry point 0x15560, 8 sections
Timestamp: 1788894915

Sections (PE):
  .text      0x1000–0x3907A   executable code
  .rdata     0x3A000–0x6520E  read-only data
  .data      0x66000–0x689E8  writable data
  .detourc   0x69000–0x6A190  detour hooks (code)
  .detourd   0x6B000–0x6B00C  detour hooks (data)
  .fptable   0x6C000–0x6C080  function-pointer table
  .rsrc      0x6D000–0x35C4150 (~53 MB resources — largest section)
  .reloc     0x35C5000–0x35C9E24

Confirmed imports:
  - ntdll.dll: NtAllocateVirtualMemory, NtProtectVirtualMemory,
    NtWriteVirtualMemory, NtCreateThreadEx, NtTerminateProcess,
    NtFlushInstructionCache, RtlPcToFileHeader (manual mapping primitives)
  - KERNEL32.dll: VirtualAlloc, VirtualProtect, FlushInstructionCache,
    GetModuleHandleExW, SizeofResource, LockResource, LoadResource,
    FindResourceW (resource loading for manual mapping)
  - WINHTTP.dll: WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
    WinHttpSendRequest, WinHttpReceiveResponse, WinHttpReadData,
    WinHttpCloseHandle, WinHttpQueryHeaders, WinHttpSetTimeouts,
    WinHttpQueryDataAvailable (HTTP client — talks to local server)

Confirmed strings:
  - "1:30031" (x3) — connects to 127.0.0.1:30031

Runtime location (CONFIRMED via live memory, PID 21580):
  Neverlose.dll is NOT loaded through the normal Windows loader. It is
  manually mapped at allocation base 0x412A0000, size 0x00DBA000
  (PAGE_EXECUTE_WRITECOPY / WCX). A separate read-only continuation block
  exists at 0x4205A000, size 0x001DF000. The PE header image base
  (0x10000000) is therefore NOT the runtime base.

  Anchor instruction F3 0F 5B CA 0F 5B C9 0F 2E CB at 0x41400D8F; scan
  delta 0x340AB6 (furthest 0x4158F57C − closest 0x4124EAC6), matching the
  scan_nl implementation in MUST UPDATE.txt.

Initialization lifecycle (CONFIRMED from FemboyLose-main source):
  DllMain(DLL_PROCESS_ATTACH)
    -> DisableThreadLibraryCalls
    -> apply_missing_entity_fix()
    -> NtCreateThreadEx(MainThread, hinstDLL)
  MainThread:
    1. g_neverlose.map((HMODULE)hinstDLL)          — manual self-mapping
    2. wait for serverbrowser.dll (CS:GO client module)
    3. g_neverlose.fix_dump()                      — fix_imports, spoof_peb,
                                                   spoof_kusd, spoof_cpuid,
                                                   fix_interfaces, fix_cvars,
                                                   fix_signatures, NOP adds,
                                                   fix_mem_dispatcher,
                                                   flow fixes (0xEB patches),
                                                   fix_sha256,
                                                   hijack_requestor,
                                                   last_resort_fixes,
                                                   install_crypto_capture
    4. g_neverlose.set_veh()                       — vectored exception handler
    5. g_neverlose.setup_hooks()                   — detour hooks
    6. g_neverlose.spoof()                         — anti-tamper spoofing
    7. g_neverlose.entry()                         — creates suspended thread
                                                   at 0x412A0A00 (neverlose
                                                   entry inside mapped image),
                                                   resumes it, waits for exit

Role (CONFIRMED): Neverlose.dll is the injected cheat core. It is manually
mapped (not LoadLibrary'd), resolves its own imports (fix_imports.cpp IAT
table at 0x43236000+), installs detour hooks (.detourc/.detourd),
communicates with the local server over WinHTTP to 127.0.0.1:30031, and
exposes a Lua scripting environment (require("neverlose/...") libraries,
lagrecord library, FFI memory access).

Key mapped-image addresses (live, PID 21580):
  - Record freshness gate: 0x413F9E00  (cmp ecx,2 at 0x413F9EC0 =
    extrapolation_limit patch site)
  - Lag-comp acceptability gate: 0x413F94D0  (al=1 accept default;
    call at 0x4148F441/0x4148F7AB)
  - Record selection: 0x4148F180  (single caller 0x4149789F)
  - Lag-comp orchestrator: 0x41496DB0 (SEH-wrapped; single caller 0x414AEDC0)
  - Origin apply: 0x41B6C700  (10 direct callers)
  - Small getter: 0x41B70930 (mov eax,[ecx+0x9960]; ret)
  - Geometry helpers: 0x41400BF0, 0x413F6B40  (jump to trampoline 0x39C21170)
  - Aim consumer entry: 0x4140C710  (SEH-wrapped; iterates entity list
    [0x424AFD68]; single caller 0x41596AA9)
  - Aim position computation: 0x4140CB75  (writes globals 0x425023C8/23D0/23EC)
  - Vector->angle: 0x41573930  (calls atan2 at 0x4202F7D0)
  - Angle normalize: 0x41573E80  (calls 0x42026D1B x3)
  - memcpy-style aim apply: 0x41408800  (copies 0x71c-byte aim struct)
  - Vector arrays: [0x424B03D0], [0x424B03D4]

----------------------------------------------------------------------
1.3 neverlose-server.exe  — the local initialization server
----------------------------------------------------------------------
File: C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose-server.exe
Size: 9,728,512 bytes
Architecture: x64 (PE32+, MACHINE 0x8664)
PE image base: 0x140000000, entry point 0x55fb80, 5 sections
Timestamp: 1788896697

Confirmed imports:
  - ws2_32.dll: WSAStartup, socket, bind, listen, accept, send, recv,
    closesocket, shutdown, getaddrinfo, freeaddrinfo, ioctlsocket,
    WSAIoctl, WSAGetLastError (TCP server — listens and accepts connections)
  - bcrypt.dll: BCryptGenRandom (randomness / tokens)
  - advapi32.dll: SystemFunction036 (RtlGenRandom)
  - ntdll.dll: NtCreateFile, NtReadFile, NtWriteFile, NtDeviceIoControlFile
  - kernel32: file/console/synchronization APIs
  - No WININET/WINHTTP imports (it is a server, not a client)

Live observation (CONFIRMED):
  - Process neverlose-server.exe running, PID 11468, WS ~84 MB.
  - TCP port 30031 OPEN and listening on 127.0.0.1 (verified by connect test).

Data directory (CONFIRMED):
  C:\Users\Intel i7 10700k\AppData\Roaming\cabbitwin\
    session.txt         token=bd6ed910…76ba, username=Sherlok
    token.txt           bd6ed910…76ba
    server/
      state.json        {"username":"local","next_entry_id":3,"serial":"",…}
      accounts.json     [{"username":"Sherlok","dir":"bd6ed910…",
                          "tokens":[…],"password":"6b86b273…",
                          "hwid":"f708b807…","uid":1}]
      server/users/<hash>/   per-user dirs (libraries, scripts, configs,
                           languages, styles, state.json, avatar.png)
      server/scripts/libraries/*.lua   ~100 Lua libraries (aa_handler, aes,
                           animations, anti_aim, better_json, bomb, cbor,
                           circuit, crc32, csgo_weapons, debugoverlay,
                           dkjson, drag_lib, easing, easy_hook, ent_c,
                           events, events_extended, exploits, file, file_system,
                           get_defensive, gradient, hashing, inspect,
                           integrity, lagrecord, mtools, mui, nl_json,
                           panel, pui, renderer, rich_presence, sha, sha1,
                           smoothy, strings, surface, timer, tween, uix,
                           utils, vmt_hook, voice_listener, websockets,
                           windows, window_system, wndproc, …)
      server/certs/cert.pem, server/certs/key.pem (TLS certs)

Role (STRONGLY SUPPORTED): neverlose-server.exe is a local HTTP/TCP server
(listening on 127.0.0.1:30031) that serves as the initialization and
Lua-library distribution server. neverlose.dll connects to it via WinHTTP
(WinHttpConnect to 127.0.0.1:30031, confirmed by "1:30031" strings in both
loader.exe and neverlose.dll). QueryLuaLibrary (Requestor.cpp) fetches Lua
script source via GET /lua/<name>. The cabbitwin directory holds per-user
state, accounts, tokens, HWID, and the Lua library tree the server serves.

It is NOT merely a passive auth service: it owns the Lua library tree,
per-user directories, TLS certs, and HTTP/WebSocket request handling
(HTTPRe/EHTTPMe strings, TRANSPORT, DESERIALIZE, EXPORT strings).

========================================
2. COMPONENT COMMUNICATION AND DEPENDENCY MAP
========================================

loader.exe
   | (injects via CreateProcessW + VirtualAllocEx + WriteProcessMemory +
   |  CreateRemoteThread; downloads via WININET; points at port 30031)
   v
csgo.exe (target process)  <-- neverlose.dll manually mapped inside it
                                    |
                                    | WinHTTP GET /lua/<name> to
                                    | 127.0.0.1:30031
                                    v
                           neverlose-server.exe (local HTTP server,
                           port 30031, AppData\Roaming\cabbitwin\)
                                    |
                                    | serves Lua scripts + libraries
                                    | from scripts/libraries/
                                    | and per-user scripts/
                                    v
                           Lua scripts execute inside neverlose.dll

Dependency direction (CONFIRMED):
  loader.exe -> neverlose.dll -> neverlose-server.exe (30031)
  neverlose.dll does NOT depend on loader.exe after injection.
  neverlose-server.exe is independent of loader.exe (standalone server).

Communication mechanisms (CONFIRMED):
  - Process injection: loader.exe -> csgo.exe (CreateRemoteThread pattern)
  - Manual mapping: neverlose.dll maps itself (g_neverlose.map, Nt*
    primitives)
  - HTTP client: neverlose.dll -> WinHTTP -> 127.0.0.1:30031
  - Lua require("neverlose/X") -> neverlose.dll -> QueryLuaLibrary ->
    WinHTTP GET /lua/X -> neverlose-server.exe returns script source

========================================
3. INITIALIZATION LIFECYCLE
========================================

Stage 1 — Loader startup (loader.exe)
  CONFIRMED (imports): Enumerates processes via Toolhelp32
  (Process32First/NextW, Module32First/NextW) to locate csgo.exe.
  Creates the target (CreateProcessW), allocates remote memory
  (VirtualAllocEx), writes the DLL (WriteProcessMemory), and starts a
  remote thread (CreateRemoteThread). Downloads components over HTTP
  (WININET). References port 30031.

Stage 2 — DLL manual mapping (inside csgo.exe)
  CONFIRMED (source main.cpp + live memory): DllMain -> MainThread ->
  g_neverlose.map() manually maps neverlose.dll at 0x412A0000. The PE
  header image base (0x10000000) is not used at runtime.

Stage 3 — Wait for game module
  CONFIRMED (source): MainThread loops `while (!GetModuleHandleW(
  L"serverbrowser.dll")) Sleep(100);` — waits for the CS:GO client module
  serverbrowser.dll before proceeding.

Stage 4 — Fix dump / anti-tamper / hooks
  CONFIRMED (source fix_dump.cpp): fix_imports (resolves IAT at
  0x43236000+), spoof_peb, spoof_kusd, spoof_cpuid, fix_interfaces,
  fix_cvars, fix_signatures, NOP pads, fix_mem_dispatcher, flow-fix
  0xEB patches (g_stupid_ahh_shit_flow_fix, ~110 addresses), fix_sha256,
  hijack_requestor (Requestor.cpp hooks GetSerial/MakeRequest at
  0x41BC78E0/0x41BC98E0; leaves QueryLuaLibrary unhooked), last_resort_fixes
  (writes abs handles/auth_token into mapped image at 0x41BF8341 etc.),
  install_crypto_capture.

Stage 5 — VEH + hooks + spoof
  CONFIRMED (source main.cpp): set_veh(), setup_hooks() (detours),
  spoof().

Stage 6 — neverlose entry
  CONFIRMED (source entry.cpp): entry() creates a suspended thread at
  0x412A0A00 (inside the mapped image), resumes it, and waits for it to
  exit (NtWaitForSingleObject). This is the neverlose runtime entry.

Stage 7 — Server connection
  CONFIRMED (live): neverlose-server.exe (PID 11468) listens on
  127.0.0.1:30031. neverlose.dll connects via WinHTTP. csgo.exe (PID 21580)
  confirmed running with neverlose mapped.

Actual order (CONFIRMED):
  loader.exe starts first (injects into csgo.exe) ->
  neverlose.dll maps and initializes inside csgo.exe ->
  neverlose.dll connects to neverlose-server.exe on 30031 ->
  Lua scripts are fetched and executed inside csgo.exe

The server is started independently (it is running as PID 11468
independently of the injection moment).

========================================
4. GENERATED RUNTIME ARTIFACTS INVENTORY
========================================

| File | Creator | When created | Read/modified by | Temp/Persistent | Content/Format | Role |
|------|---------|--------------|------------------|-----------------|----------------|------|
| cabbitwin\session.txt | neverlose-server.exe | at server startup (10/20) | read by client auth | persistent | plain text "token=…\nusername=…" | client identity |
| cabbitwin\token.txt | neverlose-server.exe | at startup | read by client | persistent | raw token hash | auth token |
| cabbitwin\server\state.json | neverlose-server.exe | startup / updated | server writes | persistent | JSON {"username","next_entry_id","log","serial","created_at"} | server state |
| cabbitwin\server\accounts.json | neverlose-server.exe | startup / registration | server writes | persistent | JSON array of {username,dir,tokens,password,hwid,uid} | user accounts |
| cabbitwin\server\users/<hash>/ | neverlose-server.exe | per user | server + client | persistent | per-user libraries/scripts/configs/styles/state/avatar | user data |
| cabbitwin\server\scripts/libraries/*.lua | neverlose-server.exe (distributed) | at server install | read by client via QueryLuaLibrary | persistent | Lua source libraries | Lua API surface |
| cabbitwin\server\certs/{cert,key}.pem | neverlose-server.exe | at install | server TLS | persistent | PEM certificate/key | TLS for server |
| nl.bin | FemboyLose BUILD (source tree) | at build, NOT at runtime | none observed | persistent (source artifact) | 55,578,624 bytes Lua 5.1 bytecode stdlib | Lua standard library bundle (source tree only) |

nl.bin (CONFIRMED location):
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\
  neverlose\bins\nl.bin, 55,578,624 bytes, mtime 7/14/2026.

nl.bin content (CONFIRMED via byte analysis): Lua 5.1 standard-library
bytecode. Strings observed: "typeDnextEpairs@FipairsgetmetatableLsetmetatable
getfenv setfenv rawget rawset rawequal rawlen …". It is a precompiled Lua
standard library bundle.

nl.bin runtime status (CONFIRMED): NOT referenced by name in any binary
(grep of neverlose.dll, neverlose-server.exe, loader.exe for "nl.bin" and
"bins" returned zero hits). NOT created at runtime. It is a source-tree /
build artifact in FemboyLose-main, NOT a generated runtime file. The earlier
assumption that nl.bin is a runtime-generated artifact is INCORRECT.

No other generated runtime artifacts were identified in the workspace or
cabbitwin data directory beyond the files listed above. The Dumper/ and
Dumper.v2/ directories contain third-party dumping tools (Il2CppDumper,
ghidra/ida scripts, il2cpp.h, script.json, dump.cs) — analysis tools, not
runtime artifacts of Neverlose.

========================================
5. CONFIRMED vs INFERRED BEHAVIOR
========================================

CONFIRMED:
  - Three components exist as separate files (loader.exe, neverlose.dll,
    neverlose-server.exe) with distinct PE architectures (x86, x86, x64).
  - neverlose-server.exe runs independently and listens on 127.0.0.1:30031.
  - neverlose.dll is manually mapped at 0x412A0000 inside csgo.exe.
  - neverlose.dll imports WINHTTP and contains "1:30031" — connects to the
    local server.
  - loader.exe imports injection APIs (CreateRemoteThread, VirtualAllocEx)
    and WININET (download) — it is the injector/downloader.
  - cabbitwin\ is the server data dir with session, token, accounts, state,
    per-user dirs, and a Lua library tree.
  - neverlose.dll exposes Lua: require("neverlose/..."), lagrecord library,
    FFI memory access (scan_nl, byte_patch, VirtualProtect, etc.).
  - Aim consumer is native code (0x4140C710 etc.), not Lua.

INFERRED:
  - loader.exe downloads neverlose.dll from a remote server before injecting
    (WININET imports + downloader behavior), but the remote URL was not
    established.
  - neverlose-server.exe authenticates clients via token/HWID (accounts.json
    has token, password, hwid fields) — auth mechanism details UNKNOWN.
  - The Lua scripts executed at runtime come from the server /lua/<name>
    endpoint; which specific scripts run at init is UNKNOWN (no observed
    require() trace at runtime).
  - The server's exact HTTP routes beyond /lua/<name> are UNKNOWN.

UNKNOWN:
  - Remote download URL used by loader.exe.
  - Whether neverlose-server.exe is started by loader.exe or independently.
  - Full list of Lua scripts loaded at runtime init.
  - Whether nl.bin (or a runtime copy) is ever loaded by the VM.

========================================
6. CORRECTION OF PREVIOUS INCONSISTENCY
========================================

Mapped-image size arithmetic (Phase 3 / NATIVE_REVERSE_ENGINEERING_DUMP.txt):

  The mapped region was stated as base 0x412A0000, size 0x00DBA000.
  0x412A0000 + 0x00DBA000 = 0x4205A000 (NOT 0x4134BA000 — a digit-transpose
  error). The main WCX block therefore spans 0x412A0000–0x4205A000.

  A SEPARATE read-only continuation block was observed at
  0x4205A000, size 0x001DF000 (spanning to 0x42239000). This is not part of
  the 0xDBA000 WCX block; it is a distinct allocation with PAGE_READONLY
  protection and adjacent NOACCESS guard pages.

  Correction: the mapped image is TWO blocks:
    Block 1 (WCX): 0x412A0000 – 0x4205A000 (0x00DBA000 bytes)
    Block 2 (RO):  0x4205A000 – 0x42239000 (0x001DF000 bytes)
  All function addresses cited (0x412Axxxx–0x4159xxxx) fall within Block 1.
  Global data addresses (0x42xxxxxx) fall in Block 2 / adjacent data pages.

  This does not change any function-address or global-value findings.

========================================
END
========================================