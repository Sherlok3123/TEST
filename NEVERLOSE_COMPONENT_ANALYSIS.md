# NEVERLOSE COMPONENT ANALYSIS
==============================
Separate technical analysis of the three components: loader.exe,
Neverlose.dll, and neverlose-server.exe. Responsibilities, boundaries,
source availability, and recovery limitations.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

========================================
1. COMPONENT 1 — loader.exe  (the injector / downloader)
========================================

File: C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\loader.exe
Size: 490,496 bytes
Architecture: x86 PE32 (MACHINE 0x14c)
PE image base: 0x400000; entry point 0x60e60; 5 sections
Timestamp: 1788895578

1.1 Responsibilities
--------------------
(CONFIRMED via imports)
  - Process enumeration: Process32FirstW/NextW, Module32FirstW/NextW —
    locates the target (csgo.exe) by name/module walk.
  - Process creation: CreateProcessW — can spawn the target suspended.
  - Remote memory: VirtualAllocEx, VirtualFreeEx, VirtualProtect,
    WriteProcessMemory (import context) — allocates and writes into the
    target process.
  - Remote execution: CreateRemoteThread — starts code in the target.
  - HTTP download: WININET.dll (InternetOpenA, InternetOpenUrlA,
    HttpOpenRequestA, HttpSendRequestA, InternetReadFile,
    InternetConnectA, InternetCloseHandle) — fetches components over HTTP.
  - Integrity/hashing: bcrypt.dll (BCryptCreateHash, BCryptHashData,
    BCryptGenRandom, …).
  - Overlay prep: d3d11.dll, dxgi.dll, dwmapi.dll.
  - Registry: RegOpenKeyExA, RegQueryValueExA, RegCloseKey.
  - Shell: ShellExecuteW.

(CONFIRMED via strings)
  - "1:30031" at 0x065533 — references the local server port 30031.

1.2 Boundaries
--------------
(CONFIRMED): loader.exe runs OUTSIDE csgo.exe. It does not contain the
cheat logic. Its job is to obtain the DLL and inject it. After injection
it has no further runtime role (no evidence of a resident loader).

Source availability:
  CONFIRMED ABSENT. No loader source is present in the workspace. The only
  source tree present (FemboyLose-main/) is the neverlose.dll source, not
  the loader. loader.exe behavior is reconstructed solely from PE imports
  and strings (INFERRED for the download URL, which was not located).

1.3 Recovery limitations
------------------------
  - The remote download URL is UNKNOWN (not in strings).
  - The exact injection sequence (CreateProcessW suspended vs. open-process
    of a running csgo) cannot be determined from imports alone.
  - No symbol/PBD information; all addresses are raw.

========================================
2. COMPONENT 2 — Neverlose.dll  (the injected client / cheat core)
========================================

File: C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll
Size: 56,370,688 bytes (~53 MB)
Architecture: x86 PE32 (MACHINE 0x14c)
PE image base: 0x10000000; entry point 0x15560; 8 sections
Timestamp: 1788894915

2.1 Responsibilities
--------------------
(CONFIRMED via imports + live memory + source)
  - Manual self-mapping: ntdll NtAllocateVirtualMemory,
    NtProtectVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx,
    NtFlushInstructionCache; KERNEL32 VirtualAlloc, VirtualProtect,
    FlushInstructionCache, GetModuleHandleExW, SizeofResource, LockResource,
    LoadResource, FindResourceW. The DLL maps ITSELF at 0x412A0000 (WCX)
    rather than being LoadLibrary'd.
  - Import resolution: builds its own IAT (fix_imports.cpp table at
    0x43236000+, mapping ntdll/kernel32/user32/gdi32/winmm/v8/ws2_32/
    advapi32/ole32/combase/imm32/iphlpapi/bcrypt/crypt32 to absolute
    addresses in the mapped image).
  - Anti-tamper / spoofing: spoof_peb, spoof_kusd, spoof_cpuid,
    fix_sha256, install_crypto_capture (fix_dump.cpp).
  - Detour hooks: .detourc/.detourd sections, setup_hooks().
  - Vectored exception handling: set_veh().
  - HTTP client: WINHTTP.dll — connects to 127.0.0.1:30031 ("1:30031"
    strings x3 in neverlose.dll and loader.exe).
  - Lua environment: require("neverlose/…") libraries, lagrecord library
    (get_record/get_snapshot/get_all/set_update_callback), FFI memory
    access (scan_nl, byte_patch, VirtualProtect, FlushInstructionCache).
  - Aim consumption: native aim pipeline at 0x4140C710 (entity iteration),
    0x4140CB75 (aim position -> globals 0x425023C8/23D0/23EC),
    0x41573930 (vector->angle via atan2), 0x41573E80 (normalize),
    0x41408800 (memcpy aim-struct apply).

2.2 Initialization lifecycle (CONFIRMED from FemboyLose-main source)
---------------------------------------------------------------------
  DllMain(DLL_PROCESS_ATTACH)
    -> DisableThreadLibraryCalls(hinstDLL)
    -> apply_missing_entity_fix()
    -> NtCreateThreadEx(MainThread, hinstDLL)
  MainThread:
    1. g_neverlose.map((HMODULE)hinstDLL)          — manual self-map
    2. while (!GetModuleHandleW(L"serverbrowser.dll")) Sleep(100)
                                                       — wait for CS:GO client
    3. g_neverlose.fix_dump()                        — fix_imports,
                                                       spoof_peb/kusd/cpuid,
                                                       fix_interfaces/cvars/
                                                       signatures, NOP pads,
                                                       flow fixes (0xEB),
                                                       fix_sha256,
                                                       hijack_requestor,
                                                       last_resort_fixes,
                                                       install_crypto_capture
    4. g_neverlose.set_veh()                         — VEH install
    5. g_neverlose.setup_hooks()                     — detour hooks
    6. g_neverlose.spoof()                           — anti-tamper spoof
    7. g_neverlose.entry()                           — NtCreateThreadEx at
                                                       0x412A0A00 (suspended),
                                                       NtResumeThread,
                                                       NtWaitForSingleObject

2.3 Runtime location (CONFIRMED via live memory PID 21580)
-----------------------------------------------------------
  Manually mapped at allocation base 0x412A0000, size 0x00DBA000 (WCX),
  plus a separate read-only continuation block at 0x4205A000
  (size 0x001DF000). PE header image base 0x10000000 is NOT used at
  runtime. Anchor F3 0F 5B CA 0F 5B C9 0F 2E CB at 0x41400D8F; scan delta
  0x340AB6.

2.4 Key mapped-image functions (live disassembly)
-------------------------------------------------
  - 0x413F9E00  record freshness gate (cmp ecx,2 at 0x413F9EC0 =
    extrapolation_limit patch site; returns record ptr or 0)
  - 0x413F94D0  lag-comp acceptability gate (al=1 accept default;
    horizontal distance vs [0x4206CDC0]=100.0f)
  - 0x4148F180  record selection (nearest record by 3D distance with
    half-tick z projection; single caller 0x4149789F)
  - 0x41496DB0  lag-comp orchestrator (SEH-wrapped; origin assembly
    out = arrayA[i] + arrayB[i]; callers 0x414AEDC0 only)
  - 0x41B6C700  origin apply (10 direct callers; fn ptr [0x424B0408])
  - 0x41B70930  small getter (mov eax,[ecx+0x9960]; ret)
  - 0x41400BF0 / 0x413F6B40  geometry helpers (dead-end at trampoline
    0x39C21170)
  - 0x4140C710  aim consumer entry (SEH-wrapped; iterates entity list
    [0x424AFD68]; single caller 0x41596AA9)
  - 0x4140CB75  aim position computation (writes globals
    0x425023C8/23D0/23EC)
  - 0x41573930  vector->angle (atan2 at 0x4202F7D0)
  - 0x41573E80  angle normalize (0x42026D1B x3)
  - 0x41408800  memcpy-style aim-struct apply (0x71c bytes, ret 4)

2.5 Source availability
------------------------
(CONFIRMED PRESENT): FemboyLose-main/neverlose/ contains C++ source:
main.cpp, entry.cpp, fix_dump.cpp, fix_imports.cpp, fix_interfaces.cpp,
fix_signatures.cpp, fix_cvars.cpp, fix_mem_dispatcher.cpp, fix_sha256.cpp,
spoof.cpp, spoof_peb.cpp, spoof_kusd.cpp, spoof_cpuid.cpp, setup_hooks.cpp,
mem_dispatcher.cpp, VEH.cpp, HookFn.cpp, Requestor.cpp, neverlose.h,
internal_fixes.h, token.h, nops.h. This is the neverlose.dll source.

This source was used to confirm the initialization lifecycle and import
table. It does NOT include loader.exe or neverlose-server.exe source.

2.6 Recovery limitations
------------------------
  - The .rsrc section (~53 MB) is resources; content not analyzed.
  - Obfuscated helper region (0x39C21170 trampoline) cannot be statically
    traced past — behavior of 0x41400BF0/0x413F6B40 beyond that point is
    UNKNOWN.
  - The Lua VM entry point and which Lua scripts run at init are not in the
    C++ source (they are fetched from the server at runtime).

========================================
3. COMPONENT 3 — neverlose-server.exe  (local initialization server)
========================================

File: C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose-server.exe
Size: 9,728,512 bytes
Architecture: x64 PE32+ (MACHINE 0x8664)
PE image base: 0x140000000; entry point 0x55fb80; 5 sections
Timestamp: 1788896697

3.1 Responsibilities
--------------------
(CONFIRMED via imports)
  - TCP server: ws2_32.dll WSAStartup, socket, bind, listen, accept,
    send, recv, closesocket, shutdown, getaddrinfo, freeaddrinfo,
    ioctlsocket, WSAIoctl. It listens and accepts connections.
  - Cryptographic randomness: bcrypt BCryptGenRandom,
    advapi32 SystemFunction036 (RtlGenRandom).
  - File I/O: ntdll NtCreateFile/NtReadFile/NtWriteFile,
    NtDeviceIoControlFile; kernel32 file APIs.
  - Console/synchronization: WriteConsoleW, ReleaseSemaphore,
    SwitchToThread, WaitOnAddress, WakeByAddress*.

(CONFIRMED via strings)
  - HTTP/WebSocket frame handling: HTTPRe, EHTTPMe, SECURITYHTTP,
    TRANSPORT, DESERIALIZE, EXPORT, EXPORTED, UNEXPORTED, SUPPORTED,
    UNSUPPORTED — it parses HTTP/WebSocket messages.
  - CCSGOP (CS:GO process) strings — game-process awareness.

(CONFIRMED via live observation)
  - Running as PID 11468, WS ~84 MB.
  - Listening on TCP 127.0.0.1:30031 (port connect test succeeded).

3.2 Data directory (CONFIRMED)
------------------------------
C:\Users\Intel i7 10700k\AppData\Roaming\cabbitwin\
  session.txt            token=bd6ed910…76ba, username=Sherlok
  token.txt              bd6ed910…76ba (raw token)
  server/
    state.json           {"username":"local","next_entry_id":3,"serial":"",
                          "log":[],"created_at":"2026-09-08T21:14:53Z"}
    accounts.json        [{"username":"Sherlok","dir":"bd6ed910…",
                           "tokens":[…],"password":"6b86b273…",
                           "hwid":"f708b807…","uid":1}]
    server/users/<hash>/   per-user dirs: libraries, scripts, configs,
                           languages, styles, state.json (2.4 MB), avatar.png
    server/scripts/libraries/*.lua   ~100 Lua libraries
    server/certs/cert.pem, key.pem   TLS certificate/key

3.3 Role (STRONGLY SUPPORTED)
-----------------------------
neverlose-server.exe is a LOCAL initialization and Lua-library server,
NOT a passive auth service. It:
  - listens on 127.0.0.1:30031 (CONFIRMED live),
  - serves Lua scripts via GET /lua/<name> (Requestor.cpp QueryLuaLibrary;
    the DLL connects via WinHTTP — "1:30031" confirmed in DLL + loader),
  - owns the Lua library tree (scripts/libraries/*.lua) and per-user
    directories (users/<hash>/),
  - maintains accounts (username, dir, tokens, password, hwid, uid),
    session, token, and server state,
    - uses TLS certs (cert.pem/key.pem).

It is the authority that neverlose.dll talks to for Lua code and
configuration. It is independent of loader.exe (standalone process, PID
11468 running while csgo is PID 21580).

3.4 Source availability
------------------------
(CONFIRMED ABSENT): No neverlose-server.exe source is present in the
workspace. Behavior is reconstructed from PE imports, strings, the live
running process, and the cabbitwin data directory. Exact HTTP routes,
auth handshake, and port-selection logic are UNKNOWN beyond /lua/<name>
and port 30031.

3.5 Recovery limitations
------------------------
  - The server binary is x64; no disassembly was performed in this
    investigation (behavior inferred from imports/strings/live port).
  - The list of routes beyond /lua/<name> is UNKNOWN.
  - Whether the server is started by loader.exe or independently is
    UNKNOWN (it runs as a separate process).

========================================
4. CROSS-COMPONENT BOUNDARIES AND COMMUNICATION
========================================

Boundary: loader.exe <-> csgo.exe
  Mechanism: process injection (CreateProcessW + VirtualAllocEx +
  WriteProcessMemory + CreateRemoteThread). CONFIRMED by loader imports.
  Direction: loader -> target. One-time at injection.

Boundary: neverlose.dll <-> neverlose-server.exe
  Mechanism: WinHTTP client (DLL) -> HTTP server (127.0.0.1:30031).
  CONFIRMED: WINHTTP imports in DLL; "1:30031" strings; server live on
  30031; Requestor.cpp QueryLuaLibrary does WinHttpConnect to 127.0.0.1:30031.
  Content: Lua script source via GET /lua/<name> (Requestor.cpp).

Boundary: loader.exe <-> neverlose-server.exe
  Mechanism: loader references port 30031 ("1:30031" string), suggesting
  the loader points injected components at the server. Direct loader<->server
  communication not established (INFERRED only).

Dependency order (CONFIRMED):
  1. neverlose-server.exe runs (standalone, PID 11468).
  2. loader.exe injects neverlose.dll into csgo.exe (PID 21580).
  3. neverlose.dll initializes (map -> fix_dump -> hooks -> entry).
  4. neverlose.dll connects to server on 30031 and fetches Lua scripts.

========================================
5. SOURCE AVAILABILITY AND RECOVERY SUMMARY
========================================

Component     Source present?  Recoverable?       Basis
------------  ---------------  -----------------  ---------------------------------
loader.exe    NO               PARTIAL (INFERRED)  PE imports + strings only;
                                                no download URL, no exact
                                                injection sequence
Neverlose.dll YES              HIGH               FemboyLose-main/neverlose/
                                                C++ source confirms init
                                                lifecycle, IAT, fix_dump
neverlose-server NO             PARTIAL (INFERRED)  PE imports + strings +
                                                live port + cabbitwin data dir

Lua libraries   YES (server tree)                  cabbitwin\server\scripts\
                                                libraries/*.lua (~100 files)
nl.bin          YES (source tree only)             FemboyLose-main/neverlose/
                                                bins\nl.bin — Lua 5.1 bytecode,
                                                NOT referenced at runtime,
                                                NOT a generated artifact

========================================
END
========================================