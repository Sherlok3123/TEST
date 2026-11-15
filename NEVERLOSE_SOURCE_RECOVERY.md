# NEVERLOSE SOURCE RECOVERY
============================
What original source is available, what can be reconstructed from binaries,
what remains unavailable, and readable architectural pseudocode where
supported by evidence.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

========================================
1. ORIGINAL SOURCE AVAILABILITY
========================================

1.1 Source PRESENT in workspace
-------------------------------

(CONFIRMED) FemboyLose-main/ — the neverlose.dll (injected client) source tree.
Files (selected, all under C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\
FemboyLose-main\neverlose/):

  main.cpp            — DllMain + MainThread (entry, map, fix_dump,
                        set_veh, setup_hooks, spoof, entry)
  entry.cpp           — neverlose::entry() — suspended thread at 0x412A0000
                        +0xA00, resume + wait
  fix_dump.cpp        — fix_imports, spoof_peb/kusd/cpuid, fix_interfaces,
                        fix_cvars, fix_signatures, NOP pads, flow fixes
                        (g_stupid_ahh_shit_flow_fix ~110 addrs), fix_sha256,
                        hijack_requestor, last_resort_fixes,
                        install_crypto_capture
  fix_imports.cpp     — import-address-table fix-up table (0x43236000+)
                        mapping ntdll/kernel32/user32/gdi32/winmm/v8/
                        ws2_32/advapi32/ole32/combase/imm32/iphlpapi/
                        bcrypt/crypt32 to absolute addresses
  fix_interfaces.cpp  — interface fixing (not fully read in this session)
  fix_signatures.cpp  — signature fixing (not fully read)
  fix_cvars.cpp       — cvar fixing (not fully read)
  fix_mem_dispatcher.cpp  — memory dispatcher fix (not fully read)
  fix_sha256.cpp      — SHA256 fixing (not fully read)
  spoof.cpp / spoof_peb.cpp / spoof_kusd.cpp / spoof_cpuid.cpp  — anti-tamper
  setup_hooks.cpp     — detour hook installation (not fully read)
  mem_dispatcher.cpp  — memory dispatcher (not fully read)
  VEH.cpp / HookFn.cpp  — vectored exception handler + hook trampoline
  Requestor.cpp       — QueryLuaLibrary / GetSerial / MakeRequest
                        (WinHTTP to 127.0.0.1:30031; hijack_requestor)
  neverlose.h         — main header (g_neverlose object)
  internal_fixes.h, token.h, nops.h  — support headers

  Source status: CONFIRMED PRESENT. This is the neverlose.dll source.
  It was used to confirm the initialization lifecycle (main.cpp), the
  import table (fix_imports.cpp), and the fix_dump routine
  (fix_dump.cpp).

(CONFIRMED PRESENT) FemboyLose-main/neverlose/bins/nl.bin — Lua 5.1
  bytecode stdlib (55 MB). Source-tree asset, NOT a runtime artifact
  (see NEVERLOSE_RUNTIME_ARTIFACTS.md).

(CONFIRMED PRESENT) Workspace Lua scripts (*.lua / *.txt):
  Aesthetic BETA.txt, BetterNL.txt, BlueSense.lua,
  BLUESENSE_HOLY_GRAIL.lua, bluesense_modular_*.lua, ethernance.lua,
  Elysian.lua, github_*.lua, lagcomp_dumper.lua, mori.txt, nyanza.lua,
  NyaHOOK.lua, Outlaw.lua, Prediction.lua, records_dumper.lua,
  REFRACTED.lua, rebelion.txt, snowfall.lua, TestUI.lua, etc.
  These are user scripts that execute inside neverlose.dll's Lua VM.

(CONFIRMED PRESENT) cabbitwin\server\scripts\libraries\*.lua (~100 files):
  The server's Lua library tree (aa_handler, aes, anti_aim, cbor, dkjson,
  events, file_system, lagrecord, pui, renderer, sha, websockets, …).
  These are the Lua libraries the server serves via /lua/<name>.

1.2 Source ABSENT from workspace
--------------------------------

(CONFIRMED ABSENT)
  - loader.exe source: not present. loader.exe behavior reconstructed
    solely from PE imports + strings (INFERRED).
  - neverlose-server.exe source: not present. Behavior reconstructed from
    PE imports + strings + live process + cabbitwin data dir (INFERRED).
  - neverlose.dll is present as source (FemboyLose-main), but the .rsrc
    section (~53 MB) content is not source-recovered.

1.3 Distribution archives (not source)
--------------------------------------
  - neverlose-last.rar (6,156,973 bytes) — contains copies of binaries
    (neverlose.dll, neverlose-server.exe, loader.exe, snowfall.lua).
  - 08.09.2026.rar (33,081,483 bytes) — binary distribution package.
  - FemboyLose-1.1.1.zip (7,980 bytes) — small, likely a loader/config
    package.
  These are archives, not source.

========================================
2. WHAT CAN BE RECONSTRUCTED
========================================

2.1 HIGH confidence reconstruction (source + live memory)
---------------------------------------------------------
  - neverlose.dll initialization lifecycle:
      DllMain -> MainThread -> map -> wait serverbrowser.dll ->
      fix_dump (fix_imports/spoof/fix_interfaces/fix_cvars/
      fix_signatures/NOP/flow-fix/sha256/hijack_requestor/
      last_resort_fixes/crypto_capture) -> set_veh ->
      setup_hooks -> spoof -> entry (suspended thread at 0x412A0A00)
  - Manual mapping at 0x412A0000 (WCX) + RO continuation at 0x4205A000.
  - Import table at 0x43236000+ (fix_imports.cpp).
  - Record freshness gate 0x413F9E00 (cmp ecx,2 at 0x413F9EC0).
  - Lag-comp gate 0x413F94D0 (al=1 default).
  - Record selection 0x4148F180.
  - Lag-comp orchestrator 0x41496DB0.
  - Aim consumer 0x4140C710 -> aim position 0x4140CB75 -> angle
    0x41573930/0x41573E80 -> apply 0x41408800.
  - Lua boundary: require("neverlose/…"), lagrecord library,
    FFI memory access; QueryLuaLibrary fetches /lua/<name> from server.

2.2 PARTIAL reconstruction (binaries + strings + live process)
---------------------------------------------------------------
  - loader.exe: injector/downloader (CreateRemoteThread + VirtualAllocEx +
    WriteProcessMemory + WININET download; port 30031 reference).
    Exact download URL UNKNOWN; exact injection sequence UNKNOWN.
  - neverlose-server.exe: local HTTP server on 127.0.0.1:30031; owns
    cabbitwin\ data; serves /lua/<name>; TLS certs. Exact routes beyond
    /lua/<name> UNKNOWN; auth handshake details UNKNOWN.
  - .rsrc section of neverlose.dll (~53 MB): content not recovered.

2.3 NOT reconstructable (no source, no observable behavior)
-----------------------------------------------------------
  - Remote download URL used by loader.exe.
  - Whether neverlose-server.exe is started by loader.exe or independently.
  - Full list of Lua scripts loaded at runtime init.
  - Behavior of obfuscated helpers past trampoline 0x39C21170.
  - Whether nl.bin (or a runtime copy) is loaded by the Lua VM.

========================================
3. READABLE ARCHITECTURAL PSEUDOCODE
========================================
The following pseudocode is a RECONSTRUCTION from source + live memory,
NOT recovered original C++ source. Function names that appear in source
are kept; addresses are the live mapped-image addresses.

----------------------------------------------------------------------
3.1 Loader (INFERRED from imports/strings)
----------------------------------------------------------------------
// loader.exe — NOT recovered source. Reconstructed from PE imports.

bool LoaderMain()
{
    // enumerate processes to find csgo.exe
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    while (Process32NextW(hSnap, &pe32)) {
        if (wcscmp(pe32.szExeFile, L"csgo.exe") == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    // download component over HTTP (WININET) — URL UNKNOWN
    hNet = InternetOpenA(...);
    hUrl = InternetOpenUrlA(hNet, <remote URL>, ...);
    InternetReadFile(hUrl, buf, size, &read);  // -> neverlose.dll bytes

    // create or open csgo.exe suspended
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
        or CreateProcessW(..., CREATE_SUSPENDED);

    // allocate remote memory, write DLL, start remote thread
    remoteBuf = VirtualAllocEx(hProc, NULL, size,
                              MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remoteBuf, dllBytes, size, NULL);
    CreateRemoteThread(hProc, NULL, 0, remoteBuf, NULL, 0, &tid);

    // the injected DLL then connects to 127.0.0.1:30031 ("1:30031" string)
    return 0;
}

----------------------------------------------------------------------
3.2 neverlose.dll initialization (CONFIRMED from FemboyLose source)
----------------------------------------------------------------------
// neverlose.dll — recovered from FemboyLose-main/neverlose/ source

NTSTATUS NTAPI MainThread(LPVOID lpThreadParameter)
{
    g_neverlose.map((HMODULE)lpThreadParameter);   // manual self-map at 0x412A0000

    while (!GetModuleHandleW(L"serverbrowser.dll"))
        Sleep(100);                                 // wait for CS:GO client

    g_neverlose.fix_dump();                         // imports, spoof, hooks, etc.
    g_neverlose.set_veh();                          // vectored exception handler
    g_neverlose.setup_hooks();                      // detour hooks
    g_neverlose.spoof();                            // anti-tamper spoofing

    g_neverlose.entry();                            // neverlose runtime entry
    return STATUS_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        apply_missing_entity_fix();
        NtCreateThreadEx(&hThread, ..., MainThread, hinstDLL, ...);
        NtClose(hThread);
    }
    return TRUE;
}

void neverlose::entry()
{
    // create suspended thread at 0x412A0A00 (inside mapped image)
    NtCreateThreadEx(&hThread, ..., (PUSER_THREAD_START_ROUTINE)0x412A0A00,
                     0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ...);
    NtResumeThread(hThread);
    NtWaitForSingleObject(hThread, FALSE, NULL);   // wait for entry to exit
    NtClose(hThread);
}

----------------------------------------------------------------------
3.3 fix_dump (CONFIRMED from fix_dump.cpp)
----------------------------------------------------------------------
void neverlose::fix_dump()
{
    fix_imports();            // resolve IAT at 0x43236000+
    spoof_peb();
    spoof_kusd();
    spoof_cpuid();
    fix_interfaces();
    fix_cvars();
    fix_signatures();

    for (auto& [address, count] : g_noped_addrs)
        memset(address, 0x90, count);              // NOP pads

    fix_mem_dispatcher();

    for (DWORD addr : g_stupid_ahh_shit_flow_fix)   // ~110 addresses
        *(PBYTE)addr = 0xEB;                        // force unconditional jump

    fix_sha256();
    hijack_requestor();                             // hooks GetSerial/MakeRequest
    last_resort_fixes();
    install_crypto_capture();
}

// last_resort_fixes writes absolute handles into the mapped image:
//
//   *(PHANDLE)0x42518C44 = GetStdHandle(STD_OUTPUT_HANDLE);
//   memset(0x41C12B3E, 0x90, 6);                    // websocketpp nop
//   *(PPVOID)0x41BF8341 = (PVOID)&auth_token;
//   *(PBYTE)0x41B63BB0 = 0xC3;
//   *(PBYTE)0x41DA128F = 0xEB;
//   *(PBYTE)0x4152A163 = 0x84;
//   PVOID addr = VirtualAlloc(NULL, 0x2000, ...);
//   *(PPVOID)0x424AFCC0 = addr;
//   *(PDWORD)0x4479EE00 = (DWORD)addr + 0x1000;

----------------------------------------------------------------------
3.4 Requestor / Lua boundary (CONFIRMED from Requestor.cpp)
----------------------------------------------------------------------
// neverlose.dll -> WinHTTP -> 127.0.0.1:30031 -> neverlose-server.exe

void QueryLuaLibrary(std::string& out, std::string_view libname)
{
    // GET /lua/<name>?cheat=csgo&token=<token>
    route = "/lua/" + libname + "?cheat=csgo&token=" + auth_token;
    WinHttpOpenRequest(...); WinHttpSendRequest(...); WinHttpReadData(...);
    // out = Lua script source
}
// Note: GHETTO_FIX build hooks GetSerial (0x41BC78E0) and MakeRequest
// (0x41BC98E0) but leaves QueryLuaLibrary unhooked (real request runs).

----------------------------------------------------------------------
3.5 Aim-consumer pipeline (RECONSTRUCTED from live disassembly)
----------------------------------------------------------------------
// native aim path inside neverlose.dll (mapped image 0x412A0000)

// entry: 0x41596AA9 (no E8 caller found; hook/indirect entry)
//        -> ... -> 0x4140C710

void aim_consumer_entry()           // 0x4140C710, SEH-wrapped
{
    entity_list = *(uint32_t*)0x424AFD68;
    count = *entity_list;                              // [ecx]
    if (count == 0 || count > 0x2FFFF) return;
    for (i = 0; i < count; i++) {
        entity = entity_list[i];
        ... aim computation ...
    }
}

void compute_aim_position()                            // 0x4140CB75
{
    call 0x41B6C700;                                   // origin apply
    *(double*)0x425023C8 = xmm0;                       // aim out X
    *(float*)0x425023D0 = xmm0;                        // aim out Y
    ...
    *(float*)0x425023EC = xmm0;                        // aim out Z/other
}

float vector_to_angle(vec3* dst, vec3* src)            // 0x41573930
{
    dy = dst->y - src->y;
    dx = dst->x - src->x;
    angle = atan2(dy, dx) at 0x4202F7D0;
    angle = angle * 0x4206CEE0 + 0x4206CDD8;           // rad->deg + offset
    return normalize(angle);
}

void normalize_angle(float* a)                         // 0x41573E80
{
    call 0x42026D1B x3;                                // clamp +/-2, +/-1
}

void apply_aim_result(void* dst, void* src)            // 0x41408800
{
    memcpy(dst, src, 0x71c);                           // aim result struct
    ret 4;
}

----------------------------------------------------------------------
3.6 Lua-side record library (CONFIRMED from lagrecord.lua)
----------------------------------------------------------------------
-- getters defined but NEVER called by any workspace script (grep verified)
function lagrecord.get_record(player, idx)   -- lines 611-630
function lagrecord.get_snapshot(player, idx) -- lines 633-714
function lagrecord.get_all(player)           -- lines 593-609
function lagrecord.set_update_callback(fn)   -- lines 783-793 (boolean filter)
function lagrecord.get_server_time()         -- lines 215-241
   -- client_tick + clock_offset + engine.dll FFI delta

-- records stored per player in self.data[index].records
-- fields: tick, shifting, elapsed, choked, origin, origin_old,
--         simulation_time, simulation_time_old, angles, eye_position, volume

----------------------------------------------------------------------
END OF PSEUDOCODE (reconstruction, not original source)
========================================