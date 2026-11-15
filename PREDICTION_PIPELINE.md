# PREDICTION PIPELINE
==============================
Scope: Reverse-engineering the Neverlose/GameSense CS:GO environment at `C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF` to understand and eventually improve enemy-position extrapolation.

This document is authoritative for Phase 3 of the investigation. It is **descriptive only** — no code changes are proposed.

Companion documents: `PREDICTION_FUNCTION_MAP.md`, `PREDICTION_DATA_FLOW.md`, `PREDICTION_API_GAPS.md`, `EXTRAPOLATION_ANALYSIS.md`, `DISCREPANCY_REPORT.md`.

---

## 1. How to Read This Document

### 1.1 Evidence Grading

| Tag | Meaning |
|-----|---------|
| **[OBSERVED]** | Read directly from the live process or from disassembly of the live process. Reproducible with the scripts named. |
| **[INFERRED]** | Follows from **[OBSERVED]** instructions but depends on an assumption about struct layout or calling convention. |
| **[UNKNOWN]** | Not determined. Do not treat as fact. |

No statement in this document is based on runtime behavioural testing. There has never been an in-game validation session for this project.

### 1.2 Address Base

All addresses are **runtime virtual addresses** inside the manually mapped module, not file offsets.

| Item | Value |
|------|-------|
| Allocation base | `0x412A0000` |
| Allocation size | `0x00DBA000` |
| Protection | `PAGE_EXECUTE_WRITECOPY` (WCX) |
| Anchor instruction | `F3 0F 5B CA 0F 5B C9 0F 2E CB` at `0x41400D8F` |
| Scan delta | `0x340AB6` |

`neverlose.dll` on disk (SHA256 `529C59BD687901D4E86898F78F50534CA4FC5611D693C296C9A3BD7BF8F61253`, 56,370,688 bytes, x86, `.text` only `0x3807A`) is a **loader stub** — 0 pattern matches. Real engine is manually mapped at `0x412A0000`, size `0x00DBA000`, `PAGE_EXECUTE_WRITECOPY` (WCX); continuation `0x4205A000` (`0x001DF000`, R); small WCX thunk pages + NOACCESS guards.

### 1.3 Reproducing the Addresses

All scripts are read-only. They open the target with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` and never write.

| Script | Purpose |
|--------|---------|
| `_audit/real_module.py` | Locates the mapped allocation and confirms the anchor |
| `_audit/map_record_func2.py` | Chunked disassembly of the record-selection function |
| `_audit/wfunc.py` | Linear walk with terminator awareness |
| `_audit/find_callers.py` | Finds `E8 rel32` callers and 4-byte-aligned address references |
| `_audit/patch_offsets.py` | Byte-exact verification of every documented patch site |
| `_audit/snapshot.py` | Consolidated runtime snapshot of globals and patch bytes |
| `_audit/disasm_consts.py` | Locates float constants (`1/64`, `1/128`, `0.2`) and their xrefs |
| `_audit/find_helper.py` | Identifies the helper reached from float-constant sites |

Target process: `csgo.exe`, PID **8780**, 32-bit, ~1059 MB working set.

---

## 2. Verified Function Table

| Address | Role | Grade | Notes |
|---------|------|-------|-------|
| `0x413F9E00` | Record freshness gate | **[OBSERVED]** | Contains the `cmp ecx, 2` immediate patched by `extrapolation_limit`. Writes the tick correction to `record+0xAC`. |
| `0x413F94D0` | Lag-comp acceptability gate | **[OBSERVED]** | Horizontal-distance test against `[0x4206CDC0]`. Returns `al=1` accept / `al=0` reject. |
| `0x4148F180` | Record selection (nearest-record search) | **[OBSERVED]** | Single `E8` caller at `0x4149789F`. Contains the distance metric and the record-ring walk. |
| `0x41496DB0` | Lag-comp orchestrator | **[OBSERVED]** | SEH-wrapped. Assembles the output origin and applies it. |
| `0x41400BF0` | Geometry / visibility helper | **[OBSERVED]** | Two out-parameters, called with `0.2f` at one site. Not a prediction routine. |
| `0x413F6B40` | Sibling of `0x41400BF0` | **[OBSERVED]** | Same shape, three call sites. |
| `0x41B6C700` | Origin apply | **[INFERRED]** | Called with a pointer to the assembled origin. |
| `0x41B70930` | Small field getter | **[OBSERVED]** | `mov eax,[ecx+0x9960]; ret` — three bytes of code. |
| `0x39C21170` | Obfuscation trampoline | **[OBSERVED]** | Jump target from the helpers. Static tracing stops here. |

---

## 3. Function Detail

### 3.1 `0x413F9E00` — Record Freshness Gate

Prologue at `0x413F9E00`, `ret 8` at `0x413F9F20`. `this` in `ecx`, argument at `[ebp+0xC]`. **[OBSERVED]**

The decisive block:

```
0x413F9EA8  mov  eax, [0x4223F428]      ; context
0x413F9EAD  mov  eax, [eax+0x16C]       ; server tick
0x413F9EB3  sub  eax, [edx+0x84]        ; minus record.tick   (edx = record)
0x413F9EB9  mov  ecx, eax
0x413F9EBB  neg  ecx
0x413F9EBD  cmovs ecx, eax              ; ecx = |server_tick - record.tick|
0x413F9EC0  cmp  ecx, 2                 ; <== extrapolation_limit patch site
0x413F9EC3  mov  ecx, 0
0x413F9EC8  ja   0x413F9F0B             ; too stale -> return 0 (no record)
0x413F9ECA  mov  eax, [0x424F4B18]      ; tick correction
0x413F9ECF  mov  [edx+0xac], eax        ; record+0xAC = correction
0x413F9ED5  mov  ecx, edx               ; ecx = record
0x413F9ED7  jmp  0x413F9F0B             ; return record
```

Facts established:

- `record+0x84` is the record's tick. **[OBSERVED]**
- `record+0xAC` is written with the value of `[0x424F4B18]` on the accept path. **[OBSERVED]**
- The comparison is against the **absolute tick delta**, not a distance. **[OBSERVED]**
- Stock immediate is `2`; `extrapolation_limit` rewrites it. **[OBSERVED]**
- Returning `ecx = 0` means "no usable record"; returning `ecx = record` means "usable". **[INFERRED]** from the `mov ecx, 0` / `mov ecx, edx` pairing.

Interpretation: this is a **staleness tolerance in ticks**. At 64 tick, a stock value of 2 admits records up to about 31.2 ms old. It does not extend a prediction horizon. **[INFERRED]** from the arithmetic; not behaviourally tested.

The function also touches a ring at `[ebx+0x10]`, `[ebx+8]`, `[ebx+0xC]`, `[ebx+4]` and tests `[record+0xB1] & 8`, consistent with the ring layout in `PREDICTION_DATA_FLOW.md`.

### 3.2 `0x413F94D0` — Lag-Comp Acceptability Gate

```
0x413F94D5  mov  edx, [0x4223F428]
0x413F94DB  mov  esi, [ecx+0x84]        ; record.tick
0x413F94E1  mov  al, 1                  ; default: accept
0x413F94E3  cmp  [edx+0x16C], esi       ; server_tick == record.tick ?
0x413F94E9  je   0x413F9552             ; equal -> accept
0x413F94EB  movsd xmm0, [ecx+0x18]      ; record origin x,y
0x413F94F0  mulps xmm0, xmm0
0x413F94F6  shufps xmm1, xmm0, 0x55
0x413F94FA  addss xmm1, xmm0
0x413F94FE  xorps xmm0, xmm0
0x413F9501  sqrtss xmm0, xmm1           ; horizontal distance
0x413F9505  ucomiss xmm0, [0x4206CDC0]  ; compare with max lag-comp distance
0x413F950C  jbe  0x413F9552             ; within limit -> accept
0x413F950E  mov  eax, [0x4223CA04]
0x413F9513  mulss xmm0, [eax+0x20]      ; scale
0x413F9518  movss xmm1, [0x4205AC74]    ; 64.0
0x413F9520  divss xmm1, xmm0            ; 64.0 / (distance * scale)
```

Facts established:

- `record+0x18` holds the origin **x and y** as a packed pair. **[OBSERVED]**
- The distance computed here is **horizontal only** (x,y). **[OBSERVED]**
- `[0x4206CDC0]` is a float limit. Runtime value observed: `100.0`. **[OBSERVED]**
- `[0x4205AC74]` is a float. Runtime value observed: `64.0`. **[OBSERVED]**
- The division `64.0 / (distance * scale)` is a ratio, not a tick count, as far as can be determined. **[INFERRED]**
- The function returns `al`, and the default is `1`. **[OBSERVED]**

Consequence for the existing patch: overwriting the `call` at `0x4148F441` with `mov al, 0` forces `al = 0`, which takes the record-rejection branch. The two UI labels `break_lagcomp_distance_a` and `_b` are therefore **inverted** relative to what the patch does. **[OBSERVED]** mechanism; see `EXTRAPOLATION_ANALYSIS.md` §1.4 and §6.8.

### 3.3 `0x4148F180` — Record Selection

Prologue at `0x4148F180`. Exactly one direct caller: `0x4149789F`. No 4-byte-aligned address references, so it is not reached through a vtable. **[OBSERVED]**

Arguments at the call site:

```
0x4148F977  lea  edx, [esi+0x10]       ; arg4 = &out_origin
0x4148F97A  push edx                    ; arg4 = &out_origin
0x4148F97B  push eax                    ; arg3 = record index / array element
0x4148F97C  push ecx                    ; arg2 = tick-derived value
0x4148F97D  push [esi]                  ; arg1 = entity pointer
0x4148F97F  call 0x4148F180
0x4148F984  add  esp, 0x10
0x4148F987  mov  [esi+4], eax           ; store returned record index
```

The distance metric, at `0x4148F46C`–`0x4148F4B0`:

```
0x4148F46C  mov ecx, [esp+0x30]        ; target origin pointer
0x4148F470  movss xmm0, [ecx]          ; target.x
0x4148F474  subss xmm0, [eax]          ; minus record.x   (record+0x00)
0x4148F478  movss xmm1, [eax+0x38]     ; record velocity component
0x4148F47D  mulss xmm1, [0x4205A518]    ; times 0.5
0x4148F485  addss xmm1, [eax+8]        ; plus record.z     (record+0x08)
0x4148F48A  mulss xmm0, xmm0           ; dx squared
0x4148F48E  movsd xmm2, [ecx+4]        ; target.y, target.z
0x4148F493  movss xmm3, [eax+4]        ; record.y          (record+0x04)
0x4148F498  unpcklps xmm3, xmm1        ; xmm3 = {record.y, predicted_z}
0x4148F49B  subps xmm2, xmm3           ; {dy, dz}
0x4148F49E  mulps xmm2, xmm2           ; {dy², dz²}
0x4148F4A1  addss xmm0, xmm2           ; dx² + dy²
0x4148F4A5  shufps xmm2, xmm2, 0x55
0x4148F4A9  addss xmm2, xmm0           ; + dz²
0x4148F4B0  sqrtss xmm0, xmm2          ; euclidean distance
```

Facts established:

- `record+0x00` / `+0x04` / `+0x08` are the origin **x / y / z**. **[OBSERVED]** from the `movsd` + `movss` pairing.
- `record+0x38` is a velocity-like component, scaled by the constant at `[0x4205A518]`. Runtime value of that constant: `0.5`. **[OBSERVED]**
- The z term is `record.z + record.velocity_z * 0.5`. **[INFERRED]** from the instruction sequence; the exact meaning of `+0x38` is not independently confirmed.
- This is a **half-tick forward projection used only for scoring**. It is not a general 3D prediction and does not produce the final origin. **[INFERRED]**
- The ring walk skips records whose flags have bit 3 set (`test byte [ecx+0xB1], 8`). **[OBSERVED]**
- The loop terminates when the cursor equals `[ring+0x10] + [ring+0x0C]`. **[OBSERVED]**
- The SIMD tail at `0x4148F640`–`0x4148F778` is a vectorised min/max reduction over `[0x42504EDC]`; it is not position arithmetic. **[OBSERVED]**

### 3.4 `0x41496DB0` — Lag-Comp Orchestrator

SEH-wrapped: `push ebp; mov ebp,esp; and esp,0xFFFFFFF0; sub esp,0x160`, exception registration at `[esi+0x150]` with handler `0x414B49C0`. **[OBSERVED]**

Sequence relevant to origin reconstruction:

```
0x4148F7BC  movss xmm0, [eax+edi+8]   ; A[index].z      (A = [0x424B03D0])
0x4148F7CA  mov   ecx, [esi+0xAC]     ; B pointer
0x4148F7D0  addss xmm0, [ecx+edi+8]   ; + B[index].z
0x4148F7D6  movsd xmm1, [ecx+edi]     ; B[index].x,y
0x4148F7DB  movsd xmm2, [eax+edi]     ; A[index].x,y
0x4148F7E0  addps xmm2, xmm1          ; A[index] + B[index]
0x4148F7E3  movlps [esi+0x10], xmm2   ; out.x, out.y
0x4148F7E7  movss [esi+0x18], xmm0    ; out.z
0x4148F7F8  call  0x41B70930          ; getter
0x4148F7FD  lea   edx, [esi+0x10]
0x4148F802  mov   [esi+0xAC], edx     ; out pointer
0x4148F80A  call  0x41B6C700          ; apply origin (ecx = entity, arg = &out)
```

Facts established:

- The output origin is assembled as the **sum of two vector arrays**, indexed by the selected record index: `A = [0x424B03D0]`, `B = [esi+0xAC]`. **[OBSERVED]**
- The result is written to `[esi+0x10]` (x,y) and `[esi+0x18]` (z). **[OBSERVED]**
- `[esi+0xAC]` is then repointed at `[esi+0x10]`, i.e. it is an **out-pointer to the assembled origin**, not an input. **[OBSERVED]**
- `0x41B6C700` is called with that pointer. **[OBSERVED]** call; **[INFERRED]** role as an origin setter.

Two distinct paths exist in this function, separated by guards on `[0x424B03C0]` / `[0x424B03D4]` / `[0x424B03B4]`. The ordering of the two paths relative to each other is **[UNKNOWN]**; do not assume the origin is applied before or after record selection without a runtime trace.

### 3.5 `0x41400BF0` and `0x413F6B40` — Geometry Helpers

`0x41400BF0` is called from `0x4148F3EC` and `0x4148F5B4`. It takes:

- `[esp+0]` a float (the record's `[record+0x94]` value, or `0.2f` at the `0x4148F5AC` site)
- `[esp+4]` a float
- `[esp+8]` a pointer (`record+0xA4` at the first site)
- `[esp+0xC]` and `[esp+0x10]` two out-pointers into caller stack slots

Facts established:

- It writes a byte `1` to one out-parameter on the early-out path (`mov byte [edi], 1`). **[OBSERVED]**
- It branches on `[0x42501CA4]` and `[0x42241C4C]` before doing any work. **[OBSERVED]**
- It is reached from the record-selection loop and from the "is this record still valid" path. **[OBSERVED]**

Ruled out: the `0.2f` argument at `0x4148F5AC` is **not** a prediction horizon or a prediction distance. It is one argument to a geometry/visibility-style helper that fills two out-parameters. **[OBSERVED]** at the call site; **[INFERRED]** for the semantic role.

Both helpers end in a `jmp` to the trampoline at `0x39C21170`, and contain junk bytes and opaque predicates. Static tracing **cannot** continue past them. **[OBSERVED]**

### 3.6 `0x41B6C700` and `0x41B70930` — Apply and Get

`0x41B70930` is `mov eax,[ecx+0x9960]; ret`. **[OBSERVED]**

`0x41B6C700` is SEH-wrapped, takes a pointer at `[ebp+8]`, and tests `[ptr+0x109]` and `[ptr+0xA4]`. It reads `[0x424B0408]` and `[0x42518540]`. Its precise semantics are **[INFERRED]**: it consumes a pointer to an assembled origin and writes it into entity state. Not independently confirmed.

---

## 4. Ruled Out

| Candidate | Why Ruled Out | Grade |
|-----------|---------------|-------|
| `0.2f` at `0x4148F5B0` | Argument to a geometry helper with two out-params, not a horizon | **[OBSERVED]** |
| `0x424F4B18` (86 xrefs) | Read-only in the mapped image; a tick-correction scalar | **[OBSERVED]** |
| `0x39C21170` | Obfuscation trampoline; no recoverable body | **[OBSERVED]** |
| `neverlose.dll` on disk | Loader stub, 0 pattern matches | **[OBSERVED]** |
| `Prediction.lua` | Hitchance override; no prediction code | **[OBSERVED]** |

---

## 5. What Is Still Unknown

1. Whether any code path performs a **general N-tick forward prediction** of an enemy position. None has been found. The only projection observed is the half-tick z term in `0x4148F180`. **[UNKNOWN]**
2. The exact semantics of `record+0x38` (velocity component) and of the `0.5` scale at `[0x4205A518]`. **[UNKNOWN]**
3. The meaning of the two vector arrays `[0x424B03D0]` and `[esi+0xAC]` beyond "they are summed". **[UNKNOWN]**
4. The write sites for `[0x424F4B18]`. **[UNKNOWN]**
5. The order of the two paths inside `0x41496DB0`. **[UNKNOWN]**
6. Anything reached through the `0x39C21170` trampoline. **[UNKNOWN]**

---

## 6. Relationship to Earlier Findings

This document does not retract anything. It adds resolution below the level established in `EXTRAPOLATION_ANALYSIS.md`:

- §1.2 (staleness tolerance) is now confirmed at the instruction level: `0x413F9EC0 cmp ecx, 2`.
- §1.4 (inverted labels) is now confirmed at the instruction level: `0x413F94D0` defaults `al = 1`, so forcing `al = 0` rejects.
- §6.7 (`0.2` hardcoded) is now **resolved**: the `0.2f` is a helper argument, not a prediction constant. The open question is closed.
- §2.1 (record layout) is refined: `+0x00/+0x04/+0x08` origin, `+0x84` tick, `+0xAC` tick correction / out-pointer, `+0x38` velocity-like.

The absence of a located prediction routine is consistent with, and strengthens, the earlier conclusion that **no identified pattern targets the actual prediction routine**.

---  
*End of PREDICTION_PIPELINE.md*