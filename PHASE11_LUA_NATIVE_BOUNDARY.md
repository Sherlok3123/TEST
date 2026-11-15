# PHASE11_LUA_NATIVE_BOUNDARY.md
========================================
Phase 5 Investigation — Lua ↔ engine prediction correlation audit.
Read-only investigation. No implementation, no file changes.

Evidence tiers:

| Tier | Meaning |
|------|---------|
| **T1** | Directly observed in Lua source (file + line) or binary disassembly (address + instruction). |
| **T2** | Observed in source, but the Neverlose API semantics are incompletely documented. |
| **T3** | Inferred from FFI / binary structure / opcode scan. |
| **T4** | Hypothesis from naming or indirect evidence. |
| **T5** | Unknown. |

No variable name, UI label, or comment is treated as proof of semantics. There has
never been an in-game runtime validation; all findings are static source or read-only
binary analysis.

Companion documents: `PREDICTION_FUNCTION_MAP.md`, `PREDICTION_PIPELINE.md`,
`PREDICTION_DATA_FLOW.md`, `PREDICTION_API_GAPS.md`, `EXTRAPOLATION_ANALYSIS.md`,
`DISCREPANCY_REPORT.md`.

---

## 1. Lua Sources Inspected

All files under `C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\` excluding the
`Dumper`, `Dumper.v2`, `New folder`, `_audit`, `.git`, `__pycache__`, and
`FemboyLose-main` C++/server trees. Size cutoff of 200 bytes applied to skip
trivial files.

| File | Role | Size |
|------|------|------|
| `lagcomp_dumper.lua` | Client.dll pattern scanner | 5,498 B |
| `records_dumper.lua` | Client.dll pattern scanner | 4,260 B |
| `Prediction.lua` | Hitchance override (mislabeled) | 1,221 B |
| `TestUI.lua` | UI smoke test | 3,063 B |
| `animbreaker_new.txt` | Anti-aim helper | 2,242 B |
| `DoubleTapSpeed.lua` | Speed tweak | 4,562 B |
| `ConditionalMultipoint.lua` | Multipoint helper | 3,482 B |
| `betterNL.txt` | Lag-comp cvar toggle | 242,386 B |
| `rebelion.txt` | Prediction render box | 300,969 B |
| `Aesthetic BETA.txt` | extrapolate_pos + aim menu | 86,977 B |
| `REFRACTED.lua` | Shot telemetry, motion sampling | 724,276 B |
| `ERROR.txt` | Duplicate of BLUESENSE_HOLY_GRAIL.lua | 721,013 B |
| `DONT EDIT.txt` | Duplicate of BLUESENSE_HOLY_GRAIL.lua | 722,307 B |
| `BLUESENSE_HOLY_GRAIL.lua` | Local movement + AI threat | 722,307 B |
| `BlueSense.lua` | Local movement + AI threat | 660,887 B |
| `Elysian.lua` | Aim menu + origin reads | 640,992 B |
| `Outlaw.lua` | FFI-heavy | 660,119 B |
| `NyaHOOK.lua` | Hooks | 275,719 B |
| `mori.txt` | Origin reads | 373,938 B |
| `nyanza.lua` | Velocity reads | 352,022 B |
| `ethernance.lua` | Aim menu | 205,359 B |
| `snowfall.lua` = `08.09.2026/test_20.lua` | FFI-heavy (identical pair) | 7,242,763 B |
| `github_bebrasense.lua` | Anti-aim, lagrecord filter | 19,363 B |
| `github_luasense.lua` | Reference | 51,239 B |
| `github_momentumnl.lua` | Reference | 51,162 B |
| `github_testarossa.lua` | Reference | 51,331 B |
| `github_wraith.lua` | Reference | 9,608 B |
| `bluesense_modular_*.lua` | Modular libs (ai_peek, core, defensive, extras, indicators, main, configs, teleport_exploit) | various |
| `records_dumper.lua` | Pattern scanner | 4,260 B |
| `REFRACTED.lua` | Motion telemetry | 724,276 B |

Duplicate / dead files noted: `ERROR.txt`, `DONT EDIT.txt`, and
`BLUESENSE_HOLY_GRAIL.lua`/`BlueSense.lua` share the same size and identical
API-frequency profile, indicating duplicate or near-identical copies.
`snowfall.lua` and `08.09.2026/test_20.lua` are byte-identical (both
7,242,763 B).

---

## 2. Lua API Surface by Confidence Tier

### T1 — Directly Verified in Source

| Item | Evidence |
|------|----------|
| `entity.get_local_player()` | `lagrecord.lua:209`, `get_lc.lua:9`, `rebelion.txt:4883` |
| `entity.get_players(...)` | `lagrecord.lua:771`, `rebelion.txt:4883` |
| `entity.get_player()` | `lagrecord.lua:541` |
| `player:get_index()` | `lagrecord.lua:197`, `rebelion.txt:4885` |
| `player:m_vecOrigin`, `player:m_vecVelocity`, `player:m_vecMins`, `player:m_vecMaxs` | `rebelion.txt:4890-4892` |
| `player:get_origin()` | `lagrecord.lua:355`, `rebelion.txt` |
| `player:get_simulation_time()` → `{current, old}` | `rebelion.txt:4895-4896`, `REFRACTED.lua:1078-1080` |
| `player:get_angles()`, `player:get_eye_position()` | `lagrecord.lua:451,453` |
| `player:is_alive()`, `player:is_dormant()`, `player:is_enemy()`, `player:get_network_state()` | `rebelion.txt:4886` |
| `player:get_name()` | `REFRACTED.lua:1107` |
| `player:get_player_info()` | `REFRACTED.lua:1133` |
| `globals.tickinterval`, `globals.client_tick`, `globals.clock_offset`, `globals.estimated_tickbase`, `globals.is_in_game` | `lagrecord.lua:203,217,218,249` |
| `cvar.sv_maxunlag` | `lagrecord.lua:1` |
| `events.net_update_end`, `events.createmove`, `events.render`, `events.entity_update`, `events.shutdown`, `events.level_init` | `lagrecord.lua:727,733,739,743,843` |
| `renderer.lerp(...)`, `renderer.box_new(...)`, `renderer.texture(...)` | `lagrecord.lua` (none); `rebelion.txt:4907`; `REFRACTED.lua` (telemetry prints) |
| `lagrecord.set_update_callback(fn)`, `unset_update_callback`, `get_player_data`, `get_all`, `get_record`, `get_snapshot`, `get_server_time` | `lagrecord.lua:781-824` |
| `ffi.cast`, `ffi.new`, `ffi.C.VirtualQuery` | `lagrecord.lua:3,9,171` |
| `utils.opcode_scan("engine.dll", ...)` | `lagrecord.lua:5` |
| `utils.net_channel().latency[0]` | `lagrecord.lua:273` |
| `utils.opcode_scan("engine.dll", "03 05 ? ? ? ? 83 CF 10", 2)` | `lagrecord.lua:3` |

### T2 — Observed in Source, API Semantics Incomplete

| Item | Evidence | Gap |
|------|----------|-----|
| `player:get_simulation_time()` shape `{current, old}` | `lagrecord.lua:261`, `rebelion.txt:4895` | Whether values are ticks or seconds not documented |
| `target:get_network_state() == 5` (dormant sentinel) | `rebelion.txt:4886` | sentinel meaning undocumented |
| `globals.tickinterval * delta` as time step | `rebelion.txt:4872` | `delta` units not documented |
| `lagrecord.get_record(player, idx)` | `lagrecord.lua:611-630` | return record shape verified only within lib |
| `lagrecord.get_snapshot(player, idx)` | `lagrecord.lua:633-714` | caller-side consumption not verified |

### T3 — Inferred from FFI / Binary

| Item | Evidence | Confidence |
|------|----------|------------|
| `reloaded_0_1[0] - reloaded_0_2[0]` engine.dll time delta | `lagrecord.lua:3,5,223` | engine.dll globals read by opcode scan |
| `scan_nl` over neverlose mapped image | `REFRACTED.lua:214` | anchors to neverlose.dll allocation |
| Extrapolation limit pattern `{0xF7,0xD9,0x0F,0x48,0xC8,0x83,0xF9,nil,0xB9,...}` → `addr+7` = immediate `02` | `REFRACTED.lua:213-216` | matches Phase 3 binary `0x413F9EC2` |

### T4 — Hypothesis from Naming / Indirect Evidence

| Item | Evidence | Confidence |
|------|----------|------------|
| `extrapolate_pos` computes forward position | `Aesthetic BETA.txt:1617` | high within source |
| `rebelion v751` computes forward position | `rebelion.txt:4871-4873` | high within source |
| `m_vecAbsVelocity` as last-resort velocity fallback | `REFRACTED.lua:1010-1014` | diagnostic, not aim input |
| `anim_state.velocity` as velocity fallback | `REFRACTED.lua:1019-1040` | undocumented binding shape |

### T5 — Unknown

| Item |
|------|
| Whether any engine-side record pointer is ever passed to Lua |
| Whether `get_simulation_time().current` is seconds or ticks in each binding |
| What `renderer.box_new` does with the `tickinterval * 2` duration arg |
| Whether `anim_state.velocity` and `m_vecVelocity` are sampled at the same sim stage |

---

## 2. Enemy-Position Data Flow — Source by Source

### 2.1 `lagrecord.lua` — Lua-Side Lag Record System (T1/T2)

This is a **complete Lua reimplementation** of lag records. It does **not** read
the engine's record ring at `0x4148F180`. It builds its own records.

Flow (all **[T1]**):

1. `events.net_update_end` → `lagrecord:on_net_update(player, server_time, dead_time)` (line 739 → 347), iterated over `entity.get_players(false, true, cb)` (line 771).
2. Per player: `player:get_index()` (353), `player:get_origin()` (355), `player:is_alive()` (357), `player:is_dormant()` (393), `fire_callback(player)` (387) = `set_update_callback` result.
3. New record appended to `self.data[index].records` (lines 433-463) with fields:
   `tick`, `shifting`, `elapsed`, `choked`, `origin`, `origin_old`, `simulation_time`, `simulation_time_old`, `angles`, `eye_position`, `volume` (mins/maxs).
4. `verify_records` (line 283): purges records when `arg_12_2 >= record.simulation_time` or when `origin:distsqr(record.origin) > 4096` (teleport detection, 64 units).
5. Public getters — **defined but never called by any script** (verified by grep):
   - `get_record(player, idx)` → `records[idx or 1]` (lines 611-630)
   - `get_snapshot(player, idx)` → rich snapshot table (lines 633-714)
   - `get_all(player)` → `records` table (lines 593-609)
   - `set_update_callback` / `unset_update_callback` (lines 783-793)
   - `get_server_time` → `globals.client_tick + globals.clock_offset` + engine.dll delta (lines 215-241)

Evidence grade: **[T1]** for library source; **[T5]** for whether any consumer uses `get_record`/`get_snapshot` (they don't).

### 2.2 `github_bebrasense.lua` — lagrecord Consumer (T1)

- Line 31: `lagrecord = require("neverlose/lagrecord")`
- Line 32: security check `lagrecord = lagrecord^lagrecord.SIGNED`
- Lines 34-38: `lagrecord.set_update_callback(function(player) if player == entity.get_local_player() then return true end end)` — **boolean filter** (returns true only for local player).
- Does **not** call `get_record`, `get_snapshot`, or `get_all`.

Grade: **[T1]**. Confirms `set_update_callback` is a filter, used to allow/block per-player record updates.

### 2.3 `Aesthetic BETA.txt` — Hardcoded Forward Extrapolation (T1/T4)

- `extrapolate_pos(x,y,z,ticks,player)` at lines 1617-1624:
  ```lua
  x = x + player.m_vecVelocity.x * (1 / 64)   -- repeated `ticks` times
  y = y + player.m_vecVelocity.y * (1 / 64)
  z = z + player.m_vecVelocity.z * (1 / 64)
  ```
- Hardcoded step `1/64` (fixed 64-tick assumption; does **not** read `globals.tickinterval`).
- `get_velocity(player)` → `m_vecVelocity:length()` at lines 1610-1615.
- Call sites (lines 1726-1727):
  - target: `extrapolate_pos(target_pos.x,y,z, 6*(100-sens/2)/100, target)`
  - local player: `extrapolate_pos(lpos.x,y,z, 14*(100-sens/2)/100, lp)`
- Purpose at call sites: **[T4]** — surrounding context is an aim/anti-aim menu; exact consumer not fully isolated.

Grade: **[T1]** for implementation; **[T4]** for consumer/integration.

### 2.4 `rebelion.txt` — Prediction Render Box (T1)

- Line 4871-4873: `v751 = function(v1457, v1458, v1459) return v1457 + v1458 * (globals.tickinterval * v1459) end` — forward extrapolation: `origin + velocity * tickinterval * delta`.
- Lines 4895-4896: `delta = simulation_time.current - simulation_time.old`.
- Line 4898: teleport gate `distsqr(current_origin, previous_origin) > 4096` → `is_lagcomp`.
- Line 4900: `predicted_origin = v751(l_m_vecOrigin_3, l_m_vecVelocity_2, v1474)`.
- Line 4905-4907: if `is_lagcomp`, `v17.box_new(predicted_origin, mins, maxs, ..., globals.tickinterval * 2)` — **rendering only**.
- Consumer: **render box**, not aim ([T1]).

Grade: **[T1]** for implementation and consumer (render only).

### 2.5 `REFRACTED.lua` — Telemetry + Explicit Anti-Engine-Extrapolation Statement (T1)

- `read_target_motion(target)` (lines 967-1098): velocity priority `m_vecVelocity` → `anim_state.velocity` → `m_vecAbsVelocity`; simulation time via `get_simulation_time()` → `{current, old}`; `simulation_delta_ticks = (current-old)/tickinterval`.
- `MAX_MOTION_SAMPLE_GAP_TICKS = 4` (line 1146) — acceleration window ≤ 4 ticks.
- `sample_entity_after_net_update(target, tick, update_sequence)` (lines 1168+) — samples each entity once per `net_update_end`.
- `on_aim_fire(event)` (lines 1887+): **telemetry-only**. Logs `event.aim`, `event.angle` (supplied by an external aim-fire event), `target_origin`/`target_velocity` from `read_target_motion`. Shot mode: `BT=0 → PREDICT`, `BT>0 → BACKTRACK` (lines 1904-1905).
- Line 2238 (T1 source statement):
  > "motion/acceleration values are derived from consecutive net_update_end entity samples, **not** the game's internal extrapolation vector"
- `extrapolation_limit` pattern definition (lines 212-216): `{0xF7,0xD9,0x0F,0x48,0xC8,0x83,0xF9,nil,0xB9,...}` → `addr+7` = immediate `02`. **Exactly matches** Phase 3 binary `0x413F9EC2` (the `cmp ecx, 2` patched by `extrapolation_limit`). This is a **[T1]** correlation between Lua source and binary.

Grade: **[T1]**. REFRACTED is diagnostic telemetry; it does not compute aim positions.

### 2.6 `get_lc.lua` — Lag-Comp State Heuristic (T1)

- Compares local-player origin now vs. `1/tickinterval` ticks ago (lines 13-17, 23-47).
- Returns `0` / `1` / `-1` based on velocity > 255 and dist² < / > 4096 (lines 33-45).
- Heuristic "is lag comp active"; **no position output**.

### 2.7 Outlaw.lua / snowfall.lua / ethernance.lua / Elysian.lua / BlueSense.lua / NyaHOOK.lua / mori.txt / nyanza.lua

- High `ffi_C` / `opcode_scan` counts (Outlaw 18/11, snowfall 47/9) but grep shows **no** `get_record`/`get_snapshot`/`get_all` calls and no forward-prediction function definitions.
- They read origins/velocities for menu/ESP/telemetry; no verified forward-prediction-to-aim flow.

---

## 3. Reconstructed Position Pipeline

```
Enemy entity
   │
   ├─── Lua netprop read: get_origin() / m_vecOrigin           [T1]
   ├─── Lua netprop read: m_vecVelocity                        [T1]
   ├─── Lua sim time: get_simulation_time() {current, old}     [T1/T2]
   │
   ▼
[Optional Lua-side record store — lagrecord.lua]
   - on_net_update per player, stores records in Lua table   [T1]
   - get_record / get_snapshot / get_all defined, UNUSED     [T1]
   - teleport purge distsqr > 4096                            [T1]
   │
   ▼
[Forward prediction — Lua-side only]
   - extrapolate_pos: origin + velocity*(1/64)*ticks          [T1]  Aesthetic BETA.txt:1617
   - rebelion v751: origin + velocity*tickinterval*delta      [T1]  rebelion.txt:4871
   - REFRACTED read_target_motion: diagnostics only           [T1]
   │
   ▼
[Consumers]
   - rebelion: render box at predicted_origin (lagcomp-gated) [T1]
   - REFRACTED: log aim event (external aim point)            [T1]
   - github_bebrasense: set_update_callback filter only       [T1]
```

**Critical separation:** historical-position selection (lagrecord.lua Lua table) is **distinct** from forward prediction (extrapolate_pos / v751). The two are not combined in any inspected source.

No Lua script calls the engine's record-selection function `0x4148F180`. Lua's record store is independent of the engine's lag-comp records.

---

## 4. Correlation with Phase 3

| Phase 3 claim | Phase 4 corroboration | Source |
|---------------|----------------------|--------|
| `extrapolation_limit` patch = `cmp ecx, 2` at `0x413F9EC2` | Lua pattern `addr+7` where pattern starts `F7 D9 0F 48 C8 83 F9` → immediate `02` | `REFRACTED.lua:213-216` |
| `extrapolation_adjust` = 7-byte NOP at `0x413F9EC0` | Lua pattern `{0F 9C C0 34 01 0F B6 C0 29 C6}` + `init_patch(...,7)` | `REFRACTED.lua:235-240,370` |
| `break_lagcomp_distance_a/b` patch = `call` → `mov al,0` | Lua `init_patch("break_lagcomp_distance_a", 5)` / `_b, 5` | `REFRACTED.lua:372-373` |
| Engine record selection (`0x4148F180`) not exposed to Lua | No script references `0x4148F180` or engine record ring; lagrecord.lua is Lua-only | Phase 4 grep |
| `set_update_callback` is boolean filter, not getter | `github_bebrasense.lua:34-38` uses it as filter; `get_record`/`get_snapshot` never called | Phase 4 grep |
| Motion/acceleration from net_update_end samples, not engine extrapolation | REFRACTED.lua:2238 (explicit source statement) | `REFRACTED.lua:2238` |

Resolved from Phase 3 open questions:
- §6.7 `0.2` hardcoded: resolved — `0.2f` is a geometry-helper argument, not a prediction horizon (Phase 3 §9.2). Confirmed by Lua `extrapolation_limit` pattern being about staleness, not prediction.

Still unresolved (carried forward):
- Trampoline calls `0x41400BF0` / `0x413F6B40` behavior.
- Relationship `record+0x00` vs `record+0x18`.
- Meaning of `0x424F4B18` (no write sites found).
- Any in-game runtime behavior.

---

## 4. Final-Position Architecture — Existence Check

| Question | Answer | Evidence |
|----------|--------|----------|
| Is there one authoritative final position? | **No.** Multiple independent computations (extrapolate_pos, v751, engine record selection) with no merger. | Phase 4 source survey |
| Are multiple prediction methods evaluated? | **No** — each script uses its own single method; none compared or blended. | Aesthetic BETA.txt:1726-1727; rebelion.txt:4900 |
| Is engine info used as input/fallback/independent? | **None** — engine record selection not read by Lua. | Phase 4 grep |
| Are custom calcs added to or substituted for engine positions? | **Substituted** — Lua prediction replaces, never adds to, engine origin. | rebelion.txt:4900 (render only) |
| Are results blended, selected, or overwritten? | **None** — no blend/selection logic found. | Phase 4 source survey |
| Can different consumers receive different positions? | **Not observable** — consumers are render-box (rebelion) and telemetry-log (REFRACTED), not aim. | rebelion.txt:4907; REFRACTED.lua:1887 |
| Is there a consistent tick/time basis? | **No** — extrapolate_pos hardcodes `1/64`; rebelion uses `tickinterval*delta`; lagrecord uses `globals.client_tick`; REFRACTED uses `net_update_end` samples. | lines cited above |

**Conclusion (T1):** The intended "combine engine-derived and custom calculation into one final extrapolated position" architecture **does not exist** in the inspected source. Lua-side prediction exists but is fragmented, unblended, and render/telemetry-only in the inspected copies.

---  
*End of PREDICTION_API_GAPS.md*