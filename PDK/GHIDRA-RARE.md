# PDK (Padauk PDK13/14/15/16) — Ghidra-Rare verification notes

Based on [CUB3D/ghidra-pdk](https://github.com/CUB3D/ghidra-pdk) (Apache-2.0); see [CREDITS.md](CREDITS.md).  None of the
upstream's five specs compiled; the module was reworked (see the README table) and verified as below.

## What it covers

| Language ID | Family | Devices (register table) |
|---|---|---|
| `pdk13:LE:16:default` | PDK13, 13 bit code words | PMS150C / PMS15A |
| `pms152:LE:16:default` | PDK14, 14 bit | PMS152 and relatives |
| `pms132:LE:16:default` | PDK14, 14 bit | PMS132 (multiplier, PWM, ADC) |
| `pms134:LE:16:default` | PDK15, 15 bit | PMS133 / PMS134 |
| `pmc884:LE:16:default` | PDK16, 16 bit | PMC884 (8 FPPA cores) |

Code is word addressed, data memory (`ram`) is separate, I/O registers live at `register:0x100 + io address`.
Other devices of a family decode with the closest table; unnamed I/O addresses are `io_XX`.
Instruction patterns come from the Free PDK tables; the whole instruction set of a family decodes on every device of it
(optional instructions such as `MUL`, `COMP`, `NADD` are available only on some devices; the Free PDK pages list which).

## How to test

```
GHIDRA_INSTALL_DIR=<Ghidra with this directory linked as Ghidra/Processors/PDK> \
SDCC_ROOT=<prefix with usr/bin/{sdcc,ucsim_pdk,sdaspdk13,sdaspdk14,sdaspdk15,makebin}> \
  test/run-tests.sh [--real] [--per-form N] <workdir>
```

Needs python3, a C compiler and curl (the MIT-licensed fppa-pdk-tools are fetched by pinned archive and SHA-256).
`--real` also fetches and builds the free-pdk showcase projects with SDCC.  Nothing fetched or built is committed.
`tools/gen_pdk.py` and `tools/gen_chips.py` regenerate the `*_tok.sinc`, `*_ops.sinc`, `*_regs.sinc`, `*_attach.sinc`
files (`run-tests.sh` checks that they match).

## Results

| Area | Result |
|---|---|
| Builds | all five `.slaspec` compile on Ghidra 12.1.3, 12.1.4 and 12.2 (no pattern conflicts); `.sla` < 1 MB; release zips built with `tools/build-module.sh --standard --name PDK` |
| Decode vs dispdk (MIT, fppa-pdk-tools) | every opcode word of PDK13 (8192), PDK14 (16384), PDK15 (32768), PDK16 (65536): 7801 / 16089 / 30105 / 35224 identical, 389 / 293 / 1893 / 1700 invalid in both, the rest in the explained classes below, **0 unexplained** |
| Decode vs ucsim (SDCC) | same words: 7226 / 15962 / 19738 / 63048 identical, 0 unexplained (896 / 128 / 11136 / 785 in explained ucsim gaps and bugs) |
| Decode vs sdaspdk13/14/15 | Ghidra's text for every valid opcode (except GOTO/CALL) assembled back with the SDCC assembler: 5754 / 11994 / 22170 words identical, **0 differ** (PDK15: the assembler lacks `NMOV`, 512 words; PDK16 has no assembler) |
| Every constructor reached | 87/87 (PDK13), 94/94 (PMS132), 94/94 (PMS152), 99/99 (PMS134), 112/112 (PMC884) |
| Semantics: emulator | 68 hand-computed sequences (38 PDK14, 8 PDK13, 10 PDK15, 12 PDK16) cover ALU flags (carry, borrow, aux carry, overflow), skip instructions, bit operations in memory and I/O, `flag`/`sp` as I/O registers, push/pop, call/return, `PCADD`, `IDXM`, `STT16`/`LDT16`, `LDTAB`, `PUSHW`/`POPW`, `IGOTO`/`ICALL`, `TOG`, `NMOV`, `DELAY`, `MUL`; one deliberately wrong expectation per instruction set is detected |
| Semantics: ucsim | single instructions run in Ghidra's emulator and in ucsim from the same random states (A, flags, SP, 64 data bytes, PC): 3144 / 3480 / 3478 / 3672 cases agree, 0 differ (explained deviations below); 131 / 145 / 150 / 155 instruction forms |
| Real code | 13 SDCC-built programs (free-pdk showcase projects: audioplayer, noiseplug, polysound, ws2812animation16x16 for PMS150C, PFS154, PFS172, PFS173): 4003 instructions, 129 functions, 0 bad-instruction bookmarks, 0 error bookmarks, 0 decompile failures; every instruction agrees with ucsim at the same address (3756 identical, 243 in explained ucsim gaps) |
| Intel Hex | the built-in loader imports SDCC `.ihx` files at the right word addresses |

### Differences against the reference tools (all explained)

dispdk (fppa-pdk-tools): the all-ones word is "illegal" (the table calls it `CALL`); `TRAP` at 0x0020 is named only there; no
`NMOV`/`SWAP M` for PDK15; data addresses >= 0x20 rejected in PDK16; PDK16 `GOTO`/`CALL` swapped; PDK16 `A,M`/`M,A` forms
of `NMOV`/`NADD`/`CEQSN`/`COMP` swapped.
ucsim: no `SUBC M` (PDK13), `COMP M,A` (PDK14), `TOG` (PDK16); decodes `CNEQSN` in PDK13 (table and sdaspdk13 reject it);
`GOTO`/`CALL` without operand and no memory bit-operand forms in PDK13/15; `LDTABL`/`LDTABH` swapped; `POPWPC n` shown as
`PUSHWPC`; `ICALL` shows the raw odd address.

### Confirmed bugs in the reference tools

- ucsim_pdk: `MOV A,M` / `MOV A,IO` do not update ZF; `LDSPTH` returns the low byte; PDK16 memory bit tests (`T0SN/T1SN M.n`)
  always make the same skip decision; PDK16 `IDXM` goes through another pointer; PDK16 `LDTABL/H`, `ICALL`, `IGOTO`, `STT16`,
  `LDT16` not executed or wrong; `RETI` is "invalid instruction"; the interpreter loop prints asynchronously (the tests use one
  process per case); `pc <n>` followed by `step` fails for n != 0 on the pdk14 model.
- dispdk (fppa-pdk-tools): the PDK16 swaps listed above.
- Free PDK PDK16 page: the bit cells of ADD M,A .. MOV A,M (0x40..0x5F) are shifted (the hex column is right); the `SR M`
  hex cell reads 0x73 instead of 0x74.
- sdaspdk: absolute `goto`/`call` operands are scaled before linking (linked images are right; the round trip excludes them).

## Doesn't work

- Peripherals, timers (`T16` only holds the value moved by `STT16`/`LDT16`), watchdog, interrupt dispatch and the system
  clock are hardware state; `WDRESET`, `STOPSYS`, `STOPEXE`, `PMODE`, `PUSHWPC`, `POPWPC` are p-code operations
  (`watchdog_reset`, `stop_sys`, `stop_exe`, `pmode`, `fppa_getpc`, `fppa_setpc`).  `RESET` is `chip_reset()` followed by a
  jump to address 0.  `ENGINT`/`DISGINT`/`RETI` maintain the register `GIE` only; no interrupt vector flow.
- Instruction timing: `DELAY` only clears `A`; `WAIT0`/`WAIT1` loop on the instruction until the bit changes.
- `.pdk` programmer files and Padauk IDE listings have no loader (convert with fppa-pdk-tools' `depdk`, or use `.ihx`/`.bin`).
- Only five device tables exist; other devices use the nearest one (unnamed addresses decode as `io_XX`).
- No `.dwarf` mapping and no ELF opinion: SDCC's pdk backends emit neither.

## Unverified

- `LDSPTL`/`LDSPTH`: the module follows the Free PDK table (`CodeMem(WORD[SP])`, the word in data memory at `SP`, as in
  fppa-pdk-tools' emulator); ucsim reads `ROM[SP]`.  No hardware or vendor text settles it.
- `NADD` flags: result agrees with ucsim; ucsim's flags fit neither addition nor subtraction; the module uses the flags of
  the addition `M + NEG(A)`.
- PDK16 behaviour that ucsim cannot confirm: `IDXM` pointer width (word at M masked to 9 bits), `LDTAB`, `ICALL`/`IGOTO`,
  `PUSHW`/`POPW`, `DELAY`, `WAIT`, `TOG`, `XOR A,IO` (covered by hand-computed cases only), and the PMC884 register table
  (the datasheet copy named by upstream could not be retrieved complete).
- No PDK16 program: SDCC has no pdk16 backend and no freely licensed PDK16 firmware was found.
- The 16-bit timer value; `RETI` re-enabling interrupts (from fppa-pdk-tools' emulator).
