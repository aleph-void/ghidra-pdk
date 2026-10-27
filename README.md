# PADAUK PDK architecture for Ghidra

Supports:
- PDK13 / SYM_84B (PMS150C)
- PDK14 / SYM_85A (PMS152 / PMS132)
- PDK15 / SYM_86A, SYM_86B (PMS134)
- PDK16 / SYM_83A, SYM_83B2 (PMC884)

The Padauk FPPA parts are Harvard machines with 13/14/15/16 bit code words, an accumulator `A`, a flag register
(ZF, CF, AC, OV), an I/O space and a small data memory that also holds the stack.

# Installing

Download the extension zip for your Ghidra version (12.1.3, 12.1.4 or 12.2) from this repository's Releases page and use
*File > Install Extensions*; or copy the `PDK` directory to `<ghidra_dir>/Ghidra/Processors`.
The original instructions (copy `PDK` to `<ghidra_dir>/Ghidra/Processors`, or install via
[AUR](https://aur.archlinux.org/packages/ghidra-extension-pdk-git)) still apply to a source checkout.

Programs: import the flat code image (little-endian 16-bit words at byte offset 2 * word address, as `makebin` of SDCC
writes it) with the *Raw Binary* loader, or an SDCC `.ihx` file with the built-in *Intel Hex* loader, and pick the
language (`pdk13`, `pms152`, `pms132`, `pms134`, `pmc884`).  Code addresses are word addresses, as in Padauk and SDCC
listings.  I/O registers are the register-space names of the device (`pa`, `tm2c`, ...; unnamed addresses are `io_XX`).

# Status of the original module's limitations and stale claims

This fork ([Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare) verification, see [GHIDRA-RARE.md](GHIDRA-RARE.md)
and [CREDITS.md](CREDITS.md)) changes the following; the original author's text above is kept.

| Original state | Now |
|---|---|
| None of the five specs compiled | Fixed: all five compile on Ghidra 12.1.3, 12.1.4 and 12.2 |
| Code space byte addressed, `GOTO`/`CALL` shifted by one | Fixed: the code space is word addressed; `CALL` pushes the word address like the hardware |
| `PC` register undefined, `pc` I/O port collided with it | Fixed: the program counter is `IP` |
| Carry/aux/overflow flags of subtraction computed with `scarry` | Fixed: CF/AC are borrows, OV is signed overflow; checked against ucsim |
| `PCADD`: "is this +A or <<1?" (TODO) | Fixed: `PCADD` adds `A` to the address of the `PCADD` instruction (ucsim and fppa-pdk-tools agree) |
| `RETI`: "the spec doesn't specify where the return address is, guess" | Fixed: it pops the return address like `RET` and re-enables interrupts (fppa-pdk-tools' emulator) |
| `UNSUPPORTED_*` constructors for instructions a device lacks | Changed: every device decodes the whole instruction set of its family; the Free PDK tables list per device which optional instructions exist |
| `LDSPTL`/`LDSPTH` read `ROM[SP*2]` | Changed to the table's `CodeMem(WORD[SP])`; unverified on hardware (see GHIDRA-RARE.md) |
| I/O register tables: PMS150C table was PMS134-like, PMS132 `arcrgc`/`tm3s` wrong | Fixed against the vendor datasheets and pdk-includes; unnamed addresses decode as `io_XX` instead of failing |
| No tests | `test/run-tests.sh`: decode differential, every-constructor, emulator, semantic differential, SDCC-built programs |
| Remaining: peripherals/timers/interrupts are not modelled; no PDK16 code to test; PMC884 register table unverified | see GHIDRA-RARE.md, "Doesn't work" and "Unverified" |

Prebuilt zips are on the fork's Releases page.
