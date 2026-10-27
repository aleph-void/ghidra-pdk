# Credits

## Upstream

- Project: ghidra-pdk, PADAUK PDK architecture for Ghidra — https://github.com/CUB3D/ghidra-pdk
- Commit: `002d34badb39f3052af32bd280bdfd8b5135a7bc` ("Missed one", 2026-05-11); the repository has a single commit
- License: Apache License 2.0 (see `LICENSE`; the original `../LICENSE` is kept at the repository root)
- Original author: CUB3D (GitHub @CUB3D, git author "CUB3D")

The module's directory layout, language IDs (`pdk13`, `pms152`, `pms132`, `pms134`, `pmc884`), device selection and
the first versions of the register tables are the original author's work.

## Changes made by Ghidra-Rare (all in git commits on branch `ghidra-rare`)

1. The specs did not compile; they were reworked: word-addressed code space, I/O registers in the register space,
   program counter `IP`, per-device register tables, stack in data memory, corrected flag arithmetic, pcodes for every
   instruction of the four instruction sets.
2. The PDK13/14/15/16 constructors are generated from the Free PDK instruction-set tables (`tools/gen_pdk.py`,
   `tools/parse_doc.py`, `tools/doc/*.tab`); device I/O tables are generated from `tools/chips.json`
   (`tools/gen_chips.py`).  Errata applied: the Free PDK PDK16 page's bit cells for 0x40..0x5F (checked against ucsim and
   dispdk), LDSPTL/LDSPTH added to PDK15 (sdaspdk15, ucsim and dispdk decode them).
3. I/O register tables checked against the vendor datasheets and corrected (PMS150C, PMS132, PMS152).
4. cspec/pspec/ldefs rewritten for the new address spaces; extension build files (`build.gradle`,
   `extension.properties`), `LICENSE`.
5. Tests (`test/`), the notes `GHIDRA-RARE.md` and this file, README updates.

## Sources used

- Free PDK documentation, instruction set tables for PDK13/14/15/16 (https://free-pdk.github.io/instruction-sets/,
  source: https://github.com/free-pdk/fppa-pdk-documentation): encodings and flag effects.  Only the facts (bit
  patterns, mnemonics) are in `tools/doc/*.tab`; the pages themselves are not copied.
- Padauk datasheets PMS150C/PMS15A, PMS132(B), PMS133/PMS134 (I/O address tables; not redistributed).
- free-pdk `pdk-includes` (GPL-2.0, https://github.com/free-pdk/pdk-includes): register names and addresses of
  PMS150C/PMS152 were cross-checked against it; nothing copied.
- Reference tools used as black boxes (their GPL source was not read to learn encodings or semantics): SDCC 4.5.0
  `ucsim_pdk`, `sdaspdk13/14/15`, `sdcc`, `makebin`.
- fppa-pdk-tools (MIT, https://github.com/free-pdk/fppa-pdk-tools, commit
  `670e7bc9c1b33469fe8c80cd4c1eeb053d20c191`): disassembler used as reference, its emulator read as a second opinion on flag
  behaviour (MIT-licensed).
- Test programs: free-pdk easy-pdk-showcase-projects (GPL-3.0,
  https://github.com/free-pdk/easy-pdk-showcase-projects, commit `6a42c21fe7da5a35af5cb2002a9e8c0c1bd3234d`), fetched by
  `test/fetch-real.sh` at test time, never committed.
