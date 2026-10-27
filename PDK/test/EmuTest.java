// P-code semantics check for the PDK module.  Reads test/emu/cases.txt (expectations worked out by hand from
// the Free PDK instruction tables and the Padauk datasheets), runs each case in Ghidra's emulator
// (EmulatorHelper) and compares registers, flags, data memory and the program counter.
//
// Case format ('#' comments):
//   case <name> isa <13|14|15|16> [broken]    "broken" cases carry a deliberately wrong expectation
//   code <hex words>                          16-bit instruction words, placed at word address 0
//   asm <mnemonic> ; <mnemonic> ; ...         what each code word must disassemble to (guards against mistyped encodings)
//   until <word-address>                      stop when the PC reaches this word address (default: end of code)
//   set <A|flag|sp|T16|GIE|pa|...> <value>    register (flag and sp are I/O registers 0 and 2)
//   set ram:<hex-addr> <value>                data memory byte
//   set rom:<hex-addr> <value>                code word
//   expect <register|ram:addr|rom:addr|PC>    <value>   (PC in words)
//   end
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public class EmuTest extends GhidraScript {

	private static class Case {
		String name;
		int isa;
		boolean broken;
		int[] code;
		String[] asm;
		long until = -1;
		Map<String, Long> set = new LinkedHashMap<>();
		Map<String, Long> expect = new LinkedHashMap<>();
	}

	private List<Case> load(String path) throws Exception {
		List<Case> cases = new ArrayList<>();
		Case c = null;
		try (BufferedReader r = new BufferedReader(new FileReader(path))) {
			String line;
			while ((line = r.readLine()) != null) {
				int h = line.indexOf('#');
				if (h >= 0 && !line.startsWith("asm ")) {
					line = line.substring(0, h);
				}
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				String[] f = line.split("\\s+");
				switch (f[0]) {
					case "case":
						c = new Case();
						c.name = f[1];
						for (int i = 2; i < f.length; i++) {
							if (f[i].equals("isa")) {
								c.isa = Integer.parseInt(f[++i]);
							}
							else if (f[i].equals("broken")) {
								c.broken = true;
							}
						}
						break;
					case "code":
						c.code = new int[f.length - 1];
						for (int i = 1; i < f.length; i++) {
							c.code[i - 1] = Integer.parseInt(f[i], 16);
						}
						break;
					case "asm":
						c.asm = line.substring(3).trim().split("\\s*;\\s*");
						break;
					case "until":
						c.until = Long.decode(f[1]);
						break;
					case "set":
						c.set.put(f[1], Long.decode(f[2]));
						break;
					case "expect":
						c.expect.put(f[1], Long.decode(f[2]));
						break;
					case "end":
						cases.add(c);
						break;
					default:
						throw new IllegalArgumentException("bad line: " + line);
				}
			}
		}
		return cases;
	}

	private String dis(int w) {
		ghidra.program.model.lang.Language lang = currentProgram.getLanguage();
		Address a = currentProgram.getAddressFactory().getAddressSpace("rom").getAddress(0x1000);
		byte[] b = new byte[8];
		b[0] = (byte) w;
		b[1] = (byte) (w >> 8);
		try {
			ghidra.program.model.lang.ProcessorContextImpl ctx =
				new ghidra.program.model.lang.ProcessorContextImpl(lang);
			ghidra.program.model.mem.MemBuffer buf =
				new ghidra.program.model.mem.ByteMemBufferImpl(a, b, true);
			ghidra.program.model.lang.InstructionPrototype proto = lang.parse(buf, ctx, false);
			return new ghidra.app.util.PseudoInstruction(currentProgram, a, proto, buf, ctx).toString();
		}
		catch (Exception e) {
			return "BAD";
		}
	}

	// case and spacing do not matter, nor do leading zeros of hex numbers (0x0a == 0xa)
	private static String norm(String s) {
		return s.replace(" ", "").toLowerCase().replaceAll("0x0+([0-9a-f])", "0x$1");
	}

	private int isaOf(String lang) {
		String p = lang.substring(0, lang.indexOf(':')).toLowerCase();
		switch (p) {
			case "pdk13":
				return 13;
			case "pms132":
			case "pms152":
				return 14;
			case "pms134":
				return 15;
			default:
				return 16;
		}
	}

	private boolean isMem(String k) {
		return k.startsWith("ram:") || k.startsWith("rom:");
	}

	private long readMem(EmulatorHelper emu, String key) {
		long a = Long.parseLong(key.substring(4), 16);
		if (key.startsWith("ram:")) {
			AddressSpace ram = currentProgram.getAddressFactory().getAddressSpace("ram");
			return emu.readMemory(ram.getAddress(a), 1)[0] & 0xff;
		}
		AddressSpace rom = currentProgram.getAddressFactory().getAddressSpace("rom");
		byte[] b = emu.readMemory(rom.getAddress(2 * a), 2);   // emulator memory offsets are byte offsets
		return (b[0] & 0xff) | ((b[1] & 0xff) << 8);
	}

	private String runCase(Case c) throws Exception {
		AddressSpace rom = currentProgram.getAddressFactory().getAddressSpace("rom");
		AddressSpace ram = currentProgram.getAddressFactory().getAddressSpace("ram");
		if (c.asm != null) {
			if (c.asm.length != c.code.length) {
				return "asm/code length mismatch";
			}
			for (int i = 0; i < c.code.length; i++) {
				String d = norm(dis(c.code[i]));
				if (!d.equals(norm(c.asm[i]))) {
					return String.format("word %d (0x%04x) disassembles as '%s', not '%s'", i, c.code[i],
						dis(c.code[i]), c.asm[i]);
				}
			}
		}
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			byte[] code = new byte[2 * c.code.length + 8];
			for (int i = 0; i < c.code.length; i++) {
				code[2 * i] = (byte) c.code[i];
				code[2 * i + 1] = (byte) (c.code[i] >> 8);
			}
			emu.writeMemory(rom.getAddress(0), code);
			long end = c.until >= 0 ? c.until : c.code.length;
			for (Map.Entry<String, Long> e : c.set.entrySet()) {
				String k = e.getKey();
				if (k.startsWith("ram:")) {
					emu.writeMemory(ram.getAddress(Long.parseLong(k.substring(4), 16)),
						new byte[] { (byte) (long) e.getValue() });
				}
				else if (k.startsWith("rom:")) {
					long w = e.getValue();
					emu.writeMemory(rom.getAddress(2 * Long.parseLong(k.substring(4), 16)),
						new byte[] { (byte) w, (byte) (w >> 8) });
				}
				else {
					emu.writeRegister(k, e.getValue());
				}
			}
			emu.writeRegister(emu.getPCRegister(), 0);
			int steps = 0;
			while (emu.getExecutionAddress().getOffset() / 2 != end) {
				if (++steps > 5000) {
					return "did not reach the end (pc " + emu.getExecutionAddress() + ")";
				}
				if (!emu.step(monitor)) {
					return "emulation error at " + emu.getExecutionAddress() + ": " + emu.getLastError();
				}
			}
			StringBuilder bad = new StringBuilder();
			for (Map.Entry<String, Long> e : c.expect.entrySet()) {
				long got;
				String k = e.getKey();
				if (isMem(k)) {
					got = readMem(emu, k);
				}
				else if (k.equals("PC")) {
					got = emu.getExecutionAddress().getOffset() / 2;
				}
				else {
					got = emu.readRegister(k).longValue();
					if (k.equals("flag")) {
						got &= 0xf;
					}
				}
				if (got != e.getValue()) {
					bad.append(String.format(" %s=0x%x (expected 0x%x)", k, got, e.getValue()));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<Case> cases = load(args[0]);
		PrintStream out = new PrintStream(args[1]);
		String lang = currentProgram.getLanguageID().getIdAsString();
		int isa = isaOf(lang);
		int pass = 0, fail = 0, brokenSeen = 0, brokenMissed = 0;
		for (Case c : cases) {
			if (c.isa != isa) {
				continue;
			}
			String err = runCase(c);
			if (c.broken) {
				if (err != null) {
					brokenSeen++;
					out.println("PASS (broken expectation detected) " + c.name + ": " + err);
				}
				else {
					brokenMissed++;
					out.println("FAIL " + c.name + ": the deliberately wrong expectation passed");
				}
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + c.name);
			}
			else {
				fail++;
				out.println("FAIL " + c.name + ": " + err);
			}
		}
		out.printf("emulation (%s): %d passed, %d failed, broken expectation %s%n", lang, pass,
			fail + brokenMissed, brokenSeen > 0 && brokenMissed == 0 ? "detected" : "NOT detected");
		out.close();
	}
}
