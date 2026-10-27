// Runs single instructions in Ghidra's emulator (EmulatorHelper) for a list of randomised cases and
// writes the resulting state, so that test/sem_diff.py can compare it with the ucsim simulator.
//
// input line:  <id> <opcode hex> <A hex> <flag hex> <sp hex> <ram hex string (RAMN bytes)> [<rom word hex>@<addr hex>]...
// output line: <id> OK <A> <flag> <sp> <pc hex> <ram hex string>   or   <id> ERR <message>
// Script args: <cases> <out>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public class SemCheck extends GhidraScript {
	static final int RAMN = 64;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		AddressSpace rom = currentProgram.getAddressFactory().getAddressSpace("rom");
		AddressSpace ram = currentProgram.getAddressFactory().getAddressSpace("ram");
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String line;
			while ((line = r.readLine()) != null) {
				String[] f = line.trim().split("\\s+");
				if (f.length < 6) {
					continue;
				}
				String id = f[0];
				EmulatorHelper emu = new EmulatorHelper(currentProgram);   // new emulator per case: decoded instructions are cached
				try {
					int op = Integer.parseInt(f[1], 16);
					// EmulatorHelper memory offsets are byte offsets: word w of the word-addressed code space is at 2*w
					emu.writeMemory(rom.getAddress(0), new byte[] { (byte) op, (byte) (op >> 8) });
					// nops after it (skip instructions) and, if given, extra code words
					emu.writeMemory(rom.getAddress(2), new byte[] { 0, 0, 0, 0 });
					for (int i = 6; i < f.length; i++) {
						String[] p = f[i].split("@");
						int w = Integer.parseInt(p[0], 16);
						emu.writeMemory(rom.getAddress(2 * Long.parseLong(p[1], 16)),
							new byte[] { (byte) w, (byte) (w >> 8) });
					}
					emu.writeRegister("A", Long.parseLong(f[2], 16));
					emu.writeRegister("flag", Long.parseLong(f[3], 16));
					emu.writeRegister("sp", Long.parseLong(f[4], 16));
					emu.writeRegister("GIE", 0);
					byte[] rb = new byte[RAMN];
					for (int i = 0; i < RAMN; i++) {
						rb[i] = (byte) Integer.parseInt(f[5].substring(2 * i, 2 * i + 2), 16);
					}
					emu.writeMemory(ram.getAddress(0), rb);
					emu.writeRegister(emu.getPCRegister(), 0);
					if (!emu.step(monitor)) {
						out.println(id + " ERR " + emu.getLastError());
						continue;
					}
					StringBuilder sb = new StringBuilder();
					byte[] after = emu.readMemory(ram.getAddress(0), RAMN);
					for (byte b : after) {
						sb.append(String.format("%02x", b & 0xff));
					}
					out.printf("%s OK %02x %02x %02x %x %s%n", id, emu.readRegister("A").intValue(),
						emu.readRegister("flag").intValue() & 0xf, emu.readRegister("sp").intValue(),
						emu.getExecutionAddress().getOffset() / 2, sb);   // offsets of the emulator are byte offsets
				}
				catch (Exception e) {
					out.println(id + " ERR " + e);
				}
				finally {
					emu.dispose();
				}
			}
		}
		out.close();
	}
}
