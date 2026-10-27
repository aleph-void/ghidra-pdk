// After import + auto-analysis of a real PDK program: dump every instruction (word address, opcode word, text),
// count functions, bad-instruction and error bookmarks, and decompile every function.
// Script args: <outfile>      (writes "ins <addr> <word> <text>" lines and a "summary ..." line)
//@category Testing

import java.io.PrintStream;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Bookmark;
import java.util.Iterator;

public class RealCheck extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[0]);
		int ins = 0;
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			Instruction i = it.next();
			Address a = i.getAddress();
			long w = 0;
			byte[] b = i.getBytes();
			w = (b[0] & 0xff) | ((b[1] & 0xff) << 8);
			out.printf("ins %x %04x %s%n", a.getAddressableWordOffset(), w, i);
			ins++;
		}
		int funcs = 0, decFail = 0;
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			funcs++;
			DecompileResults r = di.decompileFunction(f, 60, monitor);
			if (!r.decompileCompleted()) {
				decFail++;
				out.println("decompile-fail " + f.getName() + " " + r.getErrorMessage());
			}
		}
		int bad = 0, err = 0, warn = 0;
		Iterator<Bookmark> bi = currentProgram.getBookmarkManager().getBookmarksIterator();
		while (bi.hasNext()) {
			Bookmark bm = bi.next();
			String t = bm.getTypeString();
			if (t.equals("Error")) {
				err++;
				out.println("bookmark Error " + bm.getAddress() + " " + bm.getCategory() + " " + bm.getComment());
			}
			else if (t.equals("Warning")) {
				warn++;
			}
			if (bm.getCategory().contains("Bad Instruction") || bm.getComment().contains("Bad Instruction")) {
				bad++;
			}
		}
		out.printf("summary instructions=%d functions=%d bad_instruction_bookmarks=%d error_bookmarks=%d warning_bookmarks=%d decompile_failures=%d%n",
			ins, funcs, bad, err, warn, decFail);
		out.close();
	}
}
