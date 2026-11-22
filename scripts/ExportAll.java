import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class ExportAll extends ghidra.app.script.GhidraScript {
    private String cEscape(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '\\') out.append("\\\\");
            else if (ch == '"') out.append("\\\"");
            else if (ch == '\n') out.append("\\n");
            else if (ch == '\r') out.append("\\r");
            else if (ch == '\t') out.append("\\t");
            else if (ch >= 32 && ch <= 126) out.append(ch);
            else out.append(String.format("\\x%02X", (int) ch & 255));
        }
        return out.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new Exception("Output C path is required");
        File output = new File(args[0]);
        File parent = output.getParentFile();
        if (parent != null) parent.mkdirs();

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) {
            throw new Exception("Could not open program in decompiler");
        }

        int total = currentProgram.getFunctionManager().getFunctionCount();
        int done = 0;
        List<String> strings = new ArrayList<String>();

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(output))) {
            writer.write("/* Ghidra decompilation output. Approximate reconstruction, not original source. */\n");
            writer.write("#include <stddef.h>\n\n");
            writer.write("/* Decompiled functions */\n\n");

            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                monitor.checkCancelled();
                DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
                writer.write("\n/* " + function.getName() + " @ " + function.getEntryPoint() + " */\n");
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    writer.write(result.getDecompiledFunction().getC());
                    writer.write("\n");
                } else {
                    writer.write("/* Decompilation failed: " + cEscape(result == null ? "no result" : result.getErrorMessage()) + " */\n");
                }
                done++;
                if ((done % 100) == 0) println("Decompiled " + done + " / " + total);
            }

            Listing listing = currentProgram.getListing();
            for (Data data : listing.getDefinedData(true)) {
                monitor.checkCancelled();
                if (data.getDataType() != null && data.getDataType().getName().toLowerCase().contains("string")) {
                    Object value = data.getValue();
                    if (value != null) {
                        String text = value.toString();
                        if (!text.isEmpty()) strings.add(data.getAddress() + "\t" + text);
                    }
                }
            }

            writer.write("\n/* Extracted strings */\n");
            writer.write("const char *samp_extracted_strings[] = {\n");
            for (String item : strings) {
                int tab = item.indexOf('\t');
                String address = item.substring(0, tab);
                String value = item.substring(tab + 1);
                writer.write("    \"" + cEscape(address + ": " + value) + "\",\n");
            }
            writer.write("    NULL\n};\n");
            writer.write("const size_t samp_extracted_string_count = " + strings.size() + ";\n");
        } finally {
            decompiler.dispose();
        }

        println("Exported " + done + " functions and " + strings.size() + " strings to " + output.getAbsolutePath());
    }
}
