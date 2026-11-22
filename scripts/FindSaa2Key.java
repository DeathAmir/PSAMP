import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class FindSaa2Key extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new Exception("Output path required");
        byte[] key = new byte[] {
(byte)0xac,(byte)0xa8,(byte)0xaa,(byte)0xaa,(byte)0xaa,(byte)0x8e,(byte)0xaa,(byte)0xaa,
(byte)0xf8,(byte)0xf9,(byte)0xeb,(byte)0x9b,(byte)0xaa,(byte)0xae,(byte)0xaa,(byte)0xaa,
(byte)0xab,(byte)0xaa,(byte)0xab,(byte)0xaa,(byte)0x65,(byte)0xcc,(byte)0x2a,(byte)0xc9,
(byte)0x3e,(byte)0x4e,(byte)0x7a,(byte)0x51,(byte)0xed,(byte)0xc9,(byte)0x29,(byte)0xf7,
(byte)0x9c,(byte)0xb2,(byte)0xb0,(byte)0x63,(byte)0xfd,(byte)0x43,(byte)0x6c,(byte)0xae,
(byte)0x99,(byte)0xd7,(byte)0x99,(byte)0x41,(byte)0x01,(byte)0x9a,(byte)0xe9,(byte)0x49,
(byte)0x56,(byte)0x97,(byte)0x72,(byte)0x82,(byte)0x79,(byte)0xd5,(byte)0x4f,(byte)0xbc,
(byte)0x6b,(byte)0xb0,(byte)0x5c,(byte)0x9c,(byte)0xf0,(byte)0xc9,(byte)0x1f,(byte)0x17,
(byte)0x3b,(byte)0xbe,(byte)0x21,(byte)0x5d,(byte)0x74,(byte)0xb8,(byte)0x29,(byte)0x8d,
(byte)0xb0,(byte)0x7b,(byte)0x2d,(byte)0xe2,(byte)0x83,(byte)0x25,(byte)0x0b,(byte)0x6e,
(byte)0x28,(byte)0x4e,(byte)0x4e,(byte)0x99,(byte)0x66,(byte)0xe0,(byte)0x9f,(byte)0x58,
(byte)0x09,(byte)0xd6,(byte)0xda,(byte)0xe3,(byte)0x7b,(byte)0x86,(byte)0x41,(byte)0xcd,
(byte)0xff,(byte)0xbc,(byte)0x37,(byte)0x5b,(byte)0xd8,(byte)0x49,(byte)0x10,(byte)0x1a,
(byte)0x0d,(byte)0xc2,(byte)0x64,(byte)0x35,(byte)0x71,(byte)0x9a,(byte)0x7c,(byte)0x32,
(byte)0xa9,(byte)0x59,(byte)0x45,(byte)0x7e,(byte)0x51,(byte)0x38,(byte)0xe4,(byte)0x0b,
(byte)0x53,(byte)0x4d,(byte)0xaf,(byte)0x87,(byte)0xa0,(byte)0x48,(byte)0xd5,(byte)0x54,
(byte)0x4c,(byte)0x6c,(byte)0x8e,(byte)0xa4,(byte)0xd7,(byte)0x5b,(byte)0xe1,(byte)0xe0,
(byte)0x20,(byte)0x76,(byte)0x10,(byte)0x4c,(byte)0x75,(byte)0x89,(byte)0x6a,(byte)0x2a,
(byte)0x44,(byte)0xf5,(byte)0xab,(byte)0x1d
        };
        byte[] mask = new byte[key.length];
        java.util.Arrays.fill(mask, (byte)0xff);
        File out = new File(args[0]);
        File parent = out.getParentFile();
        if (parent != null) parent.mkdirs();
        try (BufferedWriter w = new BufferedWriter(new FileWriter(out))) {
            w.write("pattern_size=" + key.length + "\n");
            w.write("image_base=" + currentProgram.getImageBase() + "\n");
            Address start = currentProgram.getMinAddress();
            Address end = currentProgram.getMaxAddress();
            int count = 0;
            while (start != null && start.compareTo(end) <= 0) {
                monitor.checkCancelled();
                Address found = currentProgram.getMemory().findBytes(start, end, key, mask, true, monitor);
                if (found == null) break;
                long rva = found.subtract(currentProgram.getImageBase());
                w.write("match_" + count + "_address=" + found + "\n");
                w.write("match_" + count + "_rva=0x" + Long.toHexString(rva) + "\n");
                count++;
                start = found.add(1);
            }
            w.write("matches=" + count + "\n");
        }
        println("SAA2 key scan complete: " + out.getAbsolutePath());
    }
}