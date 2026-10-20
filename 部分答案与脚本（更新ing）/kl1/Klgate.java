package com.Fatdog.kkl1;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class Klgate {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;


    private final boolean logging;

    Klgate(boolean logging) {
        this.logging = logging;

        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.fatdog.reverse.gate")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM();
        vm.setVerbose(logging);
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/Fatdog/libcedar.so"), false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();
    }

    @Override
    public String toString() {
        return "Fatdog backend=" + emulator.getBackend();
    }

    void destroy() {
        IOUtils.close(emulator);
        if (logging) {
            System.out.println("destroy");
        }
    }

    public static void main(String[] args) throws Exception {
        Klgate test = new Klgate(true);
        test.klgate();
        test.destroy();
    }

    public int klgate() {
        Symbol symbol1 = module.findSymbolByName("Java_com_fatdog_reverse_Ku1_klGate", false);
        if (symbol1 == null) {
            throw new RuntimeException("找不到导出函数 gate");
        }
        Number result = (Number) symbol1.call(emulator, 0,0,0x20260101);
        System.out.println("result = " + result.intValue());
        return result.intValue();
    }
}