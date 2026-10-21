package com.Fatdog.kkl3;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.utils.Inspector;
import unicorn.Arm64Const;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.PointerArg;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.DvmObject;
import java.io.File;

public class Kl3 {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    private final boolean logging;

    private static class MyJni extends AbstractJni {
        @Override
        public DvmObject<?> callStaticObjectMethodV(
                BaseVM vm,
                DvmClass dvmClass,
                String signature,
                VaList vaList) {
            if (signature.equals("com/fatdog/reverse/Ku3->halfA()Ljava/lang/String;")) {
                return new StringObject(vm, "Fatdog_");
            }
            return super.callStaticObjectMethodV(
                    vm, dvmClass, signature, vaList);
        }

        @Override
        public int callStaticIntMethodV(
                BaseVM vm,
                DvmClass dvmClass,
                String signature,
                VaList vaList) {

            if ("com/fatdog/reverse/Ku3->bridgeSeed()I"
                    .equals(signature)) {
                return 539362051;
            }

            return super.callStaticIntMethodV(
                    vm, dvmClass, signature, vaList);
        }
    }

    Kl3(boolean logging) {
        this.logging = logging;

        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.fatdog.reverse.kl3")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM();
        vm.setJni(new MyJni());
        vm.setVerbose(logging);
        // 先加载 C++ 运行库
        DalvikModule cxx = vm.loadLibrary(
                new File("unidbg-android/src/test/resources/example_binaries/Fatdog/libc++_shared.so"),
                false);

        DalvikModule bramble = vm.loadLibrary(
            new File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl3/libbramble.so"), 
                false);

        DalvikModule cinder = vm.loadLibrary(
            new File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl3/libcinder.so"), 
                false);

        DalvikModule drift = vm.loadLibrary(
            new File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl3/libdrift.so"), 
                false);

        DalvikModule elder = vm.loadLibrary(
            new File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl3/libelder.so"), 
                false);

        DalvikModule fable = vm.loadLibrary(
            new File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl3/libfable.so"), 
                false);

        DalvikModule dm = vm
                .loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/Fatdog/libacorn.so"), false);
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
        Kl3 test = new Kl3(true);

        try {
            test.nativekey();
        } finally {
            test.destroy();
        }
    }

    public void nativekey() {
        DvmClass ku3Class = vm.resolveClass("com/fatdog/reverse/Ku3");

        DvmObject<?> result = ku3Class.callStaticJniMethodObject(
                emulator,
                "nativeKey()Ljava/lang/String;");

        System.out.println("result = " +
                (result == null ? "null" : result.getValue()));
    }
}