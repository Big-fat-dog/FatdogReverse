package com.Fatdog.kkl2;

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
import com.github.unidbg.linux.android.dvm.DvmObject;
import java.io.File;

public class Kl2 {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    private final boolean logging;

    Kl2(boolean logging) {
        this.logging = logging;

        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.fatdog.reverse.kl2")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM();
        vm.setVerbose(logging);
        DalvikModule dm = vm
                .loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/Fatdog/liblotus.so"), false);
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
        Kl2 test = new Kl2(true);

        try {
            test.hookFunc();

            // 获取 Java 层对应的类
            DvmClass ku2 = test.vm.resolveClass("com/fatdog/reverse/Ku2");

            // 创建该类的实例
            DvmObject<?> obj = ku2.newObject(null);

            // 调用 nativeForge(int)，参数示例为 123
            Number result = obj.callJniMethodInt(
                    test.emulator,
                    "nativeForge(I)I",
                    0x20260202);

            System.out.println("Java 层拿到的返回值: " + result);
        } finally {
            test.destroy();
        }
    }

    public void hookFunc() {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                if (address == module.base + 0x0774) {// hook的目标地址
                    long a3 = backend.reg_read(
                            Arm64Const.UC_ARM64_REG_X2).longValue();

                    // a3 在 C 函数中是 int，取低 32 位
                    int value = (int) a3;

                    System.out.println("进入 sub_774");
                    System.out.println("参数 a3 = " + value);
                    System.out.printf("参数 a3 (hex) = 0x%x%n", value);

                } else if (address == module.base + 0x0794) {
                    long ret = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                    System.out.println("返回值（十进制）: " + ret);
                    System.out.printf("返回值（十六进制）: 0x%x%n", ret);
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                // 这里可以进行一些初始化工作
                System.out.println("attach");
            }

            @Override
            public void detach() {
                // 这里可以进行一些收尾工作
                System.out.println("detach");
            }
        }, module.base + 0x0774/* start */, module.base + 0x0794/* end */, emulator);
    }
}