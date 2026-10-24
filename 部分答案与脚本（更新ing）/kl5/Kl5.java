package com.Fatdog.kl5;

import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.IntArray;
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

public class Kl5 {

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
            if (signature.equals("com/fatdog/reverse/Ku5->baseMark()Ljava/lang/String;")) {
                int[] iArr = { 70, 97, 116, 100, 111, 103, 95 };
                StringBuilder sb = new StringBuilder(7);
                for (int i = 0; i < 7; i++) {
                    sb.append((char) iArr[i]);
                }
                return new StringObject(vm, sb.toString());
            }

            if (signature.equals("com/fatdog/reverse/Ku4->saltPlan()[I")) {
                return new IntArray(vm, new int[] {
                        7994, 11851, 15708, 19565, 23422
                });
            }

            if (signature.equals("com/fatdog/reverse/Ku5->routePlan()[I")) {
                return new IntArray(vm, new int[]{287454020, 590628182, 876959335, 1163290488, 1449621641, 1735952794});
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

            if ("com/fatdog/reverse/Ku5->climbSeed()I"
                    .equals(signature)) {
                return 539362565;
            }

            return super.callStaticIntMethodV(
                    vm, dvmClass, signature, vaList);
        }

        @Override
        public long callStaticLongMethodV(
                BaseVM vm,
                DvmClass dvmClass,
                String signature,
                VaList vaList) {

            if ("com/fatdog/reverse/Ku5->peakStamp()J"
                    .equals(signature)) {
                return 1311768467750121217L;
            }

            return super.callStaticIntMethodV(
                    vm, dvmClass, signature, vaList);
        }

        @Override
        public DvmObject<?> getStaticObjectField(
                BaseVM vm,
                DvmClass dvmClass,
                String signature) {
            if (signature.equals("com/fatdog/reverse/Ku5->SUMMIT_TAG:Ljava/lang/String;")) {
                return new StringObject(vm,"kunlun_ridge");
            }
            return super.getStaticObjectField(vm, dvmClass, signature);
        }

    }

    Kl5(boolean logging) {
        this.logging = logging;

        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.fatdog.reverse.kl5")
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
        new
        File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl5/libquarry.so"),
        false);

        DalvikModule cinder = vm.loadLibrary(
        new
        File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl5/libridge.so"),
        false);

        DalvikModule drift = vm.loadLibrary(
        new
        File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl5/libshard.so"),
        false);

        DalvikModule elder = vm.loadLibrary(
        new
        File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl5/libtalus.so"),
        false);

        DalvikModule fable = vm.loadLibrary(
        new
        File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl5/libverge.so"),
        false);

        DalvikModule dm = vm
                .loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/Fatdog/kl5/libspire.so"),
                        false);
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
        Kl5 test = new Kl5(true);

        try {
            test.byPassUnicorn();
            test.byPassTraceid();
            test.byPassCmdline();
            test.nativeClimb();
        } finally {
            test.destroy();
        }
    }

    public void byPassUnicorn() {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                if (address == module.base + 0x338C) {// hook的目标地址

                }

                if (address == module.base + 0x349C) {
                    long before = backend.reg_read(
                            Arm64Const.UC_ARM64_REG_X0).longValue();

                    // 将 probe_maps() 的返回值设置为 0
                    backend.reg_write(
                            Arm64Const.UC_ARM64_REG_X0, 0);

                    long after = backend.reg_read(
                            Arm64Const.UC_ARM64_REG_X0).longValue();

                    System.out.printf(
                            "[Hook] probe_maps 返回值修改前：0x%x，修改后：0x%x%n",
                            before, after);
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                // 这里可以进行一些初始化工作
                System.out.println("unicorn检测函数已被劫持");
            }

            @Override
            public void detach() {
                // 这里可以进行一些收尾工作
                System.out.println("伪装完成，成功绕过unicorn检测");
            }
        }, module.base + 0x338C/* start */, module.base + 0x349C/* end */, emulator);
    }

    public void byPassTraceid() {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                if (address == module.base + 0x34AC) {// hook的目标地址

                }
                if (address == module.base + 0x3580) {
                    long before = backend.reg_read(
                            Arm64Const.UC_ARM64_REG_X0).longValue();

                    System.out.printf(
                            "[Hook] probe_tracer 返回值修改前：0x%x%n",
                            before);

                    backend.reg_write(
                            Arm64Const.UC_ARM64_REG_X0, 0);

                    long after = backend.reg_read(
                            Arm64Const.UC_ARM64_REG_X0).longValue();

                    System.out.printf(
                            "[Hook] probe_tracer 返回值修改后：0x%x%n",
                            after);
                }

            }

            @Override
            public void onAttach(UnHook unHook) {
                // 这里可以进行一些初始化工作
                System.out.println("调试器检测函数已被劫持");
            }

            @Override
            public void detach() {
                // 这里可以进行一些收尾工作
                System.out.println("伪装完成，成功绕过调试器检测");
            }
        }, module.base + 0x34AC/* start */, module.base + 0x3580/* end */, emulator);
    }

    public void byPassCmdline() {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                RegisterContext context = emulator.getContext();
                if (address == module.base + 0x3588) {// hook的目标地址

                }
                if (address == module.base + 0x364C) {
                    long before = backend.reg_read(
                            Arm64Const.UC_ARM64_REG_X0).longValue();

                    System.out.printf(
                            "[Hook] probe_cmdline 返回值修改前：0x%x%n",
                            before);

                    backend.reg_write(
                            Arm64Const.UC_ARM64_REG_X0, 0);

                    long after = backend.reg_read(
                            Arm64Const.UC_ARM64_REG_X0).longValue();

                    System.out.printf(
                            "[Hook] probe_cmdline 返回值修改后：0x%x%n",
                            after);
                }

            }

            @Override
            public void onAttach(UnHook unHook) {
                // 这里可以进行一些初始化工作
                System.out.println("调试器检测函数已被劫持");
            }

            @Override
            public void detach() {
                // 这里可以进行一些收尾工作
                System.out.println("伪装完成，成功绕过调试器检测");
            }
        }, module.base + 0x3588/* start */, module.base + 0x364C/* end */, emulator);
    }

    public void nativeClimb() {
        DvmClass Ku5 = vm.resolveClass("com.fatdog.reverse.Ku5");

        DvmObject<?> result = Ku5.callStaticJniMethodObject(emulator, "nativeClimb(IIIIIIIICIJ)Ljava/lang/String;");

        System.out.println("result = " +
                (result == null ? "null" : result.getValue()));
    }
}