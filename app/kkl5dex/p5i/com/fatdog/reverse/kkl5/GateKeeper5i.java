package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5i —— VM 还原指纹校验。
 * 内存机解释器跑完后，输出指纹必须齐全（步数、是否正常 HALT）。
 */
public final class GateKeeper5i {

    private GateKeeper5i() {}

    /** onCreate 还原链路自检：VMP 解释器输出的指纹必须齐全。 */
    public static boolean gateLooksValid(int vmSteps, boolean halted) {
        return halted && vmSteps >= 100;
    }
}
