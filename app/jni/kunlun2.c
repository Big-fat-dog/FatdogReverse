#include <jni.h>

static jint k2_forge_impl(JNIEnv *env, jclass clazz, jint seed) {
    unsigned int x = (unsigned int) seed;
    x = x * 0x41C64E6Du + 0x3039u;
    x = (x >> 16) ^ x;
    x = x * 0x45D9F3Bu;
    return (jint) x;
}

JNIEXPORT jint JNICALL
Java_com_fatdog_reverse_Ku2_nativeForge(JNIEnv *env, jclass clazz, jint seed) {
    (void) env; (void) clazz;
    return seed ^ 0x0000DEAD;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jclass cls;
    JNINativeMethod ms[1];
    (void) reserved;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    cls = (*env)->FindClass(env, "com/fatdog/reverse/Ku2");
    if (cls == NULL) return JNI_ERR;
    ms[0].name      = "nativeForge";
    ms[0].signature = "(I)I";
    ms[0].fnPtr     = (void *) k2_forge_impl;
    if ((*env)->RegisterNatives(env, cls, ms, 1) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
