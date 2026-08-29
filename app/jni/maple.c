#include <jni.h>
#include <string.h>
#include <stdio.h>

/* 后半密钥 "raven"，非 const 全局防折叠 */
unsigned short KEY3_B[] = {0x0072,0x0061,0x0076,0x0065,0x006e};

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ku3_nativeKey(JNIEnv *env, jclass clazz) {
    /* 跨层回调：向 Java 的 Ku3.halfA() 索取前半密钥 */
    jmethodID mid = (*env)->GetStaticMethodID(env, clazz, "halfA", "()Ljava/lang/String;");
    if (!mid) return (*env)->NewStringUTF(env, "ERR_NO_METHOD");

    jstring ja = (jstring)(*env)->CallStaticObjectMethod(env, clazz, mid);
    if (!ja) return (*env)->NewStringUTF(env, "ERR_NULL_RET");

    const char *a = (*env)->GetStringUTFChars(env, ja, NULL);
    if (!a) { (*env)->DeleteLocalRef(env, ja); return (*env)->NewStringUTF(env, "ERR_UTF"); }

    char key[32];
    strncpy(key, a, sizeof(key)-1);
    key[sizeof(key)-1] = '\0';
    size_t alen = strlen(key);

    int i;
    for (i = 0; i < 5; i++) key[alen+i] = (char)(KEY3_B[i] & 0xFF);
    key[alen+5] = '\0';

    (*env)->ReleaseStringUTFChars(env, ja, a);
    (*env)->DeleteLocalRef(env, ja);
    return (*env)->NewStringUTF(env, key);
}
