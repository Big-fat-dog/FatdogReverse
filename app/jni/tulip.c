#include <jni.h>
#include <string.h>
#include <stdio.h>

unsigned short K5_B[] = {0x0073,0x0075,0x006d,0x006d,0x0069,0x0074};

static const unsigned char ENC_FLAG[] = {
        0x35,0x14,0x19,0x09,0x06,0x13,0x00,0x1c,0x13,0x32,0x06,0x1c,0x1a,0x2a,0x14,0x1a,0x3b,0x5d,0x57,0x6d,0x45
};

static unsigned char g_result[64];
static int g_result_len = 0;

JNIEXPORT jstring JNICALL
Java_com_fatdog_reverse_Ku5_nativeClimb(JNIEnv *env, jclass clazz, jint seed) {
    jmethodID mid = (*env)->GetStaticMethodID(env, clazz, "summitKey", "()Ljava/lang/String;");
    if (!mid) return (*env)->NewStringUTF(env, "ERR_NO_CALLBACK");
    jstring ja = (jstring)(*env)->CallStaticObjectMethod(env, clazz, mid);
    if (!ja) return (*env)->NewStringUTF(env, "ERR_NULL");
    const char *a = (*env)->GetStringUTFChars(env, ja, NULL);
    if (!a) { (*env)->DeleteLocalRef(env, ja); return (*env)->NewStringUTF(env, "ERR_UTF"); }
    char key[32];
    strncpy(key, a, sizeof(key)-1);
    key[sizeof(key)-1] = 0;
    size_t alen = strlen(key);
    int i;
    for (i = 0; i < 6; i++) key[alen+i] = (char)(K5_B[i] & 0xFF);
    key[alen+6] = 0;
    (*env)->ReleaseStringUTFChars(env, ja, a);
    (*env)->DeleteLocalRef(env, ja);
    size_t klen = strlen(key);
    g_result_len = (int)sizeof(ENC_FLAG);
    for (i = 0; i < g_result_len; i++)
        g_result[i] = ENC_FLAG[i] ^ (unsigned char)(key[i % klen]);
    g_result[g_result_len] = 0;
    return (*env)->NewStringUTF(env, (const char *)g_result);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;(void)reserved;
    return JNI_VERSION_1_6;
}
