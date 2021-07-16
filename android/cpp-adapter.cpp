#include <jni.h>

#include "rand.h"

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomNumber(JNIEnv *env, jclass type) {
  return random32();
}
