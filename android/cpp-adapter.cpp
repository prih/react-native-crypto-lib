#include <jni.h>

#include "rand.h"

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomNumber(JNIEnv *env, jclass type) {
  return random32();
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomBytes(JNIEnv *env, jclass type, jint length) {
  uint8_t bytes[length];
  random_buffer(bytes, length);

  jbyteArray result;
  result = env->NewByteArray(length);
  env->SetByteArrayRegion(result, 0, length, reinterpret_cast<const jbyte*>(bytes));

  return result;
}
