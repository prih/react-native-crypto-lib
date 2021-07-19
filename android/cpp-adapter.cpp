#include <jni.h>

#include "rand.h"
#include "sha2.h"

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomNumber() {
  return random32();
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomBytes(JNIEnv *env, __attribute__((unused)) jclass type, jint length) {
  jbyte bytes[length];
  random_buffer(reinterpret_cast<uint8_t *>(bytes), length);

  jbyteArray result;
  result = env->NewByteArray(length);
  env->SetByteArrayRegion(result, 0, length, bytes);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_sha1(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte hash[SHA1_DIGEST_LENGTH];

  sha1_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA1_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA1_DIGEST_LENGTH, hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_sha256(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte hash[SHA256_DIGEST_LENGTH];

  sha256_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA256_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA256_DIGEST_LENGTH, hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_sha512(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte hash[SHA512_DIGEST_LENGTH];

  sha512_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA512_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA512_DIGEST_LENGTH, hash);

  return result;
}
