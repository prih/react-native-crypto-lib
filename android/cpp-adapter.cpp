#include <jni.h>

#include "options.h"
#include "rand.h"
#include "sha2.h"
#include "sha3.h"
#include "ripemd160.h"

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomNumber() {
  return random32();
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomBytes(JNIEnv *env, __attribute__((unused)) jclass type, jint length) {
  jbyte *bytes = (jbyte *) malloc(length);
  random_buffer(reinterpret_cast<uint8_t *>(bytes), length);

  jbyteArray result;
  result = env->NewByteArray(length);
  env->SetByteArrayRegion(result, 0, length, bytes);

  free(bytes);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_sha1(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte *hash = (jbyte *) malloc(SHA1_DIGEST_LENGTH);

  sha1_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA1_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA1_DIGEST_LENGTH, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_sha256(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte *hash = (jbyte *) malloc(SHA256_DIGEST_LENGTH);

  sha256_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA256_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA256_DIGEST_LENGTH, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_sha512(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte *hash = (jbyte *) malloc(SHA512_DIGEST_LENGTH);

  sha512_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA512_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA512_DIGEST_LENGTH, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_sha3_1256(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte *hash = (jbyte *) malloc(SHA3_256_DIGEST_LENGTH);

  sha3_256(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA3_256_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA3_256_DIGEST_LENGTH, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_sha3_1512(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte *hash = (jbyte *) malloc(SHA3_512_DIGEST_LENGTH);

  sha3_512(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA3_512_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA3_512_DIGEST_LENGTH, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_keccak_1256(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte *hash = (jbyte *) malloc(SHA3_256_DIGEST_LENGTH);

  keccak_256(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA3_256_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA3_256_DIGEST_LENGTH, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_keccak_1512(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte *hash = (jbyte *) malloc(SHA3_512_DIGEST_LENGTH);

  keccak_512(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(SHA3_512_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA3_512_DIGEST_LENGTH, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_ripemd160(JNIEnv *env, __attribute__((unused)) jclass type, jbyteArray data) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, 0);
  jbyte *hash = (jbyte *) malloc(RIPEMD160_DIGEST_LENGTH);

  ripemd160(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));

  jbyteArray result;
  result = env->NewByteArray(RIPEMD160_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, RIPEMD160_DIGEST_LENGTH, hash);

  free(hash);

  return result;
}
