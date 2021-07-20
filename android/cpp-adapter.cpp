#include <jni.h>
#include <stdexcept>

#include "options.h"
#include "rand.h"
#include "sha2.h"
#include "sha3.h"
#include "ripemd160.h"
#include "hmac.h"
#include "pbkdf2.h"

enum HASH_TYPE {
  SHA1,
  SHA256,
  SHA512,
  SHA3_256,
  SHA3_512,
  KECCAK_256,
  KECCAK_512,
  RIPEMD160,
};

enum HMAC_TYPE {
  HMAC_SHA256,
  HMAC_SHA512,
};

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomNumberNative() {
  return random32();
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_randomBytesNative(JNIEnv *env, __attribute__((unused)) jclass type, jint length) {
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
Java_com_reactnativecryptolib_CryptoLibModule_hashNative(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jint algorithm,
  jbyteArray data
) {
  jsize num_bytes = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, (jboolean *)false);
  
  jbyte *hash = {0};
  jsize hash_length = 0;

  switch (algorithm)
  {
    case SHA1:
      hash_length = SHA1_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      sha1_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));
      break;
    case SHA256:
      hash_length = SHA256_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      sha256_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));
      break;
    case SHA512:
      hash_length = SHA512_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      sha512_Raw(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));
      break;
    case SHA3_256:
      hash_length = SHA3_256_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      sha3_256(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));
      break;
    case SHA3_512:
      hash_length = SHA3_512_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      sha3_512(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));
      break;
    case KECCAK_256:
      hash_length = SHA3_256_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      keccak_256(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));
      break;
    case KECCAK_512:
      hash_length = SHA3_512_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      keccak_512(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));
      break;
    case RIPEMD160:
      hash_length = RIPEMD160_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      ripemd160(reinterpret_cast<uint8_t *>(raw_data), num_bytes, reinterpret_cast<uint8_t *>(hash));
      break;
    
    default:
      throw std::invalid_argument("unknown hash type");
      break;
  }
  
  jbyteArray result = env->NewByteArray(hash_length);
  env->SetByteArrayRegion(result, 0, hash_length, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_hmacNative(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jint algorithm,
  jbyteArray key,
  jbyteArray data
) {
  jsize key_length = env->GetArrayLength(key);
  jbyte *raw_key = env->GetByteArrayElements(key, (jboolean *)false);
  jsize data_length = env->GetArrayLength(data);
  jbyte *raw_data = env->GetByteArrayElements(data, (jboolean *)false);
  
  jbyte *hash = {0};
  jsize hash_length = 0;

  switch (algorithm)
  {
    case HMAC_SHA256:
      hash_length = SHA256_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      hmac_sha256(
        reinterpret_cast<uint8_t *>(raw_key), key_length,
        reinterpret_cast<uint8_t *>(raw_data), data_length,
        reinterpret_cast<uint8_t *>(hash)
      );
      break;
    case HMAC_SHA512:
      hash_length = SHA512_DIGEST_LENGTH;
      hash = (jbyte *) malloc(hash_length);
      hmac_sha512(
        reinterpret_cast<uint8_t *>(raw_key), key_length,
        reinterpret_cast<uint8_t *>(raw_data), data_length,
        reinterpret_cast<uint8_t *>(hash)
      );
      break;
    
    default:
      throw std::invalid_argument("unknown hash type");
      break;
  }
  
  jbyteArray result = env->NewByteArray(hash_length);
  env->SetByteArrayRegion(result, 0, hash_length, hash);

  free(hash);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_pbkdf2Native(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  jint algorithm,
  jbyteArray pass,
  jbyteArray salt,
  jint iterations,
  jint keyLength
) {
  jsize pass_length = env->GetArrayLength(pass);
  jbyte *raw_pass = env->GetByteArrayElements(pass, (jboolean *)false);
  jsize salt_length = env->GetArrayLength(salt);
  jbyte *raw_salt = env->GetByteArrayElements(salt, (jboolean *)false);
  
  jbyte *hash = (jbyte *) malloc(keyLength);

  switch (algorithm)
  {
    case HMAC_SHA256:
      pbkdf2_hmac_sha256(
        reinterpret_cast<uint8_t *>(raw_pass), pass_length,
        reinterpret_cast<uint8_t *>(raw_salt), salt_length,
        iterations,
        reinterpret_cast<uint8_t *>(hash), keyLength
      );
      break;
    case HMAC_SHA512:
      pbkdf2_hmac_sha512(
        reinterpret_cast<uint8_t *>(raw_pass), pass_length,
        reinterpret_cast<uint8_t *>(raw_salt), salt_length,
        iterations,
        reinterpret_cast<uint8_t *>(hash), keyLength
      );
      break;
    
    default:
      throw std::invalid_argument("unknown hash type");
      break;
  }
  
  jbyteArray result = env->NewByteArray(keyLength);
  env->SetByteArrayRegion(result, 0, keyLength, hash);

  free(hash);
  return result;
}
