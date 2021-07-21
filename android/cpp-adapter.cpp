#include <jni.h>
#include <stdexcept>

#include "options.h"
#include "rand.h"
#include "sha2.h"
#include "sha3.h"
#include "ripemd160.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "bip39.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "bignum.h"

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

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_mnemonicToSeedNative(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jstring mnemonic,
  const jstring passphrase
) {
  const char *raw_mnemonic = env->GetStringUTFChars(mnemonic, 0);
  const char *raw_passphrase = env->GetStringUTFChars(passphrase, 0);
  jbyte *seed = (jbyte *) malloc(SHA512_DIGEST_LENGTH);

  mnemonic_to_seed(raw_mnemonic, raw_passphrase, reinterpret_cast<uint8_t *>(seed), 0);

  jbyteArray result = env->NewByteArray(SHA512_DIGEST_LENGTH);
  env->SetByteArrayRegion(result, 0, SHA512_DIGEST_LENGTH, seed);
  free(seed);

  return result;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_generateMnemonicNative(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jint strength
) {
  return env->NewStringUTF(mnemonic_generate((int)strength));
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_validateMnemonicNative(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jstring mnemonic
) {
  return (jint) mnemonic_check(env->GetStringUTFChars(mnemonic, (jboolean *)false));
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_ecdsaRandomPrivateNative(
  JNIEnv *env,
  __attribute__((unused)) jclass type
) {
  uint8_t *priv = (uint8_t *) malloc(32);
  bignum256 p;

  while(true) {
    random_buffer(priv, 32);
    bn_read_be(priv, &p);

    if (!bn_is_zero(&p) && bn_is_less(&p, &secp256k1.order)) {
      break;
    }
  }
  
  jbyteArray result = env->NewByteArray(32);
  env->SetByteArrayRegion(result, 0, 32, (const jbyte *)priv);
  free(priv);

  return result;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_ecdsaValidatePublicNative(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jbyteArray pub
) {
  curve_point pub_point;

  jsize pub_length = env->GetArrayLength(pub);
  if (pub_length != 33 && pub_length != 65) {
    return 0;
  }

  jbyte *raw_pub = env->GetByteArrayElements(pub, (jboolean *)false);

  return ecdsa_read_pubkey(&secp256k1, (const uint8_t *)raw_pub, &pub_point);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_ecdsaValidatePrivateNative(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jbyteArray priv
) {
  jsize key_length = env->GetArrayLength(priv);
  if (key_length != 32) {
    return 0;
  }

  jbyte *raw_priv = env->GetByteArrayElements(priv, (jboolean *)false);

  bignum256 p;
  bn_read_be((const uint8_t *)raw_priv, &p);

  if (bn_is_zero(&p) || (!bn_is_less(&p, &secp256k1.order))) {
    return 0;
  }
  
  return 1;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_ecdsaGetPublic33Native(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jbyteArray priv
) {
  uint8_t pub_size = 33;
  jsize key_length = env->GetArrayLength(priv);
  if (key_length != 32) {
    return NULL;
  }

  jbyte *raw_priv = env->GetByteArrayElements(priv, (jboolean *)false);

  uint8_t *pub = (uint8_t *) malloc(pub_size);
  ecdsa_get_public_key33(&secp256k1, (const uint8_t *)raw_priv, pub);
  
  jbyteArray result = env->NewByteArray(pub_size);
  env->SetByteArrayRegion(result, 0, pub_size, (const jbyte *)pub);
  free(pub);

  return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_reactnativecryptolib_CryptoLibModule_ecdsaGetPublic65Native(
  JNIEnv *env,
  __attribute__((unused)) jclass type,
  const jbyteArray priv
) {
  uint8_t pub_size = 65;
  jsize key_length = env->GetArrayLength(priv);
  if (key_length != 32) {
    return NULL;
  }

  jbyte *raw_priv = env->GetByteArrayElements(priv, (jboolean *)false);

  uint8_t *pub = (uint8_t *) malloc(pub_size);
  ecdsa_get_public_key65(&secp256k1, (const uint8_t *)raw_priv, pub);
  
  jbyteArray result = env->NewByteArray(pub_size);
  env->SetByteArrayRegion(result, 0, pub_size, (const jbyte *)pub);
  free(pub);

  return result;
}
