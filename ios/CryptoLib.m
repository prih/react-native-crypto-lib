#import "CryptoLib.h"

#import "options.h"
#import "rand.h"
#import "sha2.h"
#import "sha3.h"
#import "ripemd160.h"
#import "hmac.h"
#import "pbkdf2.h"
#import "bip39.h"

@implementation CryptoLib

typedef enum {
  SHA1,
  SHA256,
  SHA512,
  SHA3_256,
  SHA3_512,
  KECCAK_256,
  KECCAK_512,
  RIPEMD160,
} HASH_TYPE;

typedef enum {
  HMAC_SHA256,
  HMAC_SHA512
} HMAC_TYPE;

RCT_EXPORT_MODULE()

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(randomNumber)
{
  return [NSNumber numberWithUnsignedInt:random32()];
}

RCT_EXPORT_METHOD(randomBytes:(int)length 
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    uint8_t *bytes = (uint8_t *) malloc(length);
    random_buffer(bytes, length);

    NSData *result = [NSData dataWithBytes:bytes length:length];

    free(bytes);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(randomBytesSync:(int)length)
{
  uint8_t *bytes = (uint8_t *) malloc(length);
  random_buffer(bytes, length);

  NSData *result = [NSData dataWithBytes:bytes length:length];

  free(bytes);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hash:(int)algorithm
  withData:(NSString *)data
)
{
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];

  uint8_t *hash;
  NSData *result;

  switch(algorithm){
    case SHA1:
      hash = (uint8_t *) malloc(SHA1_DIGEST_LENGTH);
      sha1_Raw([raw_data bytes], [raw_data length], hash);
      result = [NSData dataWithBytes:hash length:SHA1_DIGEST_LENGTH];
      break;
    case SHA256:
      hash = (uint8_t *) malloc(SHA256_DIGEST_LENGTH);
      sha256_Raw([raw_data bytes], [raw_data length], hash);
      result = [NSData dataWithBytes:hash length:SHA256_DIGEST_LENGTH];
      break;
    case SHA512:
      hash = (uint8_t *) malloc(SHA512_DIGEST_LENGTH);
      sha1_Raw([raw_data bytes], [raw_data length], hash);
      result = [NSData dataWithBytes:hash length:SHA512_DIGEST_LENGTH];
      break;
    case SHA3_256:
      hash = (uint8_t *) malloc(SHA3_256_DIGEST_LENGTH);
      sha3_512([raw_data bytes], [raw_data length], hash);
      result = [NSData dataWithBytes:hash length:SHA3_256_DIGEST_LENGTH];
      break;
    case SHA3_512:
      hash = (uint8_t *) malloc(SHA3_512_DIGEST_LENGTH);
      sha3_512([raw_data bytes], [raw_data length], hash);
      result = [NSData dataWithBytes:hash length:SHA3_512_DIGEST_LENGTH];
      break;
    case KECCAK_256:
      hash = (uint8_t *) malloc(SHA3_256_DIGEST_LENGTH);
      keccak_256([raw_data bytes], [raw_data length], hash);
      result = [NSData dataWithBytes:hash length:SHA3_256_DIGEST_LENGTH];
      break;
    case KECCAK_512:
      hash = (uint8_t *) malloc(SHA3_512_DIGEST_LENGTH);
      keccak_512([raw_data bytes], [raw_data length], hash);
      result = [NSData dataWithBytes:hash length:SHA3_512_DIGEST_LENGTH];
      break;
    case RIPEMD160:
      hash = (uint8_t *) malloc(RIPEMD160_DIGEST_LENGTH);
      ripemd160([raw_data bytes], [raw_data length], hash);
      result = [NSData dataWithBytes:hash length:RIPEMD160_DIGEST_LENGTH];
      break;
    
    default:
      return nil;
  }

  free(hash);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hmac:(int)algorithm
  withKey:(NSString *)key
  withData:(NSString *)data
)
{
  NSData *raw_key = [[NSData alloc]initWithBase64EncodedString:key options:0];
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];

  uint8_t *hmac;
  NSData *result;

  switch(algorithm){
    case HMAC_SHA256:
      hmac = (uint8_t *) malloc(SHA256_DIGEST_LENGTH);
      hmac_sha256([raw_key bytes], [raw_key length], [raw_data bytes], [raw_data length], hmac);
      result = [NSData dataWithBytes:hmac length:SHA256_DIGEST_LENGTH];
      break;
    case HMAC_SHA512:
      hmac = (uint8_t *) malloc(SHA512_DIGEST_LENGTH);
      hmac_sha512([raw_key bytes], [raw_key length], [raw_data bytes], [raw_data length], hmac);
      result = [NSData dataWithBytes:hmac length:SHA512_DIGEST_LENGTH];
      break;
    default:
      return nil;
  }

  free(hmac);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_METHOD(
  pbkdf2:(int)algorithm
  withPass:(NSString *)pass
  withSalt:(NSString *)salt
  withIterations:(int)iterations
  withKeyLength:(int)keyLength
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_pass = [[NSData alloc]initWithBase64EncodedString:pass options:0];
    NSData *raw_salt = [[NSData alloc]initWithBase64EncodedString:salt options:0];

    uint8_t *hash;
    NSData *result;

    switch(algorithm){
      case HMAC_SHA256:
        hash = (uint8_t *) malloc(keyLength);
        pbkdf2_hmac_sha256(
          [raw_pass bytes], [raw_pass length],
          [raw_salt bytes], [raw_salt length],
          iterations,
          hash, keyLength
        );
        result = [NSData dataWithBytes:hash length:keyLength];
        break;
      case HMAC_SHA512:
        hash = (uint8_t *) malloc(keyLength);
        pbkdf2_hmac_sha512(
          [raw_pass bytes], [raw_pass length],
          [raw_salt bytes], [raw_salt length],
          iterations,
          hash, keyLength
        );
        result = [NSData dataWithBytes:hash length:keyLength];
        break;
      default:
        reject(@"Error", @"unknown hash type", nil);
        return;
    }

    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  pbkdf2Sync:(int)algorithm
  withPass:(NSString *)pass
  withSalt:(NSString *)salt
  withIterations:(int)iterations
  withKeyLength:(int)keyLength
)
{
  NSData *raw_pass = [[NSData alloc]initWithBase64EncodedString:pass options:0];
  NSData *raw_salt = [[NSData alloc]initWithBase64EncodedString:salt options:0];

  uint8_t *hash;
  NSData *result;

  switch(algorithm){
    case HMAC_SHA256:
      hash = (uint8_t *) malloc(keyLength);
      pbkdf2_hmac_sha256(
        [raw_pass bytes], [raw_pass length],
        [raw_salt bytes], [raw_salt length],
        iterations,
        hash, keyLength
      );
      result = [NSData dataWithBytes:hash length:keyLength];
      break;
    case HMAC_SHA512:
      hash = (uint8_t *) malloc(keyLength);
      pbkdf2_hmac_sha512(
        [raw_pass bytes], [raw_pass length],
        [raw_salt bytes], [raw_salt length],
        iterations,
        hash, keyLength
      );
      result = [NSData dataWithBytes:hash length:keyLength];
      break;
    default:
      return nil;
  }

  free(hash);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_METHOD(mnemonicToSeed:(NSString *)mnemonic
  withPassphrase:(NSString *)passphrase
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    uint8_t *seed = (uint8_t *) malloc(SHA512_DIGEST_LENGTH);
    mnemonic_to_seed([mnemonic UTF8String], [passphrase UTF8String], seed, 0);
    NSData *result = [NSData dataWithBytes:seed length:SHA512_DIGEST_LENGTH];
    free(seed);

    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  mnemonicToSeedSync:(NSString *)mnemonic
  withPassphrase:(NSString *)passphrase
)
{
  uint8_t *seed = (uint8_t *) malloc(SHA512_DIGEST_LENGTH);
  mnemonic_to_seed([mnemonic UTF8String], [passphrase UTF8String], seed, 0);
  NSData *result = [NSData dataWithBytes:seed length:SHA512_DIGEST_LENGTH];
  free(seed);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  generateMnemonic:(int)strength
)
{
  char *mnemonic = mnemonic_generate(strength);
  return [NSString stringWithUTF8String:mnemonic];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  validateMnemonic:(NSString *)mnemonic
)
{
  int result = mnemonic_check([mnemonic UTF8String]);
  return [NSNumber numberWithInt: result];
}

@end
