#import "CryptoLib.h"

#import "options.h"
#import "rand.h"
#import "sha2.h"
#import "sha3.h"
#import "ripemd160.h"
#import "hmac.h"

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

RCT_REMAP_METHOD(randomNumber,
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSNumber *result = [NSNumber numberWithUnsignedInt:random32()];
    resolve(result);
  });
}

RCT_REMAP_METHOD(randomBytes,
                 withLength:(int)length
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    uint8_t *bytes = (uint8_t *) malloc(length);
    random_buffer(bytes, length);

    NSData *result = [NSData dataWithBytes:bytes length:length];

    free(bytes);

    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_REMAP_METHOD(hash,
                 withHashType:(int)algorithm
                 withData:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
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
        reject(@"Error", @"unknown hash type", nil);
        return;
    }

    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_REMAP_METHOD(hmac,
                 withHashType:(int)algorithm
                 withKey:(NSString *)key
                 withData:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
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
        reject(@"Error", @"unknown hash type", nil);
        return;
    }

    free(hmac);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

@end
