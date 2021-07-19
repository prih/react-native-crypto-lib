#import "CryptoLib.h"

#import "options.h"
#import "rand.h"
#import "sha2.h"
#import "sha3.h"

@implementation CryptoLib

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

RCT_REMAP_METHOD(sha1,
                 withDataForSHA1:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];
    uint8_t *hash = (uint8_t *) malloc(SHA1_DIGEST_LENGTH);

    sha1_Raw([raw_data bytes], [raw_data length], hash);

    NSData *result = [NSData dataWithBytes:hash length:SHA1_DIGEST_LENGTH];
    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_REMAP_METHOD(sha256,
                 withDataForSHA256:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];
    uint8_t *hash = (uint8_t *) malloc(SHA256_DIGEST_LENGTH);

    sha256_Raw([raw_data bytes], [raw_data length], hash);

    NSData *result = [NSData dataWithBytes:hash length:SHA256_DIGEST_LENGTH];
    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_REMAP_METHOD(sha512,
                 withDataForSHA512:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];
    uint8_t *hash = (uint8_t *) malloc(SHA512_DIGEST_LENGTH);

    sha512_Raw([raw_data bytes], [raw_data length], hash);

    NSData *result = [NSData dataWithBytes:hash length:SHA512_DIGEST_LENGTH];
    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_REMAP_METHOD(sha3_256,
                 withDataForSHA3_256:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];
    uint8_t *hash = (uint8_t *) malloc(SHA3_256_DIGEST_LENGTH);

    sha3_256([raw_data bytes], [raw_data length], hash);

    NSData *result = [NSData dataWithBytes:hash length:SHA3_256_DIGEST_LENGTH];
    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_REMAP_METHOD(sha3_512,
                 withDataForSHA3_512:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];
    uint8_t *hash = (uint8_t *) malloc(SHA3_512_DIGEST_LENGTH);

    sha3_512([raw_data bytes], [raw_data length], hash);

    NSData *result = [NSData dataWithBytes:hash length:SHA3_512_DIGEST_LENGTH];
    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_REMAP_METHOD(keccak_256,
                 withDataForKeccak_256:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];
    uint8_t *hash = (uint8_t *) malloc(SHA3_256_DIGEST_LENGTH);

    keccak_256([raw_data bytes], [raw_data length], hash);

    NSData *result = [NSData dataWithBytes:hash length:SHA3_256_DIGEST_LENGTH];
    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_REMAP_METHOD(keccak_512,
                 withDataForKeccak_512:(NSString *)data
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];
    uint8_t *hash = (uint8_t *) malloc(SHA3_512_DIGEST_LENGTH);

    keccak_512([raw_data bytes], [raw_data length], hash);

    NSData *result = [NSData dataWithBytes:hash length:SHA3_512_DIGEST_LENGTH];
    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

@end
