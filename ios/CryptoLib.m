#import "CryptoLib.h"

#import "rand.h"

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
    uint8_t bytes[length];
    random_buffer(&bytes, length);

    NSData *result = [NSData dataWithBytes:bytes length:length];

    resolve([result base64EncodedStringWithOptions:0]);
  });
}

@end
