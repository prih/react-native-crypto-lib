#import "CryptoLib.h"

#import "rand.h"

@implementation CryptoLib

RCT_EXPORT_MODULE()

RCT_REMAP_METHOD(randomNumber,
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  NSNumber *result = [NSNumber numberWithUnsignedInt:random32()];
  resolve(result);
}

@end
