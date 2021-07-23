#import <React/RCTBridgeModule.h>

typedef enum {
  SHA1,
  SHA256,
  SHA512,
  SHA3_256,
  SHA3_512,
  KECCAK_256,
  KECCAK_512,
  RIPEMD160,
  HASH256,
  HASH160
} HASH_TYPE;

typedef enum {
  DERIVE_PRIVATE,
  DERIVE_PUBLIC
} DERIVE_TYPE;

@interface CryptoLib : NSObject <RCTBridgeModule>

@end
