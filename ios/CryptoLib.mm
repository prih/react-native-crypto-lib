#import "CryptoLib.h"

#import "memzero.h"
#import "bip32.h"

@implementation CryptoLib
RCT_EXPORT_MODULE()

RCT_REMAP_METHOD(randomNumber,
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
  NSNumber *result = @(cryptolib::randomNumber());

  resolve(result);
}

RCT_EXPORT_METHOD(randomBytes:(int)length 
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
  uint8_t *bytes = (uint8_t *) malloc(length);
  cryptolib::randomBytes(bytes, length);

  NSData *result = [NSData dataWithBytes:bytes length:length];

  free(bytes);
  resolve([result base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hash:(int)algorithm
  withData:(NSString *)data)
{
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];

  size_t hashSize = 0;
  uint8_t *hash;
  NSData *result;

  switch(algorithm){
    case SHA1:
    case RIPEMD160:
    case HASH160:
      hashSize = 20;
      break;
    case SHA256:
    case SHA3_256:
    case KECCAK_256:
    case HASH256:
      hashSize = 32;
      break;
    case SHA512:
    case SHA3_512:
    case KECCAK_512:
      hashSize = 64;
      break;
    
    default:
      return nil;
  }

  hash = (uint8_t *) malloc(hashSize);
  cryptolib::hash((HASH_TYPE) algorithm, (uint8_t *)[raw_data bytes], [raw_data length], hash);
  
  result = [NSData dataWithBytes:hash length:hashSize];

  free(hash);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hmac:(int)algorithm
  withKey:(NSString *)key
  withData:(NSString *)data)
{
  NSData *raw_key = [[NSData alloc]initWithBase64EncodedString:key options:0];
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:data options:0];

  size_t hashSize = 0;
  uint8_t *hash;
  NSData *result;

  switch(algorithm){
    case SHA256:
      hashSize = 32;
      break;
    case SHA512:
      hashSize = 64;
      break;
    
    default:
      return nil;
  }

  hash = (uint8_t *) malloc(hashSize);
  cryptolib::hmac(
    (HASH_TYPE) algorithm,
    (uint8_t *)[raw_key bytes],
    [raw_key length],
    (uint8_t *)[raw_data bytes],
    [raw_data length],
    hash
  );
  
  result = [NSData dataWithBytes:hash length:hashSize];

  free(hash);
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

    uint8_t *hash = (uint8_t *) malloc(keyLength);

    cryptolib::pbkdf2(
      (HASH_TYPE) algorithm,
      (uint8_t *)[raw_pass bytes], (uint32_t)[raw_pass length],
      (uint8_t *)[raw_salt bytes], (uint32_t)[raw_salt length],
      (uint32_t) iterations,
      hash, keyLength
    );

    NSData *result = [NSData dataWithBytes:hash length:keyLength];

    free(hash);
    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_EXPORT_METHOD(mnemonicToSeed:(NSString *)mnemonic
  withPassphrase:(NSString *)passphrase
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    uint8_t *seed = (uint8_t *) malloc(64);
    cryptolib::mnemonicToSeed([mnemonic UTF8String], [passphrase UTF8String], seed);
    NSData *result = [NSData dataWithBytes:seed length:64];
    free(seed);

    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_EXPORT_METHOD(
  generateMnemonic:(int)strength
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
) {
  const char *mnemonic = cryptolib::generateMnemonic((uint32_t)strength);
  resolve([NSString stringWithUTF8String:mnemonic]);
}

RCT_EXPORT_METHOD(
  validateMnemonic:(NSString *)mnemonic
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
) {
  int result = cryptolib::validateMnemonic([mnemonic UTF8String]);
  resolve([NSNumber numberWithInt: result]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hdNodeFromSeed:(NSString *)curve
  withSeed:(NSString *)seed
) {
  NSData *raw_seed = [[NSData alloc]initWithBase64EncodedString:seed options:0];
  HDNode node = {0};

  int success = hdnode_from_seed((const uint8_t *)[raw_seed bytes], [raw_seed length], [curve UTF8String], &node);
  memzero((void *)[raw_seed bytes], [raw_seed length]);

  if (success != 1) {
    memzero(&node, sizeof(HDNode));
    @throw [NSException exceptionWithName:@"Error" reason:@"seed error" userInfo:nil];
  }

  uint32_t fp = hdnode_fingerprint(&node);

  NSDictionary *result = @{
    @"depth": [NSNumber numberWithUnsignedInt: node.depth],
    @"child_num": [NSNumber numberWithUnsignedInt: node.child_num],
    @"chain_code": [
      [NSData dataWithBytes: node.chain_code length: sizeof(node.chain_code)]
      base64EncodedStringWithOptions:0
    ],
    @"private_key": [
      [NSData dataWithBytes: node.private_key length: sizeof(node.private_key)]
      base64EncodedStringWithOptions:0
    ],
    @"public_key": [
      [NSData dataWithBytes: node.public_key length: sizeof(node.public_key)]
      base64EncodedStringWithOptions:0
    ],
    @"fingerprint": [NSNumber numberWithUnsignedInt: fp],
    @"curve": curve,
    @"private_derive": @true,
  };

  memzero(&node, sizeof(HDNode));
  fp = 0;

  return result;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hdNodeDerive:(NSDictionary *)data
  withIndex:(NSArray *)path
) {
  HDNode node = {};
  
  if (data[@"depth"]) {
    node.depth = [data[@"depth"] unsignedIntValue];
  }

  if (data[@"child_num"]) {
    node.child_num = [data[@"child_num"] unsignedIntValue];
  }

  if (data[@"chain_code"]) {
    NSData *chain_code = [[NSData alloc] initWithBase64EncodedString:data[@"chain_code"] options:0];
    if ([chain_code length] == sizeof(node.chain_code)) {
      memcpy(&node.chain_code, [chain_code bytes], sizeof(node.chain_code));
    }
  }

  if (data[@"private_key"]) {
    NSData *private_key = [[NSData alloc] initWithBase64EncodedString:data[@"private_key"] options:0];
    if ([private_key length] == sizeof(node.private_key)) {
      memcpy(&node.private_key, [private_key bytes], sizeof(node.private_key));
    }
  }

  if (data[@"public_key"]) {
    NSData *public_key = [[NSData alloc] initWithBase64EncodedString:data[@"public_key"] options:0];
    if ([public_key length] == sizeof(node.public_key)) {
      memcpy(&node.public_key, [public_key bytes], sizeof(node.public_key));
    }
  }

  if (data[@"curve"]) {
    node.curve = get_curve_by_name([data[@"curve"] UTF8String]);
  }
    
  BOOL private_derive = [data[@"private_derive"] boolValue];
    
  int success = 0;
  
  for (int i = 0; i < [path count]; i++) {
    uint32_t index = [[path objectAtIndex:i] unsignedIntValue];
    
    if (private_derive) {
      success = hdnode_private_ckd(&node, index);
      if (success == 1) {
        hdnode_fill_public_key(&node);
      }
    } else {
      success = hdnode_public_ckd(&node, index);
    }
    
    if (success != 1) {
      memzero(&node, sizeof(HDNode));
      @throw [NSException exceptionWithName:@"Error" reason:@"derive error" userInfo:nil];
    }
  }

  uint32_t fp = hdnode_fingerprint(&node);

  NSDictionary *result = @{
    @"depth": [NSNumber numberWithUnsignedInt: node.depth],
    @"child_num": [NSNumber numberWithUnsignedInt: node.child_num],
    @"chain_code": [
      [NSData dataWithBytes: node.chain_code length: sizeof(node.chain_code)]
      base64EncodedStringWithOptions:0
    ],
    @"private_key": [
      [NSData dataWithBytes: node.private_key length: sizeof(node.private_key)]
      base64EncodedStringWithOptions:0
    ],
    @"public_key": [
      [NSData dataWithBytes: node.public_key length: sizeof(node.public_key)]
      base64EncodedStringWithOptions:0
    ],
    @"fingerprint": [NSNumber numberWithUnsignedInt: fp],
    @"curve": data[@"curve"],
    @"private_derive": @(private_derive),
  };

  memzero(&node, sizeof(HDNode));
  fp = 0;

  return result;
}

RCT_REMAP_METHOD(
  ecdsaRandomPrivate,
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
) {
  uint8_t *priv = (uint8_t *) malloc(ECDSA_KEY_SIZE);
  
  cryptolib::ecdsaRandomPrivate(priv);

  NSData *result = [NSData dataWithBytes:priv length:ECDSA_KEY_SIZE];
  
  memzero(priv, sizeof(ECDSA_KEY_SIZE));
  free(priv);

  resolve([result base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaValidatePrivate:(NSString *)priv
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  if ([raw_priv length] != ECDSA_KEY_SIZE) {
    return [NSNumber numberWithInt: 0];
  }
    
  if (!cryptolib::ecdsaValidatePrivate((uint8_t *)[raw_priv bytes])) {
    return [NSNumber numberWithInt: 0];
  }
  
  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaGetPublic:(NSString *)priv
  withCompact:(BOOL)compact
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  uint8_t *pub;
  int pub_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  pub = (uint8_t *) malloc(pub_size);

  if (!cryptolib::ecdsaGetPublic((uint8_t *)[raw_priv bytes], pub, compact)) {
    @throw [NSException exceptionWithName:@"Error" reason:@"pub key error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:pub length:pub_size];
  
  memzero(pub, sizeof(pub_size));
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  free(pub);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaReadPublic:(NSString *)pub
  withCompact:(BOOL)compact
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];

  uint8_t *out_pub;
  int pub_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  out_pub = (uint8_t *) malloc(pub_size);

  if (!cryptolib::ecdsaReadPublic((uint8_t *)[raw_pub bytes], out_pub, compact)) {
    @throw [NSException exceptionWithName:@"Error" reason:@"pub key error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:out_pub length:pub_size];
  
  memzero(out_pub, sizeof(pub_size));
  memzero((void *)[raw_pub bytes], [raw_pub length]);
  free(out_pub);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaValidatePublic:(NSString *)pub
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];

  if ([raw_pub length] != ECDSA_KEY_33_SIZE && [raw_pub length] != ECDSA_KEY_65_SIZE) {
    return [NSNumber numberWithInt: 0];
  }

  if (!cryptolib::ecdsaValidatePublic((uint8_t *)[raw_pub bytes])) {
    return [NSNumber numberWithInt: 0];
  }

  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaRecover:(NSString *)sig
  withRecId:(int)recId
  withDigest:(NSString *)digest
) {
  NSData *raw_sig = [[NSData alloc]initWithBase64EncodedString:sig options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  uint8_t *pub = (uint8_t *) malloc(ECDSA_KEY_65_SIZE);

  if (!cryptolib::ecdsaRecover((uint8_t *)[raw_sig bytes], recId, (uint8_t *)[raw_digest bytes], pub)) {
    @throw [NSException exceptionWithName:@"Error" reason:@"recover error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:pub length:ECDSA_KEY_65_SIZE];
  
  free(pub);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaEcdh:(NSString *)pub
  withPriv:(NSString *)priv
  withCompact:(BOOL)compact
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  int ecdh_size = compact ? ECDSA_KEY_33_SIZE : ECDSA_KEY_65_SIZE;

  uint8_t *ecdh = (uint8_t *) malloc(ecdh_size);

  if (!cryptolib::ecdsaEcdh((uint8_t *)[raw_pub bytes], (uint8_t *)[raw_priv bytes], ecdh, compact)) {
    @throw [NSException exceptionWithName:@"Error" reason:@"ecdh error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:ecdh length:ecdh_size];
  
  memzero(ecdh, sizeof(ecdh_size));
  memzero((void *)[raw_pub bytes], [raw_pub length]);
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  free(ecdh);

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaVerify:(NSString *)pub
  withSign:(NSString *)sign
  withDigest:(NSString *)digest
) {
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_sign = [[NSData alloc]initWithBase64EncodedString:sign options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  if (!cryptolib::ecdsaVerify(
    (uint8_t *)[raw_pub bytes],
    (uint8_t *)[raw_sign bytes],
    (uint8_t *)[raw_digest bytes]
  )) {
    return [NSNumber numberWithInt: 0];
  }

  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaSign:(NSString *)priv
  withDigest:(NSString *)digest
) {
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  uint8_t *sign = (uint8_t *) malloc(ECDSA_SIGN_SIZE);

  if (!cryptolib::ecdsaSign((uint8_t *)[raw_priv bytes], (uint8_t *)[raw_digest bytes], sign)) {
    @throw [NSException exceptionWithName:@"Error" reason:@"sign error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:sign length:ECDSA_SIGN_SIZE];
  
  memzero(sign, sizeof(ECDSA_SIGN_SIZE));
  memzero((void *)[raw_priv bytes], [raw_priv length]);
  memzero((void *)[raw_digest bytes], [raw_digest length]);
  free(sign);

  return [result base64EncodedStringWithOptions:0];
}


@end
