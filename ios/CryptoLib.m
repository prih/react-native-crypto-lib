#import "CryptoLib.h"

#import "options.h"
#import "rand.h"
#import "sha2.h"
#import "sha3.h"
#import "ripemd160.h"
#import "hmac.h"
#import "pbkdf2.h"
#import "bip39.h"
#import "ecdsa.h"
#import "secp256k1.h"
#import "bignum.h"
#import "memzero.h"
#import "bip32.h"

@implementation CryptoLib

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
      ripemd160([raw_data bytes], (uint32_t)[raw_data length], hash);
      result = [NSData dataWithBytes:hash length:RIPEMD160_DIGEST_LENGTH];
      break;
    case HASH256:
      hash = (uint8_t *) malloc(SHA256_DIGEST_LENGTH);
      sha256_Raw([raw_data bytes], [raw_data length], hash);
      sha256_Raw(hash, SHA256_DIGEST_LENGTH, hash);
      result = [NSData dataWithBytes:hash length:SHA256_DIGEST_LENGTH];
      break;
    case HASH160:
      hash = (uint8_t *) malloc(RIPEMD160_DIGEST_LENGTH);
      uint8_t tmp[SHA256_DIGEST_LENGTH];

      sha256_Raw([raw_data bytes], [raw_data length], (uint8_t *)&tmp);
      ripemd160((uint8_t *)&tmp, SHA256_DIGEST_LENGTH, hash);
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
    case SHA256:
      hmac = (uint8_t *) malloc(SHA256_DIGEST_LENGTH);
      hmac_sha256([raw_key bytes], (uint32_t)[raw_key length], [raw_data bytes], (uint32_t)[raw_data length], hmac);
      result = [NSData dataWithBytes:hmac length:SHA256_DIGEST_LENGTH];
      break;
    case SHA512:
      hmac = (uint8_t *) malloc(SHA512_DIGEST_LENGTH);
      hmac_sha512([raw_key bytes], (uint32_t)[raw_key length], [raw_data bytes], (uint32_t)[raw_data length], hmac);
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
      case SHA256:
        hash = (uint8_t *) malloc(keyLength);
        pbkdf2_hmac_sha256(
          [raw_pass bytes], (uint32_t)[raw_pass length],
          [raw_salt bytes], (uint32_t)[raw_salt length],
          iterations,
          hash, keyLength
        );
        result = [NSData dataWithBytes:hash length:keyLength];
        break;
      case SHA512:
        hash = (uint8_t *) malloc(keyLength);
        pbkdf2_hmac_sha512(
          [raw_pass bytes], (uint32_t)[raw_pass length],
          [raw_salt bytes], (uint32_t)[raw_salt length],
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
    case SHA256:
      hash = (uint8_t *) malloc(keyLength);
      pbkdf2_hmac_sha256(
        [raw_pass bytes], (uint32_t)[raw_pass length],
        [raw_salt bytes], (uint32_t)[raw_salt length],
        iterations,
        hash, keyLength
      );
      result = [NSData dataWithBytes:hash length:keyLength];
      break;
    case SHA512:
      hash = (uint8_t *) malloc(keyLength);
      pbkdf2_hmac_sha512(
        [raw_pass bytes], (uint32_t)[raw_pass length],
        [raw_salt bytes], (uint32_t)[raw_salt length],
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
  const char *mnemonic = mnemonic_generate((uint32_t)strength);
  return [NSString stringWithUTF8String:mnemonic];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  validateMnemonic:(NSString *)mnemonic
)
{
  int result = mnemonic_check([mnemonic UTF8String]);
  return [NSNumber numberWithInt: result];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(ecdsaRandomPrivate)
{
  uint8_t *priv = (uint8_t *) malloc(32);
  bignum256 p = {0};

  while(true) {
    random_buffer(priv, 32);
    bn_read_be(priv, &p);

    if (!bn_is_zero(&p) && bn_is_less(&p, &secp256k1.order)) {
      break;
    }
  }

  NSData *result = [NSData dataWithBytes:priv length:32];
  
  free(priv);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaReadPublic:(NSString *)pub
  withCompact:(int)compact
)
{
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  
  curve_point pub_point = {0};
  uint8_t *pub_key;

  uint32_t pub_length = (uint32_t)[raw_pub length];
  if (pub_length != 33 && pub_length != 65) {
    @throw [NSException exceptionWithName:@"Error" reason:@"read publicKey error" userInfo:nil];
  }

  if (!ecdsa_read_pubkey(&secp256k1, [raw_pub bytes], &pub_point)) {
    @throw [NSException exceptionWithName:@"Error" reason:@"read publicKey error" userInfo:nil];
  }

  NSData *result;

  if (compact == 0) {
    pub_key = (uint8_t *) malloc(65);
    pub_key[0] = 4;
    bn_write_be(&pub_point.x, pub_key + 1);
    bn_write_be(&pub_point.y, pub_key + 33);

    result = [NSData dataWithBytes:pub_key length:65];
    free(pub_key);
  } else {
    pub_key = (uint8_t *) malloc(33);
    pub_key[0] = 0x02 | (pub_point.y.val[0] & 0x01);
    bn_write_be(&pub_point.x, pub_key + 1);

    result = [NSData dataWithBytes:pub_key length:33];
    free(pub_key);
  }
  
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaValidatePublic:(NSString *)pub
)
{
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  curve_point pub_point = {0};

  uint32_t pub_length = (uint32_t)[raw_pub length];
  if (pub_length != 33 && pub_length != 65) {
    return [NSNumber numberWithInt: 0];
  }

  int result = ecdsa_read_pubkey(&secp256k1, [raw_pub bytes], &pub_point);
  return [NSNumber numberWithInt: result];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaValidatePrivate:(NSString *)priv
)
{
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  if ([raw_priv length] != 32) {
    return [NSNumber numberWithInt: 0];
  }

  bignum256 p = {0};
  bn_read_be([raw_priv bytes], &p);

  if (bn_is_zero(&p) || (!bn_is_less(&p, &secp256k1.order))) {
    return [NSNumber numberWithInt: 0];
  }
  
  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaGetPublic33:(NSString *)priv
)
{
  uint8_t pub_size = 33;
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  if ([raw_priv length] != 32) {
    @throw [NSException exceptionWithName:@"keySizeError" reason:@"wrong key size" userInfo:nil];
  }

  uint8_t *pub = (uint8_t *) malloc(pub_size);
  ecdsa_get_public_key33(&secp256k1, [raw_priv bytes], pub);

  NSData *result = [NSData dataWithBytes:pub length:pub_size];
  
  free(pub);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaGetPublic65:(NSString *)priv
)
{
  uint8_t pub_size = 65;
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  if ([raw_priv length] != 32) {
    @throw [NSException exceptionWithName:@"keySizeError" reason:@"wrong key size" userInfo:nil];
  }

  uint8_t *pub = (uint8_t *) malloc(pub_size);
  ecdsa_get_public_key65(&secp256k1, [raw_priv bytes], pub);

  NSData *result = [NSData dataWithBytes:pub length:pub_size];
  
  free(pub);
  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaRecover:(NSString *)sig
  withDigest:(NSString *)digest
  withRecid:(int)recid
  withCompact:(int)compact
)
{
  NSData *raw_sig = [[NSData alloc]initWithBase64EncodedString:sig options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  if ([raw_sig length] != 64) {
    @throw [NSException exceptionWithName:@"sigSizeError" reason:@"wrong sig size" userInfo:nil];
  }

  if ([raw_digest length] != 32) {
    @throw [NSException exceptionWithName:@"digestSizeError" reason:@"wrong digest size" userInfo:nil];
  }

  uint8_t *pub = (uint8_t *) malloc(65);
  int err = ecdsa_recover_pub_from_sig(&secp256k1, pub, [raw_sig bytes], [raw_digest bytes], recid);

  if (err > 0) {
    free(pub);
    @throw [NSException exceptionWithName:@"recoverError" reason:@"recover error" userInfo:nil];
  }

  NSData *result;

  if (compact == 0) {
    result = [NSData dataWithBytes:pub length:65];
    free(pub);
  } else {
    uint8_t *pub_compact = (uint8_t *) malloc(33);

    curve_point p = {0};
    bn_read_be(pub + 1, &(p.x));
    bn_read_be(pub + 33, &(p.y));

    pub_compact[0] = 0x02 | (p.y.val[0] & 0x01);
    bn_write_be(&p.x, pub_compact + 1);
    memzero(&p, sizeof(p));

    result = [NSData dataWithBytes:pub_compact length:33];
    free(pub);
    free(pub_compact);
  }

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaEcdh:(NSString *)pub
  withPriv:(NSString *)priv
  withCompact:(int)compact
)
{
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];

  if ([raw_pub length] != 33 && [raw_pub length] != 65) {
    @throw [NSException exceptionWithName:@"keySizeError" reason:@"wrong key size" userInfo:nil];
  }

  if ([raw_priv length] != 32) {
    @throw [NSException exceptionWithName:@"keySizeError" reason:@"wrong key size" userInfo:nil];
  }

  uint8_t *ecdh = (uint8_t *) malloc(65);
  int err = ecdh_multiply(&secp256k1, [raw_priv bytes], [raw_pub bytes], ecdh);

  if (err > 0) {
    free(ecdh);
    @throw [NSException exceptionWithName:@"ecdhError" reason:@"ecdh error" userInfo:nil];
  }

  NSData *result;

  if (compact == 0) {
    result = [NSData dataWithBytes:ecdh length:65];
    free(ecdh);
  } else {
    uint8_t *ecdh_compact = (uint8_t *) malloc(33);

    curve_point p = {0};
    bn_read_be(ecdh + 1, &(p.x));
    bn_read_be(ecdh + 33, &(p.y));

    ecdh_compact[0] = 0x02 | (p.y.val[0] & 0x01);
    bn_write_be(&(p.x), ecdh_compact + 1);
    memzero(&p, sizeof(p));

    result = [NSData dataWithBytes:ecdh_compact length:33];
    free(ecdh);
    free(ecdh_compact);
  }

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaVerify:(NSString *)pub
  withSig:(NSString *)sig
  withDigest:(NSString *)digest
)
{
  NSData *raw_pub = [[NSData alloc]initWithBase64EncodedString:pub options:0];
  NSData *raw_sig = [[NSData alloc]initWithBase64EncodedString:sig options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  if ([raw_pub length] != 33 && [raw_pub length] != 65) {
    @throw [NSException exceptionWithName:@"keySizeError" reason:@"wrong key size" userInfo:nil];
  }

  if ([raw_sig length] != 64) {
    @throw [NSException exceptionWithName:@"sigSizeError" reason:@"wrong sig size" userInfo:nil];
  }

  if ([raw_digest length] != 32) {
    @throw [NSException exceptionWithName:@"digestSizeError" reason:@"wrong digest size" userInfo:nil];
  }

  int err = ecdsa_verify_digest(&secp256k1, [raw_pub bytes], [raw_sig bytes], [raw_digest bytes]);

  if (err != 0) {
    return [NSNumber numberWithInt: 0];
  }

  return [NSNumber numberWithInt: 1];
}

RCT_EXPORT_METHOD(
  ecdsaSign:(NSString *)priv
  withDigest:(NSString *)digest
  resolver:(RCTPromiseResolveBlock)resolve
  rejecter:(RCTPromiseRejectBlock)reject
)
{
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];
    NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

    if ([raw_priv length] != 32) {
      reject(@"Error", @"wrong priv size", nil);
      return;
    }

    if ([raw_digest length] != 32) {
      reject(@"Error", @"wrong digest size", nil);
      return;
    }

    uint8_t *sig = (uint8_t *) malloc(65);
    int err = ecdsa_sign_digest(&secp256k1, [raw_priv bytes], [raw_digest bytes], sig + 1, sig, 0);

    if (err > 0) {
      free(sig);
      reject(@"Error", @"sign error", nil);
      return;
    }

    NSData *result = [NSData dataWithBytes:sig length:65];
    free(sig);

    resolve([result base64EncodedStringWithOptions:0]);
  });
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  ecdsaSignSync:(NSString *)priv
  withDigest:(NSString *)digest
)
{
  NSData *raw_priv = [[NSData alloc]initWithBase64EncodedString:priv options:0];
  NSData *raw_digest = [[NSData alloc]initWithBase64EncodedString:digest options:0];

  if ([raw_priv length] != 32) {
    @throw [NSException exceptionWithName:@"privSizeError" reason:@"wrong priv size" userInfo:nil];
  }

  if ([raw_digest length] != 32) {
    @throw [NSException exceptionWithName:@"digestSizeError" reason:@"wrong digest size" userInfo:nil];
  }

  uint8_t *sig = (uint8_t *) malloc(65);
  int err = ecdsa_sign_digest(&secp256k1, [raw_priv bytes], [raw_digest bytes], sig + 1, sig, 0);

  if (err > 0) {
    free(sig);
    @throw [NSException exceptionWithName:@"signError" reason:@"sign error" userInfo:nil];
  }

  NSData *result = [NSData dataWithBytes:sig length:65];
  free(sig);

  return [result base64EncodedStringWithOptions:0];
}

#pragma pack(push, 1)
typedef struct {
  uint32_t depth;
  uint32_t child_num;
  uint8_t chain_code[32];
  uint8_t private_key[32];
  uint8_t public_key[33];
  uint32_t fingerprint;
} HDNodeData;
#pragma pack(pop)

void hdnode_read_data(HDNode *node, HDNodeData *data) {
  uint32_t fp = hdnode_fingerprint(node);

  memcpy(&(data->depth), &(node->depth), sizeof(node->depth));
  memcpy(&(data->child_num), &(node->child_num), sizeof(node->child_num));
  memcpy(&(data->chain_code), &(node->chain_code), sizeof(node->chain_code));
  memcpy(&(data->private_key), &(node->private_key), sizeof(node->private_key));
  memcpy(&(data->public_key), &(node->public_key), sizeof(node->public_key));
  memcpy(&(data->fingerprint), &fp, sizeof(fp));
  fp = 0;
}

void hdnode_write_data(HDNode *node, HDNodeData *data) {
  memcpy(&(node->depth), &(data->depth), sizeof(node->depth));
  memcpy(&(node->child_num), &(data->child_num), sizeof(node->child_num));
  memcpy(&(node->chain_code), &(data->chain_code), sizeof(node->chain_code));
  memcpy(&(node->private_key), &(data->private_key), sizeof(node->private_key));
  memcpy(&(node->public_key), &(data->public_key), sizeof(node->public_key));
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hdNodeFromSeed:(NSString *)seed
)
{
  NSData *raw_seed = [[NSData alloc]initWithBase64EncodedString:seed options:0];

  if ([raw_seed length] != 64) {
    @throw [NSException exceptionWithName:@"Error" reason:@"wrong seed size" userInfo:nil];
  }

  HDNode node = {0};
  const char *curve = "secp256k1";
  int success = hdnode_from_seed([raw_seed bytes], [raw_seed length], curve, &node);
  memzero((void *)[raw_seed bytes], [raw_seed length]);

  if (success != 1) {
    memzero(&node, sizeof(node));
    @throw [NSException exceptionWithName:@"Error" reason:@"seed error" userInfo:nil];
  }

  HDNodeData data = {0};
  hdnode_read_data(&node, &data);

  NSData *result = [NSData dataWithBytes:&data length:sizeof(data)];

  memzero(&node, sizeof(node));
  memzero(&data, sizeof(data));

  return [result base64EncodedStringWithOptions:0];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(
  hdNodeDerive:(int)derive_type
  withData:(NSString *)node_data
  withIndex:(int)index
)
{
  NSData *raw_data = [[NSData alloc]initWithBase64EncodedString:node_data options:0];

  if ([raw_data length] != sizeof(HDNodeData)) {
    @throw [NSException exceptionWithName:@"Error" reason:@"wrong data size" userInfo:nil];
  }

  HDNodeData *data = (HDNodeData *)[raw_data bytes];

  const char *curve = "secp256k1";
  HDNode node = {};
  hdnode_write_data(&node, data);
  node.curve = get_curve_by_name(curve);

  int success = 0;

  if (derive_type == DERIVE_PRIVATE) {
    success = hdnode_private_ckd(&node, index);
  } else {
    success = hdnode_public_ckd(&node, index);
  }

  if (success != 1) {
    memzero(&node, sizeof(node));
    memzero(data, sizeof(HDNodeData));
    @throw [NSException exceptionWithName:@"Error" reason:@"derive error" userInfo:nil];
  }

  hdnode_read_data(&node, data);

  NSData *result = [NSData dataWithBytes:data length:sizeof(*data)];

  memzero(&node, sizeof(node));
  memzero(data, sizeof(HDNodeData));

  return [result base64EncodedStringWithOptions:0];
}

@end
