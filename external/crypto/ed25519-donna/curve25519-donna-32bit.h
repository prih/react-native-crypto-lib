/*
	Public domain by Andrew M. <liquidsun@gmail.com>
	See: https://github.com/floodyberry/curve25519-donna

	32 bit integer curve25519 implementation
*/

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t bignum25519[10];

/* out = in */
void curve25519_copy(bignum25519 out, const bignum25519 in);

/* out = a + b */
void curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b);

void curve25519_add_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b);

void curve25519_add_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b);

/* out = a - b */
void curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b);

/* out = in * scalar */
void curve25519_scalar_product(bignum25519 out, const bignum25519 in, const uint32_t scalar);

/* out = a - b, where a is the result of a basic op (add,sub) */
void curve25519_sub_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b);

void curve25519_sub_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b);

/* out = -a */
void curve25519_neg(bignum25519 out, const bignum25519 a);

/* out = a * b */
#define curve25519_mul_noinline curve25519_mul
void curve25519_mul(bignum25519 out, const bignum25519 a, const bignum25519 b);

/* out = in * in */
void curve25519_square(bignum25519 out, const bignum25519 in);

/* out = in ^ (2 * count) */
void curve25519_square_times(bignum25519 out, const bignum25519 in, int count);

/* Take a little-endian, 32-byte number and expand it into polynomial form */
void curve25519_expand(bignum25519 out, const unsigned char in[32]);

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
void curve25519_contract(unsigned char out[32], const bignum25519 in);

/* if (iswap) swap(a, b) */
void curve25519_swap_conditional(bignum25519 a, bignum25519 b, uint32_t iswap);

/* uint32_t to Zmod(2^255-19) */
void curve25519_set(bignum25519 r, uint32_t x);

/* set d */
void curve25519_set_d(bignum25519 r);

/* set 2d */
void curve25519_set_2d(bignum25519 r);

/* set sqrt(-1) */
void curve25519_set_sqrtneg1(bignum25519 r);

/* constant time Zmod(2^255-19) negative test */
int curve25519_isnegative(const bignum25519 f);

/* constant time Zmod(2^255-19) non-zero test */
int curve25519_isnonzero(const bignum25519 f);

/* reduce Zmod(2^255-19) */
void curve25519_reduce(bignum25519 r, const bignum25519 in);

void curve25519_divpowm1(bignum25519 r, const bignum25519 u, const bignum25519 v);

/* Zmod(2^255-19) from byte array to bignum25519 expansion with modular reduction */
void curve25519_expand_reduce(bignum25519 out, const unsigned char in[32]);

#ifdef __cplusplus
} // extern "C"
#endif
