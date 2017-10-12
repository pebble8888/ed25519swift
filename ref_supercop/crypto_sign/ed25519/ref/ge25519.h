#ifndef GE25519_H
#define GE25519_H

#include "fe25519.h"
#include "sc25519.h"

typedef struct ge25519
{
  fe25519 x;
  fe25519 y;
  fe25519 z;
  fe25519 t;
} ge25519;

//const ge25519 ge25519_base;

#ifdef __cplusplus
extern "C" {
#endif
int ge25519_unpackneg_vartime(ge25519 *r, const unsigned char p[32]);
void ge25519_pack(unsigned char r[32], const ge25519 *p);
int ge25519_isneutral_vartime(const ge25519 *p);
void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const sc25519 *s1, const ge25519 *p2, const sc25519 *s2);
void ge25519_scalarmult_base(ge25519 *r, const sc25519 *s);
    
unsigned char equal_i8(signed char b,signed char c);
unsigned char negative(signed char b);

#ifdef __cplusplus
}
#endif

#endif
