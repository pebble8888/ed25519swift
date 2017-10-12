#include <string.h>
//#include "crypto_sign.h"
//#include "crypto_hash_sha512.h"
#include "ge25519.h"
#include <CommonCrypto/CommonDigest.h>

static void crypto_hash_sha512(unsigned char *out,
                               const unsigned char *in,
                               unsigned long long inlen)
{
    CC_SHA512(in, (CC_LONG)inlen, out);
}

int crypto_sign(
    unsigned char *sm,unsigned long long *smlen, /* out */
    const unsigned char *m,unsigned long long mlen, /* message */
    const unsigned char *sk /* sk 32byte + pk 32byte */
    )
{
  unsigned char pk[32];
  unsigned char az[64];
  unsigned char nonce[64];
  unsigned char hram[64];

  /* pk: 32-byte public key A */
  memmove(pk,sk + 32,32);

  /* az: 32-byte scalar a, 32-byte randomizer z */
  // azは64バイト
  crypto_hash_sha512(az,sk,32);
  // 整える
  az[0] &= 248;
  az[31] &= 127;
  az[31] |= 64;

  // az -> s

  // mlen = 0

  // sm は 先頭32バイトR, 次の32バイトS, ...  

  *smlen = mlen + 64; // out length
  memmove(sm + 64, m, mlen);
  memmove(sm + 32, az + 32, 32);
  /* sm: 32-byte uninit, 32-byte z, mlen-byte m */

  crypto_hash_sha512(nonce, sm + 32, mlen+32);
  /* nonce: 64-byte H(z,m) */
    
    printf("nonce:\n");
    for (int i = 0; i < 64; ++i){
        printf("%d ", nonce[i]);
    }

  sc25519 sck;
  sc25519_from64bytes(&sck, nonce);

  /* sm: 32-byte R, 32-byte z, mlen-byte m */
  ge25519 ger;
  ge25519_scalarmult_base(&ger, &sck);
    
  ge25519_pack(sm, &ger);
  
  /* sm: 32-byte R, 32-byte A, mlen-byte m */
  memmove(sm + 32,pk,32);

  /* hram: 64-byte H(R,A,m) */
  crypto_hash_sha512(hram,sm,mlen + 64);

  sc25519 scs;
  sc25519_from64bytes(&scs, hram);

  sc25519 scsk;
  sc25519_from32bytes(&scsk, az);

  sc25519_mul(&scs, &scs, &scsk);
  sc25519_add(&scs, &scs, &sck);
  /* scs: S = nonce + H(R,A,m)a */

  sc25519_to32bytes(sm + 32,&scs);
  /* sm: 32-byte R, 32-byte S, mlen-byte m */

  return 0;
}
