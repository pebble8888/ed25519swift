#include <string.h>
#include "ge25519.h"
#include "hash_sha512.h"

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
  // az is 64 bytes
  crypto_hash_sha512(az,sk,32);
  //
  az[0] &= 248;
  az[31] &= 127;
  az[31] |= 64;

  // sm = R 32 bytes + S 32bytes + ...

  *smlen = mlen + 64; // out length
  memmove(sm + 64, m, mlen);
  memmove(sm + 32, az + 32, 32);
  /* sm: 32-byte uninit, 32-byte z, mlen-byte m */

  crypto_hash_sha512(nonce, sm + 32, mlen+32);
  /* nonce: 64-byte H(z,m) */
    
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
