//
//  sign.h
//  Ed25519
//
//  Created by pebble8888 on 2017/10/12.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

#ifndef sign_h
#define sign_h

int crypto_sign(
                unsigned char *sm,unsigned long long *smlen, /* out */
                const unsigned char *m,unsigned long long mlen, /* message */
                const unsigned char *sk /* sk 32byte + pk 32byte */
);

#endif /* sign_h */
