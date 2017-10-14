//
//  open.h
//  Ed25519
//
//  Created by pebble8888 on 2017/10/14.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

#ifndef open_h
#define open_h
int crypto_sign_open(
                     unsigned char *m,unsigned long long *mlen,
                     const unsigned char *sm,unsigned long long smlen,
                     const unsigned char *pk
                     );

#endif /* open_h */
