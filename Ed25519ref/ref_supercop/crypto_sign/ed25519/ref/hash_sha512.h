//
//  Created by pebble8888 on 2017/10/14.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

#ifndef hash_sha512_h
#define hash_sha512_h

#include <stdio.h>

void crypto_hash_sha512(unsigned char *out,
                        const unsigned char *in,
                        unsigned long long inlen);

#endif /* hash_sha512_h */
