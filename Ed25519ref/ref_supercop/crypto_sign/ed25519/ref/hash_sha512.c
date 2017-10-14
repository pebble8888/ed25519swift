//
//  Created by pebble8888 on 2017/10/14.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

#include "hash_sha512.h"
#include <CommonCrypto/CommonDigest.h>

void crypto_hash_sha512(unsigned char *out,
                               const unsigned char *in,
                               unsigned long long inlen)
{
    CC_SHA512(in, (CC_LONG)inlen, out);
}
