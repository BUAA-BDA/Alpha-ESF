/*
 * This is written by Lulu Han.
 * E-mail: locomotive_crypto@163.com
 */

#ifndef HEENC_TOOLS_H
#define HEENC_TOOLS_H

#include <NTL/ZZ.h>

void rsa_param(NTL::ZZ& p, NTL::ZZ& q, long bitlens);

void dl_param(NTL::ZZ& p, NTL::ZZ& g, long mod_bitlens, long group_bitlens);

#endif // HEENC_TOOLS_H
