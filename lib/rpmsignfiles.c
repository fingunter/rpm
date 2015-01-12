/**
 * Copyright (C) 2014 IBM Corporation
 *
 * Author: Fionnuala Gunter <fin@linux.vnet.ibm.com>
 */

#include "system.h"
#include "imaevm.h"

#include <rpm/rpmlog.h>		/* rpmlog */
#include <rpm/rpmstring.h>	/* rnibble */
#include <rpm/rpmpgp.h>		/* rpmDigestLength */
#include "lib/header.h"		/* HEADERGET_MINMEM */
#include "lib/rpmtypes.h"	/* rpmRC */

#include "lib/rpmsignfiles.h"

#define MAX_SIGNATURE_LENGTH 1024

static const char *hash_algo_name[] = {
    [PGPHASHALGO_MD5]          = "md5",
    [PGPHASHALGO_SHA1]         = "sha1",
    [PGPHASHALGO_RIPEMD160]    = "rmd160",
    [PGPHASHALGO_MD2]          = "md2",
    [PGPHASHALGO_TIGER192]     = "tgr192",
    [PGPHASHALGO_HAVAL_5_160]  = "haval5160",
    [PGPHASHALGO_SHA256]       = "sha256",
    [PGPHASHALGO_SHA384]       = "sha384",
    [PGPHASHALGO_SHA512]       = "sha512",
    [PGPHASHALGO_SHA224]       = "sha224",
};

static char *signFile(const char *algo, const char *fdigest, int diglen, const char *key)
{
   char *fsignature;
   unsigned char digest[diglen];
   unsigned char signature[MAX_SIGNATURE_LENGTH];
   int siglen;

#ifndef IMAEVM
    rpmlog(RPMLOG_ERR, _("missing libimaevm\n"));
    return NULL;
#endif

   /* convert file digest hex to binary */
   memset(digest, 0, diglen);
   for (int i = 0; i < diglen; ++i, fdigest += 2)
        digest[i] = (rnibble(fdigest[0]) << 4) | rnibble(fdigest[1]);

   /* prepare file signature */
   memset(signature, 0, MAX_SIGNATURE_LENGTH);
   signature[0] = '\x03';

   /* calculate file signature */
   siglen = sign_hash(algo, digest, diglen, key, signature+1);
   if (siglen < 0) {
        rpmlog(RPMLOG_ERR, _("sign_hash failed\n"));
        return NULL;
   }

   /* convert file signature binary to hex */
   fsignature = pgpHexStr(signature, siglen+1);
   return fsignature;
}

static uint32_t signatureLength(const char *algo, int diglen, const char *key)
{
    unsigned char digest[diglen];
    unsigned char signature[MAX_SIGNATURE_LENGTH];

    memset(digest, 0, diglen);
    memset(signature, 0, MAX_SIGNATURE_LENGTH);
    signature[0] = '\x03';

    uint32_t siglen = sign_hash(algo, digest, diglen, key, signature+1);
    return siglen;
}

rpmRC rpmSignFiles(Header h, const char *key)
{
    struct rpmtd_s digests;
    int algo;
    int diglen;
    uint32_t siglen;
    const char *algoname;
    const char *digest;
    char *signature;

    algo = headerGetNumber(h, RPMTAG_FILEDIGESTALGO);
    if (!algo) {
	rpmlog(RPMLOG_ERR, _("missing RPMTAG_FILEDIGESTALGO\n"));
	return RPMRC_FAIL;
    }
    diglen = rpmDigestLength(algo);
    algoname = hash_algo_name[algo];
    if (!algoname) {
	rpmlog(RPMLOG_ERR, _("hash_algo_name failed\n"));
	return RPMRC_FAIL;
    }

    siglen = signatureLength(algoname, diglen, key);
    headerPutUint32(h, RPMTAG_FILESIGNATURELENGTH, &siglen, 1);

    headerGet(h, RPMTAG_FILEDIGESTS, &digests, HEADERGET_MINMEM);
    while ((digest = rpmtdNextString(&digests))) {
        signature = signFile(algoname, digest, diglen, key);
        if (!signature) {
            rpmlog(RPMLOG_ERR, _("signFile failed\n"));
            return RPMRC_FAIL;
        }
        if (!headerPutString(h, RPMTAG_FILESIGNATURES, signature)) {
            rpmlog(RPMLOG_ERR, _("headerPutString failed\n"));
            return RPMRC_FAIL;
        }
    }

    return RPMRC_OK;
}
