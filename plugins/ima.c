#include <sys/xattr.h>

#include <rpm/rpmfi.h>
#include <rpm/rpmte.h>
#include <rpm/rpmfiles.h>
#include <rpm/rpmtypes.h>
#include <rpmio/rpmstring.h>

#include "lib/rpmfs.h"
#include "lib/rpmplugin.h"
#include "lib/rpmte_internal.h"

#define XATTR_NAME_IMA "security.ima"

static char * fsmFsPath(rpmfi fi, const char * suffix)
{
    return rstrscat(NULL, rpmfiDN(fi), rpmfiBN(fi), suffix? suffix : "", NULL);
}

static rpmRC ima_psm_post(rpmPlugin plugin, rpmte te, int res)
{
	rpmfiles files = rpmteFiles(te);
	rpmfi fi = rpmteFI(te);
	int i;
	char *fpath;
	const unsigned char * fsig = NULL;
	size_t len;
	int rc = 0;

	if (fi == NULL) {
	    rc = RPMERR_BAD_MAGIC;
	    goto exit;
	}

	while (!rc) {
	    rc = rpmfiNext(fi);
	    i = rpmfiFX(fi);

	    if (rc < 0) {
		if (rc == RPMERR_ITER_END)
		    rc = 0;
		break;
	    }

	    /* Don't install signatures for (mutable) config files */
	    if (!(rpmfilesFFlags(files, i) & RPMFILE_CONFIG)) {
		fpath = fsmFsPath(fi, NULL);
		fsig = rpmfilesFSignature(files, i, &len);
		if (fsig) {
		    lsetxattr(fpath, XATTR_NAME_IMA, fsig, len, 0);
		}
	    }
	}
exit:
	return rc;
}

struct rpmPluginHooks_s ima_hooks = {
	.psm_post = ima_psm_post,
};
