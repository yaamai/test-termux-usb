#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include <fido.h>
#include <fido/credman.h>
#include <fido/types.h>

#include "utils.h"
#include "sk-api.h"
#include "termux-io.h"

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#else
#define SSH_FIDO_INIT_ARG	0
#endif
#define MAX_FIDO_DEVICES	8

#define MUL_NO_OVERFLOW ((size_t)1 << (sizeof(size_t) * 4))

static void
freezero(void *ptr, size_t sz)
{
	if (ptr == NULL)
		return;
	explicit_bzero(ptr, sz);
	free(ptr);
}

static void *
recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb, size_t size)
{
	size_t oldsize, newsize;
	void *newptr;

	if (ptr == NULL)
		return calloc(newnmemb, size);

	if ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	newsize = newnmemb * size;

	if ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		errno = EINVAL;
		return NULL;
	}
	oldsize = oldnmemb * size;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	if (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		if (d < oldsize / 2 && d < (size_t)getpagesize()) {
			memset((char *)ptr + newsize, 0, d);
			return ptr;
		}
	}

	newptr = malloc(newsize);
	if (newptr == NULL)
		return NULL;

	if (newsize > oldsize) {
		memcpy(newptr, ptr, oldsize);
		memset((char *)newptr + oldsize, 0, newsize - oldsize);
	} else
		memcpy(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	free(ptr);

	return newptr;
}

struct sk_usbhid {
	fido_dev_t *dev;
	char *path;
};

static struct sk_usbhid *
sk_open(const char *path)
{
	struct sk_usbhid *sk;
	int r;

  hid_init();

  fido_dev_io_t io = {
		&fido_termux_open,
		&fido_termux_close,
		&fido_termux_read,
		&fido_termux_write,
	};

	if (path == NULL) {
		skdebug(__func__, "path == NULL");
		return NULL;
	}
	if ((sk = calloc(1, sizeof(*sk))) == NULL) {
		skdebug(__func__, "calloc sk failed");
		return NULL;
	}
	if ((sk->path = strdup(path)) == NULL) {
		skdebug(__func__, "strdup path failed");
		free(sk);
		return NULL;
	}
	if ((sk->dev = fido_dev_new()) == NULL) {
		skdebug(__func__, "fido_dev_new failed");
		free(sk->path);
		free(sk);
		return NULL;
	}

  fido_dev_set_io_functions(sk->dev, &io);

	if ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		free(sk->path);
		free(sk);
		return NULL;
	}
	return sk;
}

static void
sk_close(struct sk_usbhid *sk)
{
	if (sk == NULL)
		return;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	free(sk->path);
	free(sk);
}

static int
fidoerr_to_skerr(int fidoerr)
{
	switch (fidoerr) {
	case FIDO_ERR_UNSUPPORTED_OPTION:
	case FIDO_ERR_UNSUPPORTED_ALGORITHM:
		return SSH_SK_ERR_UNSUPPORTED;
	case FIDO_ERR_PIN_REQUIRED:
	case FIDO_ERR_PIN_INVALID:
	case FIDO_ERR_OPERATION_DENIED:
		return SSH_SK_ERR_PIN_REQUIRED;
	default:
		return -1;
	}
}

static int
check_enroll_options(struct sk_option **options, char **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	if (options == NULL)
		return 0;
	for (i = 0; options[i] != NULL; i++) {
		if (strcmp(options[i]->name, "device") == 0) {
			if ((*devicep = strdup(options[i]->value)) == NULL) {
				skdebug(__func__, "strdup device failed");
				return -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} else if (strcmp(options[i]->name, "user") == 0) {
			if (strlcpy(user_id, options[i]->value, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				return -1;
			}
			skdebug(__func__, "requested user %s",
			    (char *)user_id);
		} else {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			if (options[i]->required) {
				skdebug(__func__, "unknown required option");
				return -1;
			}
		}
	}
	return 0;
}


/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
static int
pack_public_key_ecdsa(const fido_cred_t *cred,
    struct sk_enroll_response *response)
{
	const uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	int ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	if ((x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		skdebug(__func__, "libcrypto setup failed");
		goto out;
	}
	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	if (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		goto out;
	}

	if (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL) {
		skdebug(__func__, "BN_bin2bn failed");
		goto out;
	}
	if (EC_POINT_set_affine_coordinates_GFp(g, q, x, y, NULL) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates_GFp failed");
		goto out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		goto out;
	}
	if ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	if (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_key, response->public_key_len, NULL) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		goto out;
	}
	/* success */
	ret = 0;
 out:
	if (ret != 0 && response->public_key != NULL) {
		memset(response->public_key, 0, response->public_key_len);
		free(response->public_key);
		response->public_key = NULL;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	return ret;
}

static int
pack_public_key_ed25519(const fido_cred_t *cred,
    struct sk_enroll_response *response)
{
	const uint8_t *ptr;
	size_t len;
	int ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	if ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		goto out;
	}
	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	response->public_key_len = len;
	if ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	memcpy(response->public_key, ptr, len);
	ret = 0;
 out:
	if (ret != 0)
		free(response->public_key);
	return ret;
}

static int
pack_public_key(uint32_t alg, const fido_cred_t *cred,
    struct sk_enroll_response *response)
{
	switch(alg) {
	case SSH_SK_ECDSA:
		return pack_public_key_ecdsa(cred, response);
	case SSH_SK_ED25519:
		return pack_public_key_ed25519(cred, response);
	default:
		return -1;
	}
}

static int
check_sk_options(fido_dev_t *dev, const char *opt, int *ret)
{
	fido_cbor_info_t *info;
	char * const *name;
	const bool *value;
	size_t len, i;
	int r;

	*ret = -1;

	if (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		return 0;
	}
	if ((info = fido_cbor_info_new()) == NULL) {
		skdebug(__func__, "fido_cbor_info_new failed");
		return -1;
	}
	if ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		return -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	value = fido_cbor_info_options_value_ptr(info);
	len = fido_cbor_info_options_len(info);
	for (i = 0; i < len; i++) {
    skdebug(__func__, "%s=%s", name[i], value);
		if (!strcmp(name[i], opt)) {
			*ret = value[i];
			break;
		}
	}
	fido_cbor_info_free(&info);
	if (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	else
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	return 0;
}

static int
key_lookup(fido_dev_t *dev, const char *application, const uint8_t *user_id,
    size_t user_id_len, const char *pin)
{
	fido_assert_t *assert = NULL;
	uint8_t message[32];
	int r = FIDO_ERR_INTERNAL;
	int sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', sizeof(message));
	if ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	if ((r = fido_assert_set_clientdata(assert, message,
	    sizeof(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	uv = FIDO_OPT_OMIT;
	if (pin == NULL && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	if ((r = fido_assert_set_uv(assert, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		goto out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_count(assert));
	for (i = 0; i < fido_assert_count(assert); i++) {
		if (fido_assert_user_id_len(assert, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(assert, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			goto out;
		}
	}
 out:
	fido_assert_free(&assert);

	return r;
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
static int
check_sign_load_resident_options(struct sk_option **options, char **devicep)
{
	size_t i;

	if (options == NULL)
		return 0;
	for (i = 0; options[i] != NULL; i++) {
		if (strcmp(options[i]->name, "device") == 0) {
			if ((*devicep = strdup(options[i]->value)) == NULL) {
				skdebug(__func__, "strdup device failed");
				return -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} else {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			if (options[i]->required) {
				skdebug(__func__, "unknown required option");
				return -1;
			}
		}
	}
	return 0;
}

static int
pack_sig_ecdsa(fido_assert_t *assert, struct sk_sign_response *response)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	const unsigned char *cp;
	size_t sig_len;
	int ret = -1;

	cp = fido_assert_sig_ptr(assert, 0);
	sig_len = fido_assert_sig_len(assert, 0);
	if ((sig = d2i_ECDSA_SIG(NULL, &cp, sig_len)) == NULL) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	if (ret != 0) {
		free(response->sig_r);
		free(response->sig_s);
		response->sig_r = NULL;
		response->sig_s = NULL;
	}
	return ret;
}

static int
pack_sig_ed25519(fido_assert_t *assert, struct sk_sign_response *response)
{
	const unsigned char *ptr;
	size_t len;
	int ret = -1;

	ptr = fido_assert_sig_ptr(assert, 0);
	len = fido_assert_sig_len(assert, 0);
	if (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		goto out;
	}
	response->sig_r_len = len;
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	if (ret != 0) {
		free(response->sig_r);
		response->sig_r = NULL;
	}
	return ret;
}

static int
pack_sig(uint32_t  alg, fido_assert_t *assert,
    struct sk_sign_response *response)
{
	switch(alg) {
	case SSH_SK_ECDSA:
		return pack_sig_ecdsa(assert, response);
	case SSH_SK_ED25519:
		return pack_sig_ed25519(assert, response);
	default:
		return -1;
	}
}

#define PACKED_TYPE(type, def)	\
	typedef def __attribute__ ((__packed__)) type;

PACKED_TYPE(a_fido_ctap_info_t,
/* defined in section 8.1.9.1.3 (CTAPHID_INIT) of the fido2 ctap spec */
struct a_fido_ctap_info {
	uint64_t nonce;    /* echoed nonce */
	uint32_t cid;      /* channel id */
	uint8_t  protocol; /* ctaphid protocol id */
	uint8_t  major;    /* major version number */
	uint8_t  minor;    /* minor version number */
	uint8_t  build;    /* build version number */
	uint8_t  flags;    /* capabilities flags; see FIDO_CAP_* */
})

typedef struct a_fido_dev {
	uint64_t              nonce;      /* issued nonce */
	a_fido_ctap_info_t      attr;       /* device attributes */
	uint32_t              cid;        /* assigned channel id */
	char                 *path;       /* device path */
	void                 *io_handle;  /* abstract i/o handle */
	fido_dev_io_t         io;         /* i/o functions */
	bool                  io_own;     /* device has own io/transport */
	size_t                rx_len;     /* length of HID input reports */
	size_t                tx_len;     /* length of HID output reports */
	int                   flags;      /* internal flags; see FIDO_DEV_* */
	fido_dev_transport_t  transport;  /* transport functions */
	uint64_t	      maxmsgsize; /* max message size */
	int		      timeout_ms; /* read timeout in ms */
} a_fido_dev_t;

static int
read_rks(struct sk_usbhid *sk, const char *pin,
    struct sk_resident_key ***rksp, size_t *nrksp)
{
	int ret = SSH_SK_ERR_GENERAL, r = -1, internal_uv;
	fido_credman_metadata_t *metadata = NULL;
	fido_credman_rp_t *rp = NULL;
	fido_credman_rk_t *rk = NULL;
	size_t i, j, nrp, nrk, user_id_len;
	const fido_cred_t *cred;
	const char *rp_id, *rp_name, *user_name;
	struct sk_resident_key *srk = NULL, **tmp;
	const u_char *user_id;

	if (pin == NULL) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}
	if ((metadata = fido_credman_metadata_new()) == NULL) {
		skdebug(__func__, "alloc failed");
		goto out;
	}
	if (check_sk_options(sk->dev, "uv", &internal_uv) != 0) {
		skdebug(__func__, "check_sk_options failed");
		goto out;
	}

#define FIDO_DEV_CREDMAN	0x0008
  skdebug(__func__, "device flags %x", ((a_fido_dev_t*)sk->dev)->flags);
  ((a_fido_dev_t*)sk->dev)->flags ^= CTAP_CBOR_CRED_MGMT_PRE;
  ((a_fido_dev_t*)sk->dev)->flags |= FIDO_DEV_CREDMAN;
  skdebug(__func__, "device flags %x", ((a_fido_dev_t*)sk->dev)->flags);

	if ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		if (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			goto out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		// ret = fidoerr_to_skerr(r);
		// goto out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	if ((rp = fido_credman_rp_new()) == NULL) {
		skdebug(__func__, "alloc rp failed");
		goto out;
	}
	if ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		//goto out;
	}
	nrp = fido_credman_rp_count(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	for (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == NULL ? "(none)" : rp_name,
		    rp_id == NULL ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		if (rp_id == NULL ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			continue;

		fido_credman_rk_free(&rk);
		if ((rk = fido_credman_rk_new()) == NULL) {
			skdebug(__func__, "alloc rk failed");
			goto out;
		}
		if ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			goto out;
		}
		nrk = fido_credman_rk_count(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		for (j = 0; j < nrk; j++) {
			if ((cred = fido_credman_rk(rk, j)) == NULL) {
				skdebug(__func__, "no RK in slot %zu", j);
				continue;
			}
			if ((user_name = fido_cred_user_name(cred)) == NULL)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* build response entry */
			if ((srk = calloc(1, sizeof(*srk))) == NULL ||
			    (srk->key.key_handle = calloc(1,
			    fido_cred_id_len(cred))) == NULL ||
			    (srk->application = strdup(rp_id)) == NULL ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == NULL)) {
				skdebug(__func__, "alloc sk_resident_key");
				goto out;
			}

			srk->key.key_handle_len = fido_cred_id_len(cred);
			memcpy(srk->key.key_handle, fido_cred_id_ptr(cred),
			    srk->key.key_handle_len);
			srk->user_id_len = user_id_len;
			if (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

			switch (fido_cred_type(cred)) {
			case COSE_ES256:
				srk->alg = SSH_SK_ECDSA;
				break;
			case COSE_EDDSA:
				srk->alg = SSH_SK_ED25519;
				break;
			default:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				goto out; /* XXX free rk and continue */
			}

			if (fido_cred_prot(cred) == FIDO_CRED_PROT_UV_REQUIRED
			    && internal_uv == -1)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;

			if ((r = pack_public_key(srk->alg, cred,
			    &srk->key)) != 0) {
				skdebug(__func__, "pack public key failed");
				goto out;
			}
			/* append */
			if ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    sizeof(**rksp))) == NULL) {
				skdebug(__func__, "alloc rksp");
				goto out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = NULL;
		}
	}
	/* Success */
	ret = 0;
 out:
	if (srk != NULL) {
		free(srk->application);
		freezero(srk->key.public_key, srk->key.public_key_len);
		freezero(srk->key.key_handle, srk->key.key_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, sizeof(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	return ret;
}

uint32_t
sk_api_version(void)
{
	return SSH_SK_VERSION_MAJOR;
}

int
sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **options, struct sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = NULL;
	const uint8_t *ptr;
	uint8_t user_id[32];
	struct sk_usbhid *sk = NULL;
	struct sk_enroll_response *response = NULL;
	size_t len;
	int credprot;
	int cose_alg;
	int ret = SSH_SK_ERR_GENERAL;
	int r;
	char *device = NULL;

	fido_init(SSH_FIDO_INIT_ARG);

	if (enroll_response == NULL) {
		skdebug(__func__, "enroll_response == NULL");
		goto out;
	}
	*enroll_response = NULL;
	memset(user_id, 0, sizeof(user_id));
	if (check_enroll_options(options, &device, user_id,
	    sizeof(user_id)) != 0)
		goto out; /* error already logged */

	switch(alg) {
	case SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		break;
	case SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		break;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		goto out;
	}
	if (device != NULL)
		sk = sk_open(device);
	// else
	// 	sk = sk_probe(NULL, NULL, 0, 0);
	if (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	skdebug(__func__, "using device %s", sk->path);
	if ((flags & SSH_SK_RESIDENT_KEY) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = key_lookup(sk->dev, application, user_id, sizeof(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		if (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} else {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		goto out;
	}
	if ((cred = fido_cred_new()) == NULL) {
		skdebug(__func__, "fido_cred_new failed");
		goto out;
	}
	if ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	if ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_KEY) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_cred_set_user(cred, user_id, sizeof(user_id),
	    "openssh", "openssh", NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_cred_set_rp(cred, application, NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		goto out;
	}
	if ((flags & (SSH_SK_RESIDENT_KEY|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
// #if !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
//     !defined(HAVE_FIDO_CRED_SET_PROT)
// 		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
// 		ret = SSH_SK_ERR_UNSUPPORTED;
// 		goto out;
// 		credprot = 0; (void)credprot; /* avoid warning */
// #endif
		if (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			goto out;
		}
		if ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		else
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		if ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			goto out;
		}
	}
	if ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	if (fido_cred_x5c_ptr(cred) != NULL) {
		if ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			goto out;
		}
	} else {
		skdebug(__func__, "self-attested credential");
		if ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			goto out;
		}
	}
	if ((response = calloc(1, sizeof(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = flags;
	if (pack_public_key(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		goto out;
	}
	if ((ptr = fido_cred_id_ptr(cred)) != NULL) {
		len = fido_cred_id_len(cred);
		if ((response->key_handle = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc key handle failed");
			goto out;
		}
		memcpy(response->key_handle, ptr, len);
		response->key_handle_len = len;
	}
	if ((ptr = fido_cred_sig_ptr(cred)) != NULL) {
		len = fido_cred_sig_len(cred);
		if ((response->signature = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc signature failed");
			goto out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	if ((ptr = fido_cred_x5c_ptr(cred)) != NULL) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		if ((response->attestation_cert = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc attestation cert failed");
			goto out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	if ((ptr = fido_cred_authdata_ptr(cred)) != NULL) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		if ((response->authdata = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc authdata failed");
			goto out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = NULL;
	ret = 0;
 out:
	free(device);
	if (response != NULL) {
		free(response->public_key);
		free(response->key_handle);
		free(response->signature);
		free(response->attestation_cert);
		free(response->authdata);
		free(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	return ret;
}

int
sk_sign(uint32_t alg, const uint8_t *data, size_t datalen,
    const char *application,
    const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **sign_response)
{
	fido_assert_t *assert = NULL;
	char *device = NULL;
	struct sk_usbhid *sk = NULL;
	struct sk_sign_response *response = NULL;
	int ret = SSH_SK_ERR_GENERAL, internal_uv;
	int r;

	fido_init(SSH_FIDO_INIT_ARG);

	if (sign_response == NULL) {
		skdebug(__func__, "sign_response == NULL");
		goto out;
	}
	*sign_response = NULL;
	if (check_sign_load_resident_options(options, &device) != 0)
		goto out; /* error already logged */
	if (device != NULL)
		sk = sk_open(device);
	// else if (pin != NULL || (flags & SSH_SK_USER_VERIFICATION_REQD))
	// 	sk = sk_probe(NULL, NULL, 0, 0);
	// else
	// 	sk = sk_probe(application, key_handle, key_handle_len, 0);
	if (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	if ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	if ((r = fido_assert_set_clientdata(assert,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_up(assert,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	if (pin == NULL && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	if (pin == NULL && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		if (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			goto out;
		}
		if ((r = fido_assert_set_uv(assert,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			goto out;
		}
	}
	if ((r = fido_dev_get_assert(sk->dev, assert, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	if ((response = calloc(1, sizeof(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = fido_assert_flags(assert, 0);
	response->counter = fido_assert_sigcount(assert, 0);
	if (pack_sig(alg, assert, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		goto out;
	}
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	free(device);
	if (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	sk_close(sk);
	fido_assert_free(&assert);
	return ret;
}

int
sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rksp, size_t *nrksp)
{
	int ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	struct sk_resident_key **rks = NULL;
	struct sk_usbhid *sk = NULL;
	char *device = NULL;

	*rksp = NULL;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	if (check_sign_load_resident_options(options, &device) != 0)
		goto out; /* error already logged */
	if (device != NULL)
		sk = sk_open(device);
	// else
	// 	sk = sk_probe(NULL, NULL, 0, 1);
	if (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	skdebug(__func__, "trying %s", sk->path);
	if ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		goto out;
	}
	/* success, unless we have no keys but a specific error */
	if (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = NULL;
	nrks = 0;
 out:
	sk_close(sk);
	for (i = 0; i < nrks; i++) {
		free(rks[i]->application);
		freezero(rks[i]->key.public_key, rks[i]->key.public_key_len);
		freezero(rks[i]->key.key_handle, rks[i]->key.key_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], sizeof(*rks[i]));
	}
	free(device);
	free(rks);
	return ret;
}
