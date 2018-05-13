#include "includes.h"
#include "ecc.h"
#include "dbutil.h"
#include "bignum.h"

#if DROPBEAR_ECC

#if DROPBEAR_ECC_256
struct dropbear_ecc_curve ecc_curve_nistp256 = {
	&sha256_desc,	/* .hash_desc	*/
	"nistp256",	/* .name	*/
	"1.2.840.10045.3.1.7"	/* .oid	*/
};
#endif
#if DROPBEAR_ECC_384
struct dropbear_ecc_curve ecc_curve_nistp384 = {
	&sha384_desc,	/* .hash_desc	*/
	"nistp384",	/* .name	*/
	"1.3.132.0.34"	/* .oid		*/
};
#endif
#if DROPBEAR_ECC_521
struct dropbear_ecc_curve ecc_curve_nistp521 = {
	&sha512_desc,	/* .hash_desc	*/
	"nistp521",	/* .name	*/
	"1.3.132.0.35"	/* .oid		*/
};
#endif

struct dropbear_ecc_curve *dropbear_ecc_curves[] = {
#if DROPBEAR_ECC_256
	&ecc_curve_nistp256,
#endif
#if DROPBEAR_ECC_384
	&ecc_curve_nistp384,
#endif
#if DROPBEAR_ECC_521
	&ecc_curve_nistp521,
#endif
	NULL
};

struct dropbear_ecc_curve* curve_for_key(const ecc_key *key) {
	struct dropbear_ecc_curve **curve = NULL;
	char buf[64] = { 0 };
	unsigned long buf_len = sizeof(buf);
	if (ecc_get_oid_str(buf, &buf_len, key) == CRYPT_OK) {
		for (curve = dropbear_ecc_curves; *curve; curve++) {
			if (strcmp((*curve)->oid, buf) == 0) {
				break;
			}
		}
	}
	return *curve;
}

/* For the "ephemeral public key octet string" in ECDH (rfc5656 section 4) */
void buf_put_ecc_raw_pubkey_string(buffer *buf, ecc_key *key) {
	unsigned long len = ecc_get_size(key) * 2 + 1;
	int err;
	buf_putint(buf, len);
	err = ecc_get_key(buf_getwriteptr(buf, len), &len, PK_PUBLIC, key);
	if (err != CRYPT_OK) {
		dropbear_exit("ECC error");
	}
	buf_incrwritepos(buf, len);
}

/* For the "ephemeral public key octet string" in ECDH (rfc5656 section 4) */
ecc_key * buf_get_ecc_raw_pubkey(buffer *buf, const struct dropbear_ecc_curve *curve) {
	ecc_key *key = NULL;
	int ret = DROPBEAR_FAILURE;
	const ltc_ecc_curve* cu = NULL;

	key = m_malloc(sizeof(*key));
	if (ecc_get_curve(curve->oid, &cu) != CRYPT_OK) goto out;
	if (ecc_set_dp(cu, key) != CRYPT_OK) goto out;
	if (ecc_set_key(buf->data, buf->len, PK_PUBLIC, key) != CRYPT_OK) goto out;

	ret = DROPBEAR_SUCCESS;

	out:
	if (ret == DROPBEAR_FAILURE) {
		if (key) {
			ecc_free(key);
			m_free(key);
			key = NULL;
		}
	}

	return key;

}

/* a wrapped version of libtomcrypt's "ecc_shared_secret" to output
   a mp_int instead. */
mp_int * dropbear_ecc_shared_secret(ecc_key *public_key, const ecc_key *private_key)
{
	mp_int *shared_secret = NULL;
	unsigned char shared_secret_buf[64];
	unsigned long shared_secret_len = sizeof(shared_secret_buf);
	shared_secret = m_malloc(sizeof(*shared_secret));
	int err = DROPBEAR_FAILURE;

	m_mp_init(shared_secret);
	if (ecc_shared_secret(private_key, public_key, shared_secret_buf, &shared_secret_len) != CRYPT_OK) {
		goto out;
	}
	if (mp_read_unsigned_bin(shared_secret, shared_secret_buf, shared_secret_len) != MP_OKAY) {
		goto out;
	}

	err = DROPBEAR_SUCCESS;
	out:
	if (err == DROPBEAR_FAILURE) {
		dropbear_exit("ECC error");
	}
	return shared_secret;
}

#endif
