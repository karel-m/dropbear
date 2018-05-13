#include "includes.h"
#include "dbutil.h"
#include "crypto_desc.h"
#include "ecc.h"
#include "ecdsa.h"
#include "signkey.h"
#include "bignum.h"

#if DROPBEAR_ECDSA

int signkey_is_ecdsa(enum signkey_type type)
{
	return type == DROPBEAR_SIGNKEY_ECDSA_NISTP256
		|| type == DROPBEAR_SIGNKEY_ECDSA_NISTP384
		|| type == DROPBEAR_SIGNKEY_ECDSA_NISTP521;
}

enum signkey_type ecdsa_signkey_type(const ecc_key * key) {
	struct dropbear_ecc_curve* curve = curve_for_key(key);
#if DROPBEAR_ECC_256
	if (curve == &ecc_curve_nistp256) {
		return DROPBEAR_SIGNKEY_ECDSA_NISTP256;
	}
#endif
#if DROPBEAR_ECC_384
	if (curve == &ecc_curve_nistp384) {
		return DROPBEAR_SIGNKEY_ECDSA_NISTP384;
	}
#endif
#if DROPBEAR_ECC_521
	if (curve == &ecc_curve_nistp521) {
		return DROPBEAR_SIGNKEY_ECDSA_NISTP521;
	}
#endif
	return DROPBEAR_SIGNKEY_NONE;
}

ecc_key *gen_ecdsa_priv_key(unsigned int bit_size) {
	const ltc_ecc_curve *dp = NULL;
	ecc_key *new_key = NULL;
	switch (bit_size) {
#if DROPBEAR_ECC_256
		case 256:
			ecc_get_curve("nistp256", &dp);
			break;
#endif
#if DROPBEAR_ECC_384
		case 384:
			ecc_get_curve("nistp384", &dp);
			break;
#endif
#if DROPBEAR_ECC_521
		case 521:
			ecc_get_curve("nistp521", &dp);
			break;
#endif
	}
	if (!dp) {
		dropbear_exit("Key size %d isn't valid. Try "
#if DROPBEAR_ECC_256
			"256 "
#endif
#if DROPBEAR_ECC_384
			"384 "
#endif
#if DROPBEAR_ECC_521
			"521 "
#endif
			, bit_size);
	}

	new_key = m_malloc(sizeof(*new_key));
	if (ecc_make_key_ex(NULL, dropbear_ltc_prng, new_key, dp) != CRYPT_OK) {
		dropbear_exit("ECC error");
	}
	return new_key;
}

ecc_key *buf_get_ecdsa_pub_key(buffer* buf) {
	unsigned char *key_ident = NULL, *identifier = NULL;
	unsigned int key_ident_len, identifier_len;
	buffer *q_buf = NULL;
	struct dropbear_ecc_curve **curve;
	ecc_key *new_key = NULL;

	/* string   "ecdsa-sha2-[identifier]" */
	key_ident = (unsigned char*)buf_getstring(buf, &key_ident_len);
	/* string   "[identifier]" */
	identifier = (unsigned char*)buf_getstring(buf, &identifier_len);

	if (key_ident_len != identifier_len + strlen("ecdsa-sha2-")) {
		TRACE(("Bad identifier lengths"))
		goto out;
	}
	if (memcmp(&key_ident[strlen("ecdsa-sha2-")], identifier, identifier_len) != 0) {
		TRACE(("mismatching identifiers"))
		goto out;
	}
	for (curve = dropbear_ecc_curves; *curve; curve++) {
		if (memcmp(identifier, (char*)(*curve)->name, strlen((char*)(*curve)->name)) == 0) {
			break;
		}
	}
	if (!*curve) {
		TRACE(("couldn't match ecc curve"))
		goto out;
	}

	/* string Q */
	q_buf = buf_getstringbuf(buf);
	new_key = buf_get_ecc_raw_pubkey(q_buf, *curve);

out:
	m_free(key_ident);
	m_free(identifier);
	if (q_buf) {
		buf_free(q_buf);
		q_buf = NULL;
	}
	TRACE(("leave buf_get_ecdsa_pub_key"))
	return new_key;
}

ecc_key *buf_get_ecdsa_priv_key(buffer *buf) {
	ecc_key *new_key = NULL;
	TRACE(("enter buf_get_ecdsa_priv_key"))
	new_key = buf_get_ecdsa_pub_key(buf);
	if (!new_key) {
		return NULL;
	}

	if (buf_getmpint(buf, new_key->k) != DROPBEAR_SUCCESS) {
		ecc_free(new_key);
		m_free(new_key);
		return NULL;
	}

	return new_key;
}

void buf_put_ecdsa_pub_key(buffer *buf, ecc_key *key) {
	struct dropbear_ecc_curve *curve = curve_for_key(key);
	char key_ident[30];

	if (curve == NULL) dropbear_exit("ECC error");
	snprintf(key_ident, sizeof(key_ident), "ecdsa-sha2-%s", curve->name);
	buf_putstring(buf, key_ident, strlen(key_ident));
	buf_putstring(buf, curve->name, strlen(curve->name));
	buf_put_ecc_raw_pubkey_string(buf, key);
}

void buf_put_ecdsa_priv_key(buffer *buf, ecc_key *key) {
	buf_put_ecdsa_pub_key(buf, key);
	buf_putmpint(buf, key->k);
}

void buf_put_ecdsa_sign(buffer *buf, const ecc_key *key, const buffer *data_buf) {
	int err = DROPBEAR_FAILURE, rv;
	hash_state hs;
	unsigned char hash[64];
	mp_int *r = NULL, *s = NULL;
	struct dropbear_ecc_curve *curve = curve_for_key(key);
	unsigned char rawsig[200];
	unsigned long rawsig_len = sizeof(rawsig);
	char key_ident[30];
	buffer *sigbuf = NULL;

	if (curve == NULL) goto out;
	curve->hash_desc->init(&hs);
	curve->hash_desc->process(&hs, data_buf->data, data_buf->len);
	curve->hash_desc->done(&hs, hash);

	rv = ecc_sign_hash_rfc7518(hash, curve->hash_desc->hashsize,
					rawsig, &rawsig_len,
					NULL, dropbear_ltc_prng, key);
	if (rv != CRYPT_OK) goto out;

	m_mp_alloc_init_multi(&r, &s, NULL);

	if (mp_read_unsigned_bin(r, rawsig, rawsig_len / 2) != CRYPT_OK) goto out;
	if (mp_read_unsigned_bin(s, rawsig + rawsig_len / 2, rawsig_len / 2) != CRYPT_OK) goto out;

	snprintf(key_ident, sizeof(key_ident), "ecdsa-sha2-%s", curve->name);
	buf_putstring(buf, key_ident, strlen(key_ident));
	/* enough for nistp521 */
	sigbuf = buf_new(200);
	buf_putmpint(sigbuf, (mp_int*)r);
	buf_putmpint(sigbuf, (mp_int*)s);
	buf_putbufstring(buf, sigbuf);

	err = DROPBEAR_SUCCESS;

out:
	m_mp_free_multi(&r, &s, NULL);
	if (sigbuf) {
		buf_free(sigbuf);
	}

	if (err == DROPBEAR_FAILURE) {
		dropbear_exit("ECC error");
	}
}

/* returns values in s and r
   returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_get_ecdsa_verify_params(buffer *buf,
			void *r, void* s) {
	int ret = DROPBEAR_FAILURE;
	unsigned int sig_len;
	unsigned int sig_pos;

	sig_len = buf_getint(buf);
	sig_pos = buf->pos;
	if (buf_getmpint(buf, r) != DROPBEAR_SUCCESS) {
		goto out;
	}
	if (buf_getmpint(buf, s) != DROPBEAR_SUCCESS) {
		goto out;
	}
	if (buf->pos - sig_pos != sig_len) {
		goto out;
	}
	ret = DROPBEAR_SUCCESS;

out:
	return ret;
}

int buf_ecdsa_verify(buffer *buf, const ecc_key *key, const buffer *data_buf) {
	hash_state hs;
	unsigned char hash[64], rawsig[200] = { 0 };
	unsigned long sig_half, i;
	int ret = DROPBEAR_FAILURE, err, stat = 0;
	struct dropbear_ecc_curve *curve = curve_for_key(key);
	mp_int *r = NULL, *s = NULL;

	m_mp_alloc_init_multi(&r, &s, NULL);
	if (buf_get_ecdsa_verify_params(buf, r, s) != DROPBEAR_SUCCESS) {
		goto out;
	}

	if (curve == NULL) goto out;
	curve->hash_desc->init(&hs);
	curve->hash_desc->process(&hs, data_buf->data, data_buf->len);
	curve->hash_desc->done(&hs, hash);

	sig_half = ecc_get_size(key);
	i = mp_unsigned_bin_size(r);
	if (i > sig_half) goto out;
	if ((err = mp_to_unsigned_bin(r, rawsig + (sig_half - i))) != CRYPT_OK) goto out;
	i = mp_unsigned_bin_size(s);
	if (i > sig_half) goto out;
	if ((err = mp_to_unsigned_bin(s, rawsig + (2 * sig_half - i))) != CRYPT_OK) goto out;

	err = ecc_verify_hash_rfc7518(rawsig, sig_half * 2,
					hash, curve->hash_desc->hashsize,
					&stat, key);
	if (err == CRYPT_OK && stat == 1) ret = DROPBEAR_SUCCESS;
out:
	m_mp_free_multi(&r, &s, NULL);
	return ret;
}



#endif /* DROPBEAR_ECDSA */
