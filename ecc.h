#ifndef DROPBEAR_DROPBEAR_ECC_H
#define DROPBEAR_DROPBEAR_ECC_H

#include "includes.h"

#include "buffer.h"

#if DROPBEAR_ECC

struct dropbear_ecc_curve {
	const struct ltc_hash_descriptor *hash_desc;
	const char *name;
	const char *oid;
};

extern struct dropbear_ecc_curve ecc_curve_nistp256;
extern struct dropbear_ecc_curve ecc_curve_nistp384;
extern struct dropbear_ecc_curve ecc_curve_nistp521;
extern struct dropbear_ecc_curve *dropbear_ecc_curves[];

struct dropbear_ecc_curve* curve_for_key(const ecc_key *key);

void buf_put_ecc_raw_pubkey_string(buffer *buf, ecc_key *key);
ecc_key * buf_get_ecc_raw_pubkey(buffer *buf, const struct dropbear_ecc_curve *curve);
int buf_get_ecc_privkey_string(buffer *buf, ecc_key *key);

mp_int * dropbear_ecc_shared_secret(ecc_key *pub_key, const ecc_key *priv_key);

#endif

#endif /* DROPBEAR_DROPBEAR_ECC_H */
