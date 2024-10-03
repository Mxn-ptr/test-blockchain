#ifndef HBLK_CRYPTO_H
#define HBLK_CRYPTO_H

#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include <errno.h>
#include <sys/stat.h>

#define EC_PUB_LEN 65
#define EC_CURVE NID_secp256k1
#define PUB_FILENAME "key_pub.pem"
#define PRI_FILENAME "key.pem"

/**
 * struct sig_s - struct sig
 * @sig: pointer
 * @len: length
*/
typedef struct sig_s
{
	uint8_t *sig;
	size_t len;
} sig_t;

uint8_t *sha256(int8_t const *s, size_t len,
				uint8_t digest[SHA256_DIGEST_LENGTH]);
EC_KEY *ec_create(void);
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN]);
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN]);
int ec_save(EC_KEY *key, char const *folder);
EC_KEY *ec_load(char const *folder);
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg,
				size_t msglen, sig_t *sig);

#endif
