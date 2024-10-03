#include "hblk_crypto.h"

/**
 * ec_sign - Signs a given set of bytes using a given EC_KEY private key
 *
 * @key: Pointer to the EC_KEY structure containing the private key to be used
 * @msg: Pointer to the msglen bytes to be signed
 * @msglen: Length of the message to be signed
 * @sig: Holds the address at which to store the signature
 *
 * Return: A pointer to the signature buffer upon success (sig->sig), or NULL
 *         upon failure.
 */
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg,
				size_t msglen, sig_t *sig)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int sig_len;

	if (!key || !msg || !sig)
		return (NULL);

	if (!SHA256(msg, msglen, hash))
		return (NULL);

	sig->len = ECDSA_size(key);
	sig->sig = calloc(sig->len, sizeof(uint8_t));
	if (!sig->sig)
		return (NULL);

	if (ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, sig->sig, &sig_len, key) != 1)
	{
		free(sig->sig);
		sig->sig = NULL;
		return (NULL);
	}

	sig->len = sig_len;

	return (sig->sig);
}
