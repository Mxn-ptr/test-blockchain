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
	uint32_t signature_len = 0;

	if (!key || !msg || !sig)
		return (NULL);

	memset(sig->sig, 0, sizeof(sig->sig));

	if (ECDSA_sign(0, msg, msglen, sig->sig, &signature_len, (EC_KEY *)key) != 1)
		return (NULL);

	sig->len = signature_len;

	return (sig->sig);
}
