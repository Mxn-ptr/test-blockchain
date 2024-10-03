#include "hblk_crypto.h"

/**
 * ec_verify - Verifies the signature of a given set of bytes
 * @key: Pointer to the EC_KEY structure containing the private key to be used
 * @msg: Pointer to the msglen bytes to be signed
 * @msglen: Length of the message to be signed
 * @sig: Holds the address at which to store the signature
 *
 * Return: 1 if the signature is valid, 0 otherwise
*/
int ec_verify(EC_KEY const *key, uint8_t const *msg,
				size_t msglen, sig_t const *sig)
{
	if (!key || !msg || !sig)
		return (0);

	if (!EC_KEY_check_key(key))
		return (0);

	if (ECDSA_verify(0, msg, msglen, sig->sig, sig->len, (EC_KEY *)key) != 1)
		return (0);

	return (1);
}
