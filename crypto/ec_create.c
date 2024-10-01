#include "hblk_crypto.h"

/**
 * ec_create - Creates a EC key pair using secp256k1 curve
 * Return: pointeur to an EC_KEY structure or NULL on failure
*/
EC_KEY *ec_create(void)
{
	EC_KEY *ec_key = NULL;

	ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (ec_key == NULL)
		return (NULL);

	if (EC_KEY_generate_key(ec_key) != 1)
		return (NULL);

	return (ec_key);
}
