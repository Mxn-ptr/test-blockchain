#include "hblk_crypto.h"

/**
 * ec_to_pub - Extracts the public key form an EC_KEY opaque structure
 * @key: pointer to the EC_KEY structure ro retrieve public key from
 * @pub: adress at which store the extracted public key
 * Return: pointer to pub or NULL on failure
*/
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN])
{
	const EC_POINT *point;
	const EC_GROUP *group;

	if (!key || !pub)
		return (NULL);

	point = EC_KEY_get0_public_key(key);
	if (!point)
		return (NULL);

	group = EC_KEY_get0_group(key);
	if (!group)
		return (NULL);

	if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
							pub, EC_PUB_LEN, NULL) != EC_PUB_LEN)
		return (NULL);

	return (pub);
}
