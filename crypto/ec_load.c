#include "hblk_crypto.h"

/**
 * ec_load - Loads an EC key pair from the disk
 * @folder: path to the folder from which to load the keys
 * Return: pointer to the created EC key pair on success or NULL
*/
EC_KEY *ec_load(char const *folder)
{
	EC_KEY *ec_key;
	char path[1024];
	FILE *fp;

	if (!folder)
		return (NULL);

	ec_key = EC_KEY_new_by_curve_name(EC_CURVE);
	if (!ec_key)
		return (NULL);

	sprintf(path, "%s/%s", folder, PUB_FILENAME);
	fp = fopen(path, "r");
	if (!fp)
		return (NULL);

	if (!PEM_read_EC_PUBKEY(fp, &ec_key, NULL, NULL))
	{
		fclose(fp);
		return (NULL);
	}

	sprintf(path, "%s/%s", folder, PRI_FILENAME);
	fp = fopen(path, "r");
	if (!fp)
	{
		EC_KEY_free(ec_key);
		return (NULL);
	}

	if (!PEM_read_ECPrivateKey(fp, &ec_key, NULL, NULL))
	{
		fclose(fp);
		EC_KEY_free(ec_key);
		return (NULL);
	}
	fclose(fp);
	return (ec_key);
}
