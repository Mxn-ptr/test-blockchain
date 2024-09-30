#include "hblk_crypto.h"

/**
 * Computes the SHA-256 hash
 * @s: byte sequence to hash
 * @len: length of the byte sequence
 * @digest: buffer to store the hash
 * Return: pointer to digest or NULL if digest is NULL
*/
uint8_t *sha256(int8_t const *s, size_t len,
				uint8_t digest[SHA256_DIGEST_LENGTH])
{
	if (digest == NULL)
		return (NULL);

	return (SHA256((const unsigned char *)s, len, digest));
}
