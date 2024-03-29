/*
 * SHA1 hash implementation and interface functions
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "sha1.h"

#include <string.h>
#include <openssl/evp.h>

/**
 * hmac_sha1_vector:
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash (20 bytes)
 *
 * HMAC-SHA1 over data vector (RFC 2104)
 */
void hmac_sha1_vector(const uint8_t *key, size_t key_len, size_t num_elem,
    const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
  unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
  unsigned char tk[20];
  const uint8_t *_addr[6];
  size_t _len[6], i;

  if (num_elem > 5) {
    /*
     * Fixed limit on the number of fragments to avoid having to
     * allocate memory (which could fail).
     */
    return;
  }

  /* if key is longer than 64 bytes reset it to key = SHA1(key) */
  if (key_len > 64) {
    sha1_vector(1, &key, &key_len, tk);
    key = tk;
    key_len = 20;
  }

  /* the HMAC_SHA1 transform looks like:
   *
   * SHA1(K XOR opad, SHA1(K XOR ipad, text))
   *
   * where K is an n byte key
   * ipad is the byte 0x36 repeated 64 times
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected */

  /* start out by storing key in ipad */
  memset(k_pad, 0, sizeof(k_pad));
  memcpy(k_pad, key, key_len);
  /* XOR key with ipad values */
  for (i = 0; i < 64; i++)
    k_pad[i] ^= 0x36;

  /* perform inner SHA1 */
  _addr[0] = k_pad;
  _len[0] = 64;
  for (i = 0; i < num_elem; i++) {
    _addr[i + 1] = addr[i];
    _len[i + 1] = len[i];
  }
  sha1_vector(1 + num_elem, _addr, _len, mac);

  memset(k_pad, 0, sizeof(k_pad));
  memcpy(k_pad, key, key_len);
  /* XOR key with opad values */
  for (i = 0; i < 64; i++)
    k_pad[i] ^= 0x5c;

  /* perform outer SHA1 */
  _addr[0] = k_pad;
  _len[0] = 64;
  _addr[1] = mac;
  _len[1] = SHA1_MAC_LEN;
  sha1_vector(2, _addr, _len, mac);
}


/**
 * hmac_sha1:
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @data: Pointers to the data area
 * @data_len: Length of the data area
 * @mac: Buffer for the hash (20 bytes)
 *
 * HMAC-SHA1 over data buffer (RFC 2104)
 */
void hmac_sha1(const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len, uint8_t *mac)
{
  hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}


/**
 * sha1_prf:
 * @key: Key for PRF
 * @key_len: Length of the key in bytes
 * @label: A unique label for each purpose of the PRF
 * @data: Extra data to bind into the key
 * @data_len: Length of the data
 * @buf: Buffer for the generated pseudo-random key
 * @buf_len: Number of bytes of key to generate
 *
 * SHA1-based Pseudo-Random Function (PRF) (IEEE 802.11i, 8.5.1.1)
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key (e.g., PMK in IEEE 802.11i).
 */
void sha1_prf(const uint8_t *key, size_t key_len, const char *label,
    const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len)
{
  uint8_t counter = 0;
  size_t pos, plen;
  uint8_t hash[SHA1_MAC_LEN];
  size_t label_len = strlen(label) + 1;
  const unsigned char *addr[3];
  size_t len[3];

  addr[0] = (uint8_t *) label;
  len[0] = label_len;
  addr[1] = data;
  len[1] = data_len;
  addr[2] = &counter;
  len[2] = 1;

  pos = 0;
  while (pos < buf_len) {
    plen = buf_len - pos;
    if (plen >= SHA1_MAC_LEN) {
      hmac_sha1_vector(key, key_len, 3, addr, len, &buf[pos]);
      pos += SHA1_MAC_LEN;
    } else {
      hmac_sha1_vector(key, key_len, 3, addr, len, hash);
      memcpy(&buf[pos], hash, plen);
      break;
    }
    counter++;
  }
}

/**
 * sha1_vector:
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 *
 * SHA-1 hash for data vector
 */
void sha1_vector(size_t num_elem, const uint8_t *addr[], const size_t *len,
    uint8_t *mac)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  size_t i;

  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);

  for (i = 0; i < num_elem; i++)
    EVP_DigestUpdate(ctx, addr[i], len[i]);
  EVP_DigestFinal_ex(ctx, mac, NULL);
  EVP_MD_CTX_destroy(ctx);
}
