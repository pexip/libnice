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

#ifndef SHA1_H
#define SHA1_H

#ifdef _WIN32
#include "win32_common.h"
#else
#include <stdint.h>
#endif
#include <stddef.h>

#define SHA1_MAC_LEN 20

void sha1_vector(size_t num_elem, const uint8_t *addr[], const size_t *len,
    uint8_t *mac);
void hmac_sha1_vector(const uint8_t *key, size_t key_len, size_t num_elem,
    const uint8_t *addr[], const size_t *len, uint8_t *mac);
void hmac_sha1(const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len, uint8_t *mac);
void sha1_prf(const uint8_t *key, size_t key_len, const char *label,
    const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len);

#endif /* SHA1_H */
