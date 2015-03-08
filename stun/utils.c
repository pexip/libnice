/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007-2009 Nokia Corporation. All rights reserved.
 *  Contact: Rémi Denis-Courmont
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Youness Alaoui, Collabora Ltd.
 *   Olivier Crete, Collabora Ltd.
 *   Kai Vehmanen, Nokia
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "utils.h"

size_t stun_padding (size_t l)
{
  return (4 - (l & 3)) & 3;
}

size_t stun_align (size_t l)
{
  return (l + 3) & ~3;
}


uint16_t stun_getw (const uint8_t *ptr)
{
  return ((ptr)[0] << 8) | ptr[1];
}


void *stun_setw (uint8_t *ptr, uint16_t value)
{
  *ptr++ = value >> 8;
  *ptr++ = value & 0xff;
  return ptr;
}

StunMethod stun_get_type (uint8_t *h) 
{
  uint16_t t = stun_getw (h);
  /* HACK HACK HACK
     A google/msn data indication is 0x0115 which is contrary to the RFC 5389
     which states that 8th and 12th bits are for the class and that 0x01 is
     for indications...
     So 0x0115 is reported as a "connect error response", while it should be
     a data indication, which message type should actually be 0x0017
     This should fix the issue, and it's considered safe since the "connect"
     method doesn't exist anymore */
  if (t == 0x0115)
    t = 0x0017;
  return (StunMethod)(((t & 0x3e00) >> 2) | ((t & 0x00e0) >> 1) |
                          (t & 0x000f));
}

void stun_set_type (uint8_t *h, StunClass c, StunMethod m)
{
/*   assert (c < 4); */
/*   assert (m < (1 << 12)); */

  h[0] = (c >> 1) | ((m >> 6) & 0x3e);
  h[1] = ((c << 4) & 0x10) | ((m << 1) & 0xe0) | (m & 0x0f);

/*   assert (stun_getw (h) < (1 << 14)); */
/*   assert (stun_get_class (h) == c); */
/*   assert (stun_get_method (h) == m); */
}

StunClass stun_get_class (uint8_t *h)
{
  uint16_t t = stun_getw (h);
  /* HACK HACK HACK
     A google/msn data indication is 0x0115 which is contrary to the RFC 5389
     which states that 8th and 12th bits are for the class and that 0x01 is
     for indications...
     So 0x0115 is reported as a "connect error response", while it should be
     a data indication, which message type should actually be 0x0017
     This should fix the issue, and it's considered safe since the "connect"
     method doesn't exist anymore */
  if (t == 0x0115)
    t = 0x0017;
  return (StunClass)(((t & 0x0100) >> 7) | ((t & 0x0010) >> 4));
}

StunMessageReturn stun_xor_address (const StunMessage *msg,
    struct sockaddr *addr, socklen_t addrlen,
    uint32_t magic_cookie)
{
  switch (addr->sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in *ip4 = (struct sockaddr_in *)addr;
      if ((size_t) addrlen < sizeof (*ip4))
        return STUN_MESSAGE_RETURN_INVALID;

      ip4->sin_port ^= htons (magic_cookie >> 16);
      ip4->sin_addr.s_addr ^= htonl (magic_cookie);
      return STUN_MESSAGE_RETURN_SUCCESS;
    }

    case AF_INET6:
    {
      struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)addr;
      unsigned short i;

      if ((size_t) addrlen < sizeof (*ip6))
        return STUN_MESSAGE_RETURN_INVALID;

      ip6->sin6_port ^= htons (magic_cookie >> 16);
      for (i = 0; i < 16; i++)
        ip6->sin6_addr.s6_addr[i] ^= msg->buffer[4 + i];
      return STUN_MESSAGE_RETURN_SUCCESS;
    }
  }
  return STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS;
}

bool stun_get_transaction_id (uint8_t *buf, size_t len, StunTransactionId msg_id)
{
  if (len < STUN_MESSAGE_TRANS_ID_POS + STUN_MESSAGE_TRANS_ID_LEN) {
    return FALSE;
  } else {
    memcpy (msg_id, buf + STUN_MESSAGE_TRANS_ID_POS, STUN_MESSAGE_TRANS_ID_LEN);
    return TRUE;
  }
}

