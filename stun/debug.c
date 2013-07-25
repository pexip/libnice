/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007 Nokia Corporation. All rights reserved.
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

#include "debug.h"

static int debug_enabled = 1;

void stun_debug_enable (void) {
  debug_enabled = 1;
}
void stun_debug_disable (void) {
  debug_enabled = 0;
}

void stun_message_log(StunMessage* msg, gboolean transmit, struct sockaddr* addr)
{
  char *msgbuff = stun_message_to_string(msg);

  char addrbuf[INET6_ADDRSTRLEN];
  memset(addrbuf, 0, sizeof(addrbuf));
  
  switch (addr->sa_family) {
    case AF_INET:
      inet_ntop (AF_INET, &((struct sockaddr_in *)addr)->sin_addr, addrbuf, INET_ADDRSTRLEN);
      break;
    case AF_INET6:
      inet_ntop (AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, addrbuf, INET6_ADDRSTRLEN);
      break;
    default:
      g_return_if_reached ();
  }

  if (transmit) {
    g_log (G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Message=\"Sending STUN message\" Dst-address=\"%s\" %s", addrbuf, msgbuff);
  } else {
    g_log (G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Message=\"Received STUN message\" Src-address=\"%s\" %s", addrbuf, msgbuff);
  }

  g_free (msgbuff);
}

void stun_debug (const char *fmt, ...)
{
  va_list ap;
  if (debug_enabled) {
    va_start (ap, fmt);
    g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, fmt, ap);
    va_end (ap);
  }
}

void stun_debug_bytes (const void *data, size_t len)
{
  size_t i;

  gchar buffer[len*2+1];
  
  for (i = 0; i < len; i++)
    sprintf(&buffer[i*2], "%02x", ((const unsigned char *)data)[i]);
  buffer[len*2] = '\0';
  stun_debug("0x%s", buffer);
}

