/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008-2009 Nokia Corporation. All rights reserved.
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
# include "config.h"
#endif


#include <glib.h>

#include "socket.h"


gint
nice_socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  return sock->recv (sock, from, len, buf);
}

gint
nice_socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  return sock->send (sock, to, len, buf);
}

gint
nice_socket_get_tx_queue_size (NiceSocket *sock)
{
  int ret = 0;

  if (sock->get_tx_queue_size != NULL) {
    ret = sock->get_tx_queue_size (sock);
  }

  return ret;
}

void
nice_socket_set_rx_enabled (NiceSocket *sock, gboolean enabled)
{
  if (sock->set_rx_enabled != NULL)
    sock->set_rx_enabled (sock, enabled);
}

gboolean
nice_socket_is_reliable (NiceSocket *sock)
{
  return sock->is_reliable (sock);
}

void
nice_socket_free (NiceSocket *sock)
{
  if (sock) {
    sock->close (sock);
    g_slice_free (NiceSocket,sock);
  }
}

void
nice_socket_attach (NiceSocket *sock, GMainContext* ctx)
{
  if (sock && sock->attach) {
    sock->attach (sock, ctx);
  }
}

void
nice_socket_buffers_and_interface_unref  (NiceSocket *sock)
{
  if (sock) {
    if (sock->type == NICE_SOCKET_TYPE_UDP_BSD)
    {
      nice_udp_socket_buffers_and_interface_unref (sock);
    }
  }
}

void
nice_socket_buffer_interface_set (NiceSocket *sock, MemlistInterface **interface)
{
  if (sock) {
    if (sock->type == NICE_SOCKET_TYPE_UDP_BSD)
    {
      nice_udp_socket_interface_set(sock, interface);
    }
  }
}

const char* socket_type_to_string (NiceSocketType type)
{
  switch (type) {
  case NICE_SOCKET_TYPE_UDP_BSD: return "udp";
  case NICE_SOCKET_TYPE_TCP_BSD: return "tcp-bsd";
  case NICE_SOCKET_TYPE_TCP_ACTIVE: return "tcp-active";
  case NICE_SOCKET_TYPE_TCP_PASSIVE: return "tcp-passive";
  case NICE_SOCKET_TYPE_TCP_ESTABLISHED: return "tcp-established";
  case NICE_SOCKET_TYPE_TCP_SO: return "tcp-so";
  case NICE_SOCKET_TYPE_PSEUDOSSL: return "pseudossl";
  case NICE_SOCKET_TYPE_HTTP: return "http";
  case NICE_SOCKET_TYPE_SOCKS5: return "socks5";
  case NICE_SOCKET_TYPE_TURN: return "turn";
  case NICE_SOCKET_TYPE_TCP_TURN: return "tcp-turn";
  }
  return "(invalid)";
}

