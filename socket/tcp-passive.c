/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2012 Collabora Ltd.
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
 *   George Kiagiadakis, Collabora Ltd.
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

#include "tcp-passive.h"
#include "tcp-established.h"
#include "agent-priv.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef struct {
  GMainContext *context;
} TcpPassivePriv;


static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gint socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);


NiceSocket *
nice_tcp_passive_socket_new (GMainContext *ctx, NiceAddress *addr)
{
  struct sockaddr_storage name;
  NiceSocket *sock;
  TcpPassivePriv *priv;
  GSocket *gsock = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;

  if (addr == NULL) {
    /* We can't connect a tcp socket with no destination address */
    return NULL;
  }
  nice_address_copy_to_sockaddr (addr, (struct sockaddr *)&name);

  gaddr = g_socket_address_new_from_native (&name, sizeof (name));

  if (gaddr == NULL) {
    return NULL;
  }

  if (name.ss_family == AF_UNSPEC || name.ss_family == AF_INET) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_STREAM,
        G_SOCKET_PROTOCOL_TCP, NULL);

    name.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
    name.ss_len = sizeof (struct sockaddr_in);
#endif
  } else if (name.ss_family == AF_INET6) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_STREAM,
        G_SOCKET_PROTOCOL_TCP, NULL);
    name.ss_family = AF_INET6;
#ifdef HAVE_SA_LEN
    name.ss_len = sizeof (struct sockaddr_in6);
#endif
  }

  if (gsock == NULL) {
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);

  gret = g_socket_bind (gsock, gaddr, FALSE, NULL) &&
      g_socket_listen (gsock, NULL);
  g_object_unref (gaddr);

  if (gret == FALSE) {
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }

  gaddr = g_socket_get_local_address (gsock, NULL);
  if (gaddr == NULL ||
      !g_socket_address_to_native (gaddr, &name, sizeof (name), NULL)) {
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }
  g_object_unref (gaddr);

  sock = g_slice_new0 (NiceSocket);

  nice_address_set_from_sockaddr (&sock->addr, (struct sockaddr *)&name);

  sock->priv = priv = g_slice_new0 (TcpPassivePriv);
  priv->context = g_main_context_ref (ctx);

  sock->type = NICE_SOCKET_TYPE_TCP_PASSIVE;
  sock->fileno = gsock;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;

  return sock;
}

static void
socket_close (NiceSocket *sock)
{
  TcpPassivePriv *priv = sock->priv;

  if (priv->context)
    g_main_context_unref (priv->context);

  g_slice_free (TcpPassivePriv, sock->priv);
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  return -1;
}

static gint
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  return -1;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}

NiceSocket *
nice_tcp_passive_socket_accept (NiceSocket *socket)
{
  struct sockaddr_storage name;
  TcpPassivePriv *priv = socket->priv;
  GSocket *gsock = NULL;
  GSocketAddress *gaddr;
  NiceAddress remote_addr;

  gsock = g_socket_accept (socket->fileno, NULL, NULL);

  if (gsock == NULL) {
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);

  gaddr = g_socket_get_remote_address (gsock, NULL);
  if (gaddr == NULL ||
      !g_socket_address_to_native (gaddr, &name, sizeof (name), NULL)) {
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }
  g_object_unref (gaddr);

  nice_address_set_from_sockaddr (&remote_addr, (struct sockaddr *)&name);

  return nice_tcp_established_socket_new (gsock,
            &socket->addr, &remote_addr, priv->context);
}
