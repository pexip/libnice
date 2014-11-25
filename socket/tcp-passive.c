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

#define MAX_BUFFER_SIZE 65536

typedef struct {
  GMainContext       *context;
  SocketRXCallback    rxcb;
  SocketTXCallback    txcb;
  gpointer            userdata;
  GDestroyNotify      destroy_notify;
  GSList             *established_sockets;             /**< list of NiceSocket objs */
  GSList             *gsources;            /**< list of GSource objs */
  guint               max_tcp_queue_size;
} TcpPassivePriv;


static void socket_attach (NiceSocket* sock, GMainContext* ctx);
static void socket_close (NiceSocket *sock);
static gint socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gint socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);
static gint socket_get_tx_queue_size (NiceSocket *sock);

NiceSocket *
nice_tcp_passive_socket_new (GMainContext *ctx, NiceAddress *addr,
    SocketRXCallback rxcb, SocketTXCallback txcb, gpointer userdata,
    GDestroyNotify destroy_notify, guint max_tcp_queue_size)
{
  struct sockaddr_storage name;
  NiceSocket *sock;
  TcpPassivePriv *priv;
  GSocket *gsock = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;

  g_return_val_if_fail (addr != NULL, NULL);
  g_return_val_if_fail (rxcb != NULL, NULL);
  g_return_val_if_fail (txcb != NULL, NULL);

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

  gret = g_socket_bind (gsock, gaddr, TRUE, NULL) &&
      g_socket_listen (gsock, NULL);
  g_object_unref (gaddr);

  if (gret == FALSE) {
    nice_debug ("tcp-pass: Failed to listen on port %d", nice_address_get_port(addr));
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
  priv->context = ctx ? g_main_context_ref (ctx) : NULL;
  priv->rxcb = rxcb;
  priv->txcb = txcb;
  priv->userdata = userdata;
  priv->destroy_notify = destroy_notify;
  priv->max_tcp_queue_size = max_tcp_queue_size;

  sock->type = NICE_SOCKET_TYPE_TCP_PASSIVE;
  sock->fileno = gsock;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;
  sock->attach = socket_attach;
  sock->get_tx_queue_size = socket_get_tx_queue_size;

  return sock;
}

static void
socket_attach (NiceSocket* sock, GMainContext* ctx)
{
  TcpPassivePriv *priv = sock->priv;
  GSList *i;

  if (priv->context)
    g_main_context_unref (priv->context);

  priv->context = ctx;
  if (priv->context) {
    g_main_context_ref (priv->context);
  }

  for (i = priv->established_sockets; i; i = i->next) {
    NiceSocket *socket = i->data;
    nice_socket_attach (socket, ctx);
  }
}

static void
socket_close (NiceSocket *sock)
{
  TcpPassivePriv *priv = sock->priv;
  GSList *i;

  if (priv->context)
    g_main_context_unref (priv->context);

  if (priv->userdata && priv->destroy_notify)
    (priv->destroy_notify)(priv->userdata);

  for (i = priv->established_sockets; i; i = i->next) {
    NiceSocket *socket = i->data;
    nice_socket_free (socket);
  }

  if (sock->fileno) {
    g_socket_close (sock->fileno, NULL);
    g_object_unref (sock->fileno);
    sock->fileno = NULL;
  }
  g_slist_free (priv->established_sockets);
  g_slice_free (TcpPassivePriv, sock->priv);
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  TcpPassivePriv *priv = sock->priv;

  /*
   * Accept new connection, TODO: dos prevention, reconnects etc 
   */
  NiceSocket* new_socket = nice_tcp_passive_socket_accept (sock);
  if (!new_socket) {
    nice_debug ("tcp-pass %p: Failed to accept new connection", sock);
    return -1;
  }
  nice_debug ("tcp-pass %p: Accepted OK, got new established connection tcp-est %p", sock, new_socket);
  
  priv->established_sockets = g_slist_append (priv->established_sockets, new_socket);
  return 0;
}

static gint
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  TcpPassivePriv *priv = sock->priv;
  GSList *i;

  for (i = priv->established_sockets; i; i = i->next) {
    NiceSocket *socket = i->data;
    gint sent_len = nice_socket_send(socket, to, len, buf);
    if (sent_len != 0)
    {
      nice_debug("tcp-pass %p: Sent on socket, sent %d", sock, sent_len);
      return sent_len;
    }
  }
  return 0;
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}

static void
tcp_passive_established_socket_rx_cb (NiceSocket* socket, NiceAddress* from,
    gchar* buf, gint len, gpointer userdata)
{
  NiceSocket* passive = (NiceSocket *)userdata;
  TcpPassivePriv *priv = passive->priv;

  priv->rxcb (passive, from, buf, len, priv->userdata);
}

static void
tcp_passive_established_socket_tx_cb (NiceSocket* socket,
    gchar* buf, gint len, gsize queued, gpointer userdata)
{
  NiceSocket* passive = (NiceSocket *)userdata;
  TcpPassivePriv *priv = passive->priv;

  priv->txcb (passive, buf, len, queued, priv->userdata);
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
    nice_debug("tcp-pass %p: Accept failed", socket);
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

  return nice_tcp_established_socket_new (gsock, &socket->addr, &remote_addr, priv->context,
      tcp_passive_established_socket_rx_cb, tcp_passive_established_socket_tx_cb,
      (gpointer)socket, NULL, FALSE, priv->max_tcp_queue_size);
}

static gint
socket_get_tx_queue_size (NiceSocket *sock)
{
  TcpPassivePriv *priv = sock->priv;
  GSList *i;
  int ret = 0;

  for (i = priv->established_sockets; i; i = i->next) {
    NiceSocket *socket = i->data;
    gint queue_len = nice_socket_get_tx_queue_size (socket);
    if (queue_len > ret)
      ret = queue_len;
  }
  return ret;
}

