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

#include "tcp-active.h"
#include "tcp-established.h"
#include "agent-priv.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

typedef struct {
  GSocketAddress     *local_addr;
  GMainContext       *context;
  SocketRecvCallback  recv_cb;
  gpointer            userdata;
  GDestroyNotify      destroy_notify;
  GSList             *established_sockets; /**< list of NiceSocket objs */
  GSList             *gsources;            /**< list of GSource objs */
  guint               max_tcp_queue_size;
} TcpActivePriv;

static void socket_attach (NiceSocket* sock, GMainContext* ctx);
static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gint socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);
static int socket_get_tx_queue_size (NiceSocket *sock);


NiceSocket * nice_tcp_active_socket_new (GMainContext *ctx, NiceAddress *addr, 
                                         SocketRecvCallback cb, gpointer userdata, GDestroyNotify destroy_notify, guint max_tcp_queue_size)
{
  struct sockaddr_storage name;
  NiceAddress tmp_addr;
  NiceSocket *sock;
  TcpActivePriv *priv;
  GSocketAddress *gaddr;

  if (addr == NULL) {
    /* We can't connect a tcp with no local address */
    return NULL;
  }

  tmp_addr = *addr;
  /* Make sure we don't bind to any local port */
  nice_address_set_port (&tmp_addr, 0);
  nice_address_copy_to_sockaddr (&tmp_addr, (struct sockaddr *)&name);

  gaddr = g_socket_address_new_from_native (&name, sizeof (name));
  if (gaddr == NULL) {
    return NULL;
  }

  sock = g_slice_new0 (NiceSocket);

  sock->priv = priv = g_slice_new0 (TcpActivePriv);
  priv->local_addr = gaddr;
  priv->context = ctx ? g_main_context_ref (ctx) : NULL;
  priv->recv_cb = cb;
  priv->userdata = userdata;
  priv->destroy_notify = destroy_notify;
  priv->max_tcp_queue_size = max_tcp_queue_size;

  sock->type = NICE_SOCKET_TYPE_TCP_ACTIVE;
  sock->addr = *addr;
  sock->fileno = NULL;
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
  TcpActivePriv *priv = sock->priv;
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
  TcpActivePriv *priv = sock->priv;
  GSList *i;

  if (priv->context)
    g_main_context_unref (priv->context);

  if (priv->userdata && priv->destroy_notify)
    (priv->destroy_notify)(priv->userdata);

  for (i = priv->established_sockets; i; i = i->next) {
    NiceSocket *socket = i->data;
    nice_socket_free (socket);
  }

  g_object_unref (priv->local_addr);

  g_slist_free (priv->established_sockets);
  g_slice_free (TcpActivePriv, sock->priv);
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  /* 
   * Should never be called for an active connection, all real data arrives on
   * established connections 
   */
  return -1;
}

static gint
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  TcpActivePriv *priv = sock->priv;
  GSList *i;
  gint sent_len = 0;
  gchar to_string[NICE_ADDRESS_STRING_LEN];

  nice_address_to_string (to, to_string);

  for (i = priv->established_sockets; i; i = i->next) {
    NiceSocket *socket = i->data;
    sent_len = nice_socket_send(socket, to, len, buf);
    if (sent_len > 0)
    {
      nice_debug("tcp-act %p: Sent on socket, sent %d to %s:%u", sock, sent_len, to_string, nice_address_get_port (to));
      return sent_len;
    } else if (sent_len < 0) {
      /* 
       * Correct socket but failed 
       */
      nice_debug("tcp-act %p: Failed to send to %s:%u, destroying socket", sock, to_string, nice_address_get_port (to));
      nice_socket_free (socket);
      priv->established_sockets = g_slist_remove(priv->established_sockets, socket);
      break;
    }
  }

  /*
   * Connect new socket
   */
  NiceSocket* new_socket = nice_tcp_active_socket_connect (sock, to);
  if (!new_socket) {
    nice_debug ("tcp-act %p: failed to connect the new socket to %s:%u", sock, to_string, nice_address_get_port (to));
    return -1;
  }
  nice_debug ("tcp-act %p: connecting outbound socket to %s:%u. New tcp-est %p", sock, to_string, nice_address_get_port (to), new_socket);
  priv->established_sockets = g_slist_append (priv->established_sockets, new_socket);
  sent_len = nice_socket_send (new_socket, to, len, buf);
  return sent_len;
}


static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}

static
void tcp_active_established_socket_recv_cb (NiceSocket* socket, NiceAddress* from, gchar* buf, gint len, gpointer *userdata)
{
  NiceSocket* listening_socket = (NiceSocket *)userdata;
  TcpActivePriv *priv = listening_socket->priv;

  if (priv->recv_cb) {
    nice_debug("tcp-act %p: sending up %d bytes received from tcp-est %p", listening_socket, len, socket);
    
    (priv->recv_cb) (listening_socket, from, buf, len, priv->userdata);
  } else {
    nice_debug("tcp-act %p: no callback configured!!", listening_socket);
  }
}

NiceSocket *
nice_tcp_active_socket_connect (NiceSocket *socket, const NiceAddress *addr)
{
  struct sockaddr_storage name;
  TcpActivePriv *active_priv = socket->priv;
  GSocket *gsock = NULL;
  GError *gerr = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;
  NiceAddress local_addr;
  gboolean connect_pending = FALSE;

  if (addr == NULL) {
    /* We can't connect a tcp socket with no destination address */
    return NULL;
  }

  nice_address_copy_to_sockaddr (addr, (struct sockaddr *)&name);

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

  gaddr = g_socket_address_new_from_native (&name, sizeof (name));
  if (gaddr == NULL) {
    g_object_unref (gsock);
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);

  gret = g_socket_bind (gsock, active_priv->local_addr, TRUE, NULL) &&
      g_socket_connect (gsock, gaddr, NULL, &gerr);
  g_object_unref (gaddr);

  if (gret == FALSE && gerr) {
    if (g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_PENDING) == FALSE) {
      g_error_free (gerr);
      g_socket_close (gsock, NULL);
      g_object_unref (gsock);
      return NULL;
    } else {
      connect_pending = TRUE;
    }
    g_error_free (gerr);
  }

  gaddr = g_socket_get_local_address (gsock, NULL);
  if (gaddr == NULL ||
      !g_socket_address_to_native (gaddr, &name, sizeof (name), NULL)) {
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }
  g_object_unref (gaddr);

  nice_address_set_from_sockaddr (&local_addr, (struct sockaddr *)&name);

  return nice_tcp_established_socket_new (gsock,
                                          &local_addr, addr, active_priv->context, 
                                          tcp_active_established_socket_recv_cb, (gpointer)socket, NULL,
                                          connect_pending, active_priv->max_tcp_queue_size);
}


static int socket_get_tx_queue_size (NiceSocket *sock)
{
  TcpActivePriv *priv = sock->priv;
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
