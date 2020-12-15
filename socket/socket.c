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
  return sock->functions->recv (sock, from, len, buf);
}

gint
nice_socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  return sock->functions->send (sock, to, len, buf);
}
int
nice_socket_get_fd (NiceSocket *sock)
{
  return sock->functions->get_fd(sock);
}

gint
nice_socket_get_tx_queue_size (NiceSocket *sock)
{
  int ret = 0;

  if (sock->functions->get_tx_queue_size != NULL) {
    ret = sock->functions->get_tx_queue_size (sock);
  }

  return ret;
}

void
nice_socket_set_rx_enabled (NiceSocket *sock, gboolean enabled)
{
  if (sock->functions->set_rx_enabled != NULL)
    sock->functions->set_rx_enabled (sock, enabled);
}

gboolean
nice_socket_is_reliable (NiceSocket *sock)
{
  return sock->functions->is_reliable (sock);
}

void
nice_socket_attach (NiceSocket *sock, GMainContext *context)
{
  if (sock && sock->functions->attach) {
    sock->functions->attach (sock, context);
  }
}

void
nice_socket_free (NiceSocket *sock)
{
  if (sock) {
    gboolean wait_free = sock->functions->close (sock);

    if (!wait_free)
    {

      if (sock->async_cb_ctx_free)
      {
        sock->async_cb_ctx_free(sock->async_cb_ctx);
        sock->async_cb_ctx = NULL;
        sock->async_cb_ctx_free = NULL;
      }

      g_slice_free (NiceSocket,sock);
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


void
nice_socket_async_recvmsg_callback (
    void **userdata_pointer,
    struct msghdr *msg,
    gint32 result,
    GAsyncConnectionSocket * async_socket)
{
  NiceSocket *socket = (NiceSocket*) *userdata_pointer;
  // TODO: Verify that the pointer here actually points to a Nice UDP socket
  socket->functions->recv_callback(socket, msg, result);
  (void) async_socket;
}

void
nice_socket_async_sendmsg_callback (
    void **userdata_pointer,
    struct msghdr *msg,
    gint32 result,
    GAsyncConnectionSocket * async_socket)
{
  NiceSocket *socket = (NiceSocket*) *userdata_pointer;
  socket->functions->send_callback(socket, msg, result);
  (void) async_socket;
}

void
nice_socket_async_connect_callback (
    void **userdata_pointer,
    gint32 result,
    GAsyncConnectionSocket * async_socket)
{
  g_assert(FALSE);
}

void
nice_socket_async_close_callback (
    void **userdata_pointer,
    gint32 result,
    GAsyncConnectionSocket * async_socket)
{
  NiceSocket *socket = (NiceSocket*) *userdata_pointer;
  socket->functions->closed_callback(socket, result);
  (void) async_socket;
}

void
nice_socket_async_close_server_callback (
    void **userdata_pointer,
    gint32 result,
    GAsyncServerSocket * socket)
{
  g_assert(FALSE);
}

void
nice_socket_async_connection_socket_dispose_callback (
    void **userdata_pointer,
    GAsyncConnectionSocket * async_socket)
{
  NiceSocket *socket = (NiceSocket*) *userdata_pointer;
  socket->functions->dispose_callback(socket, async_socket);
  (void) async_socket;
}

void
nice_socket_async_connection_socket_teardown_callback (
    void **userdata_pointer,
    int remaining,
    GAsyncConnectionSocket * async_socket)
{
  NiceSocket *socket = (NiceSocket*) *userdata_pointer;
  socket->functions->teardown_callback(socket, remaining);
  (void) async_socket;
}
void
nice_socket_async_accept_callback (
    void **server_userdata_pointer,
    void **connection_userdata_pointer,
    gint32 result,
    GAsyncServerSocket* server_socket,
    GAsyncConnectionSocket * connection_socket,
    struct sockaddr_in *client_addr,
    socklen_t client_addr_len)
{
  g_assert(FALSE);
#if 0
  NiceSocket *socket = *server_userdata_pointer;
  if (connection_userdata_pointer != NULL)
  {
    *connection_userdata_pointer = socket;
  }
  NiceAddress client_niceaddr;
  nice_address_init(&client_niceaddr);
  nice_address_set_from_sockaddr (&client_niceaddr, (const struct sockaddr *)client_addr);
  socket->functions->accept_callback(socket, connection_socket, result, client_niceaddr);
#endif
}

void nice_socket_async_server_socket_dispose_callback(
   void **userdata_pointer,
   GAsyncServerSocket *socket)
{

}

void nice_socket_async_timeout_callback (gpointer userdata, gint32 result,
      GAsyncConnectionSocket * async_socket)
{
}
