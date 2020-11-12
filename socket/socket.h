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

#ifndef _SOCKET_H
#define _SOCKET_H

#include "address.h"
#include <gio/gio.h>
#include <gasyncio.h>

#ifdef G_OS_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

G_BEGIN_DECLS

typedef struct _NiceSocket NiceSocket;
typedef enum {
  NICE_SOCKET_TYPE_UDP_BSD,
  NICE_SOCKET_TYPE_TCP_BSD,
  NICE_SOCKET_TYPE_TCP_ACTIVE,
  NICE_SOCKET_TYPE_TCP_PASSIVE,
  NICE_SOCKET_TYPE_TCP_ESTABLISHED,
  NICE_SOCKET_TYPE_TCP_SO,
  NICE_SOCKET_TYPE_PSEUDOSSL,
  NICE_SOCKET_TYPE_HTTP,
  NICE_SOCKET_TYPE_SOCKS5,
  NICE_SOCKET_TYPE_TURN,
  NICE_SOCKET_TYPE_TCP_TURN
} NiceSocketType;

struct _NiceSocket
{
  NiceAddress addr;
  NiceSocketType type;
  union{
    GAsyncServerSocket *server;
    GAsyncServerSocket *conection;
  } transport;

  /* Asyncronous functions */
  gboolean (*recv_callback) (NiceSocket *sock, NiceAddress *from, guint len,
      gchar *buf);
  void (*accept_callback) (NiceSocket *server_socket, NiceSocket* client_socket, gint32 result, NiceAddress client_address);
  
  /* Used when a socket is requested to be freed/closed.  */
 void (*request_close) (NiceSocket *sock);
 void (*closed_callback) (NiceSocket *sock);
  /* Async function, but backed by a queue */
  gboolean (*request_send) (NiceSocket *sock, const NiceAddress *to, guint len,
      const gchar *buf);
  
  gboolean (*is_reliable) (NiceSocket *sock);
  int (*get_tx_queue_size) (NiceSocket *sock);
  void (*set_rx_enabled) (NiceSocket *sock, gboolean enabled);

  void *priv;
};

typedef void (*SocketRXCallback)(NiceSocket* socket, NiceAddress* from, gchar* buf, gint len, gpointer userdata);
typedef void (*SocketTXCallback)(NiceSocket* socket, gchar* buf, gint len, gsize queued, gpointer userdata);

G_GNUC_WARN_UNUSED_RESULT
gint
nice_socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf);

gint
nice_socket_send (NiceSocket *sock, const NiceAddress *to,
  guint len, const gchar *buf);

gboolean
nice_socket_is_reliable (NiceSocket *sock);

void
nice_socket_attach (NiceSocket *sock);

gint
nice_socket_get_tx_queue_size (NiceSocket *sock);

void
nice_socket_set_rx_enabled (NiceSocket *sock, gboolean enabled);

void
nice_socket_free (NiceSocket *sock);

const char *socket_type_to_string (NiceSocketType type);

void
nice_socket_async_recvmsg_callback (
    void **userdata_pointer,
    struct msghdr *msg,
    gint32 result,
    GAsyncConnectionSocket * socket);

void
nice_socket_async_sendmsg_callback (
    void **userdata_pointer,
    struct msghdr *msg,
    gint32 result,
    GAsyncConnectionSocket * socket);

void
nice_socket_async_connect_callback (
    void **userdata_pointer,
    gint32 result,
    GAsyncConnectionSocket * socket);

void
nice_socket_async_close_callback (
    void **userdata_pointer,
    gint32 result,
    GAsyncConnectionSocket * socket);

void
nice_socket_async_close_server_callback (
    void **userdata_pointer,
    gint32 result,
    GAsyncServerSocket * socket);

void
nice_socket_async_accept_callback (
    void **server_userdata_pointer,
    void **connection_userdata_pointer,
    gint32 result,
    GAsyncServerSocket* server_socket,
    GAsyncConnectionSocket * connection_socket,
    struct sockaddr_in *client_addr,
    socklen_t client_addr_len);

void nice_socket_async_connection_socket_dispose_callback(
    void **userdata_pointer,
   GAsyncConnectionSocket *socket);

void nice_socket_async_server_socket_dispose_callback(
   void **userdata_pointer,
   GAsyncServerSocket *socket);

void nice_socket_async_timeout_callback (gpointer userdata, gint32 result,
      GAsyncConnectionSocket * socket);

#include "udp-bsd.h"
#include "tcp-bsd.h"
#include "tcp-active.h"
#include "tcp-passive.h"
#include "pseudossl.h"
#include "socks5.h"
#include "http.h"
#include "turn.h"
#include "tcp-turn.h"

G_END_DECLS

#endif /* _SOCKET_H */
