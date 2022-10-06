/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
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
 *   Dafydd Harries, Collabora Ltd.
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

/*
 * Implementation of UDP socket interface using Berkeley sockets. (See
 * http://en.wikipedia.org/wiki/Berkeley_sockets.)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "udp-bsd.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>


#include "agent-priv.h"
#include "memlist.h"



#ifndef G_OS_WIN32
#include <unistd.h>
#endif

static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gint socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);
static void socket_recvmmsg_structures_clean_up(NiceSocket *udp_socket);

#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG

struct _MessageData
{
  NiceMemoryBufferRef *buffer;

  struct iovec iovec;
  struct sockaddr_storage remote;
};
typedef struct _MessageData MessageData;

static void socket_recvmmsg_structures_fill_entry_with_buffer(MemlistInterface *memory_interface,
  MessageData *message_data, struct mmsghdr *hdr);
static void socket_recvmmsg_structures_set_up(NiceSocket *udp_socket);
#endif


struct UdpBsdSocketPrivate
{
  NiceAddress niceaddr;
  GSocketAddress *gaddr;
#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
  /* Alloc buffers outside callback, to avoid reallocing buffers for messages
     that are not received. Any messages that are passed along are replaced with
     freshly allocated memory. */
  MessageData *message_datas;
  /* This is stored outside the MessageData struct as  this must be in a
     continous list to be able to be passed to recvmmsg */
  struct mmsghdr *message_headers;
  MemlistInterface *interface;
#endif
};

NiceSocket *
nice_udp_bsd_socket_new (NiceAddress *addr)
{
  struct sockaddr_storage name;
  NiceSocket *sock = g_slice_new0 (NiceSocket);
  GSocket *gsock = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;
  struct UdpBsdSocketPrivate *priv;

  if (addr != NULL) {
    nice_address_copy_to_sockaddr(addr, (struct sockaddr *)&name);
  } else {
    memset (&name, 0, sizeof (name));
    name.ss_family = AF_UNSPEC;
  }

  if (name.ss_family == AF_UNSPEC || name.ss_family == AF_INET) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP, NULL);
    name.ss_family = AF_INET;
#ifdef HAVE_SA_LEN
    name.ss_len = sizeof (struct sockaddr_in);
#endif
  } else if (name.ss_family == AF_INET6) {
    gsock = g_socket_new (G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP, NULL);
    name.ss_family = AF_INET6;
#ifdef HAVE_SA_LEN
    name.ss_len = sizeof (struct sockaddr_in6);
#endif
  }

  if (gsock == NULL) {
    g_slice_free (NiceSocket, sock);
    return NULL;
  }

  /* GSocket: All socket file descriptors are set to be close-on-exec. */
  g_socket_set_blocking (gsock, false);
  gaddr = g_socket_address_new_from_native (&name, sizeof (name));
  if (gaddr != NULL) {
    gret = g_socket_bind (gsock, gaddr, FALSE, NULL);
    g_object_unref (gaddr);
  }

  if (gret == FALSE) {
    g_slice_free (NiceSocket, sock);
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }

  gaddr = g_socket_get_local_address (gsock, NULL);
  if (gaddr == NULL ||
      !g_socket_address_to_native (gaddr, &name, sizeof(name), NULL)) {
    g_slice_free (NiceSocket, sock);
    g_socket_close (gsock, NULL);
    g_object_unref (gsock);
    return NULL;
  }

  g_object_unref (gaddr);

  nice_address_set_from_sockaddr (&sock->addr, (struct sockaddr *)&name);

  priv = sock->priv = g_slice_new0 (struct UdpBsdSocketPrivate);
  nice_address_init (&priv->niceaddr);

  sock->type = NICE_SOCKET_TYPE_UDP_BSD;
  sock->fileno = gsock;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;
  sock->attach = NULL;

  return sock;
}

static void
socket_close (NiceSocket *sock)
{
  struct UdpBsdSocketPrivate *priv = sock->priv;

  if (priv->gaddr)
    g_object_unref (priv->gaddr);

  nice_udp_socket_buffers_and_interface_unref(sock);
  socket_recvmmsg_structures_clean_up(sock);

  g_slice_free (struct UdpBsdSocketPrivate, sock->priv);

  if (sock->fileno) {
    g_socket_close (sock->fileno, NULL);
    g_object_unref (sock->fileno);
    sock->fileno = NULL;
  }

}

#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
gint nice_udp_socket_recvmmsg(NiceSocket *sock)
{
  struct UdpBsdSocketPrivate *priv = sock->priv;

  int socket_fd = g_socket_get_fd(sock->fileno);
  gssize result =
          recvmmsg (socket_fd, priv->message_headers, NICE_UDP_SOCKET_MMSG_LEN, MSG_WAITFORONE, NULL);

  return result;
}
#endif
static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  GSocketAddress *gaddr = NULL;
  GError *gerr = NULL;
  gint recvd;

  recvd = g_socket_receive_from (sock->fileno, &gaddr, buf, len, NULL, &gerr);

  if (recvd < 0) {
    if (g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)
        || g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_FAILED))
      recvd = 0;

    g_error_free (gerr);
  }

  if (recvd > 0 && from != NULL && gaddr != NULL) {
    struct sockaddr_storage sa;

    g_socket_address_to_native (gaddr, &sa, sizeof (sa), NULL);
    nice_address_set_from_sockaddr (from, (struct sockaddr *)&sa);
  }

  if (gaddr != NULL)
    g_object_unref (gaddr);

  return recvd;
}

static gint
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  struct UdpBsdSocketPrivate *priv = sock->priv;

  if (!nice_address_is_valid (&priv->niceaddr) ||
      !nice_address_equal (&priv->niceaddr, to)) {
    struct sockaddr_storage sa;
    GSocketAddress *gaddr;

    if (priv->gaddr)
      g_object_unref (priv->gaddr);
    nice_address_copy_to_sockaddr (to, (struct sockaddr *)&sa);
    gaddr = g_socket_address_new_from_native (&sa, sizeof(sa));
    if (gaddr == NULL)
      return -1;
    priv->gaddr = gaddr;
    priv->niceaddr = *to;
  }

  return g_socket_send_to (sock->fileno, priv->gaddr, buf, len, NULL, NULL);
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return FALSE;
}

#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG

/* TODO: We need a way to extract and replenish buffers once they have been received */

void nice_udp_socket_interface_set(NiceSocket *udp_socket, MemlistInterface *interface){
  struct UdpBsdSocketPrivate *priv = udp_socket->priv;
  g_assert(priv->interface == NULL);
}

NiceMemoryBufferRef *nice_udp_socket_packet_retrieve(NiceSocket *udp_socket,
  guint packet_index, NiceAddress *from)
{
  g_assert(packet_index < NICE_UDP_SOCKET_MMSG_TOTAL);
  struct UdpBsdSocketPrivate *priv = udp_socket->priv;
  MessageData *message_data = &priv->message_datas[packet_index];
  nice_address_set_from_sockaddr (from, (struct sockaddr *)&message_data->remote);

  NiceMemoryBufferRef *result = message_data->buffer;
  message_data->buffer = NULL;
  /* Replace the entry with a fresh buffer for next recvmmsg call */
  socket_recvmmsg_structures_fill_entry_with_buffer (priv->interface,
    message_data, &priv->message_headers[packet_index]);
  return result;
}

/* This ensures no references to any buffers are present for this socket.
   If this function is called the mem_interface may be changed, as long as it
   happens before any more data is received or sent (practically while the agent
   lock is locked). It is safe to call this function even if no MessageInterface
   has been set earlier, and thus no buffers are in need of beeing cleaned up. */
void nice_udp_socket_buffers_and_interface_unref(NiceSocket *udp_socket)
{
  struct UdpBsdSocketPrivate *priv = udp_socket->priv;
  MemlistInterface *memory_interface = priv->interface;
  for(int i = 0; i < NICE_UDP_SOCKET_MMSG_TOTAL; i++)
  {
    MessageData* msgdata = &(priv->message_datas[i]);
    struct mmsghdr *message_header = &(priv->message_headers[i]);

    if (msgdata != NULL){
      if (msgdata->buffer != NULL){
        memory_interface->buffer_return(memory_interface, msgdata->buffer);
      }
      msgdata->iovec.iov_len = 0;
      msgdata->iovec.iov_base = NULL;

      memset(message_header, 0, sizeof(struct mmsghdr));

      memory_interface->buffer_return(memory_interface, priv->message_datas[i].buffer);
      priv->message_datas[i].buffer = NULL;
    }
  }
  /* Currently we don't manage buffers when not recvmmsg is supported.
     This may change in the future. However until then do nothing here. */
  priv->interface = NULL;
}

static void socket_recvmmsg_structures_clean_up(NiceSocket *udp_socket)
{
  struct UdpBsdSocketPrivate *priv = udp_socket->priv;
  if (priv->message_datas != NULL)
  {
    free(priv->message_datas);
  }
  if (priv->message_headers != NULL)
  {
    free(priv->message_headers);
  }
  /* priv->interface is owned by agent, which again owns (indirectly) this udp
     connection. Therefore this connection does not reference count the
     interface, but rather piggybacks the ownership of the agent */
}

static void socket_recvmmsg_structures_fill_entry_with_buffer(MemlistInterface *memory_interface,
  MessageData *message_data, struct mmsghdr *hdr)
{
  if (message_data->buffer == NULL)
  {
    message_data->buffer = memory_interface->buffer_get(memory_interface, NICE_UDP_SOCKET_BUFFER_ALLOC_SIZE);
  }

  gsize buffer_size = memory_interface->buffer_size(memory_interface, message_data->buffer);
  message_data->iovec.iov_len = buffer_size;
  message_data->iovec.iov_base = memory_interface->buffer_contents(memory_interface, message_data->buffer);
  hdr->msg_len = buffer_size;

}

static void socket_recvmmsg_structures_set_up(NiceSocket *udp_socket)
{
  struct UdpBsdSocketPrivate *priv = udp_socket->priv;
  MemlistInterface *memory_interface = priv->interface;

  for(int i = 0; i < NICE_UDP_SOCKET_MMSG_TOTAL; i++)
  {
    MessageData *message_data = &priv->message_datas[i];
    struct mmsghdr *hdr = &priv->message_headers[i];

    hdr->msg_hdr.msg_control = NULL;
    hdr->msg_hdr.msg_controllen = 0;
    hdr->msg_hdr.msg_iovlen = 1;
    hdr->msg_hdr.msg_iov = &message_data->iovec;
    hdr->msg_hdr.msg_name = (struct sockaddr *) &message_data->remote;
    hdr->msg_hdr.msg_namelen = sizeof (struct sockaddr_storage);

    if (memory_interface != NULL){
      socket_recvmmsg_structures_fill_entry_with_buffer(memory_interface, message_data, hdr);
    } else {
      message_data->iovec.iov_len = 0;
      message_data->iovec.iov_base = NULL;
      hdr->msg_len = 0;
    }
  }
}

static void socket_recvmmsg_structures_fill_new_buffers(NiceSocket *udp_socket, guint iter_start, guint iter_end)
{
  struct UdpBsdSocketPrivate *priv = udp_socket->priv;
  MemlistInterface *memory_interface = priv->interface;
  g_assert(iter_start < iter_end);
  g_assert(iter_end < NICE_UDP_SOCKET_MMSG_TOTAL);
  g_assert(memory_interface != NULL);

  for(int i = iter_start; i < iter_end; i++)
  {
    MessageData *message_data = &priv->message_datas[i];
    struct mmsghdr *hdr = &priv->message_headers[i];

    socket_recvmmsg_structures_fill_entry_with_buffer(memory_interface, message_data, hdr);
  }
}

#else

void nice_udp_socket_buffers_and_interface_unref(NiceSocket *udp_socket)
{
  (void) udp_socket;
}
void clean_up_recvmmsg_structures(NiceSocket *udp_socket)
{
  (void)udp_socket;
}
void socket_recvmmsg_structures_set_up(NiceSocket *udp_socket)
{
  (void)udp_socket;
}
NiceMemoryBufferRef *nice_udp_socket_packet_retrieve(NiceSocket *udp_socket,
  guint packet_index, NiceAddress *from)
{
  (void)udp_socket;
  (void)packet_index;
  (void)from;
  return NULL;
}
gint nice_udp_socket_recvmmsg(NiceSocket *sock, gsize * num_messages_received)
{
  (void)sock;
  num_messages_received = 0;
  return -ENOTSUP;
}
#endif