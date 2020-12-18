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


#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "udp-bsd.h"
#include "errno.h"
#include "agent-priv.h"
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#include <gst/gst.h>
#define MAX_BUFFER_SIZE 65536

static void socket_attach (NiceSocket* sock, GMainContext* ctx);
static gboolean socket_close (NiceSocket *sock);
static void socket_closed (NiceSocket *sock, int result);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gint socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);
static int socket_get_fd (NiceSocket *sock);

static gboolean
socket_request_recv (NiceSocket *sock, const char * buf, gsize buflen,
                     NiceDestroyUserdataCallback * destroy_callback,
                     gpointer * destroy_userdata);

static void
socket_recvmsg_callback(NiceSocket *sock, struct msghdr * msg, int result);

static gboolean
socket_request_send (NiceSocket *sock, const NiceAddress *to, const char * buf,
                     gsize buflen,
                     NiceDestroyUserdataCallback destroy_callback,
                     gpointer destroy_userdata);

static void
socket_sendmsg_callback (NiceSocket *sock,  struct msghdr * msg, int result);

static void
socket_dispose_callback (NiceSocket *sock, GAsyncConnectionSocket *async_socket);

static void
socket_teardown_callback (NiceSocket *sock);

typedef struct _NiceAsyncPendingWriteOperation NiceAsyncPendingWriteOperation;
/* If destroy callback is local_send_buffer_destroy the embedded buffer is used */
struct _NiceAsyncPendingWriteOperation
{
  GSFListElement element;
  NiceSocket *socket;
  gsize buflen;
  gsize alloc_buflen;
  NiceDestroyUserdataCallback destroy_callback;
  gpointer * destroy_userdata;
  NiceAddress to;
  struct msghdr msg;
  struct iovec io;
  gchar* buffer; /* This is either a buffer pointer or an embedded buffer that
                    continues after the struct for alloc_buflen-sizeof(gchar*) */
};

static const NiceSocketFunctionTable socket_functions = {
    .send = socket_send,
    .recv = socket_recv,
    .request_recv = socket_request_recv,
    .recv_callback = socket_recvmsg_callback,
    .request_send = socket_request_send,
    .send_callback = socket_sendmsg_callback,
    .closed_callback = socket_closed,
    .dispose_callback = socket_dispose_callback,
    .teardown_callback = socket_teardown_callback,
    .is_reliable = socket_is_reliable,
    .close = socket_close,
    .get_fd = socket_get_fd,
    .attach = socket_attach,
};

struct UdpBsdSocketPrivate
{
  NiceAgent *agent;
  NiceAddress niceaddr;
  NiceAddress peer_niceaddr;
  struct sockaddr_storage listen_address;
  struct sockaddr_storage peer_address;
  SocketRXCallback    rxcb;
  SocketTXCallback    txcb;
  gpointer            userdata;
  GDestroyNotify      destroy_notify;

  NiceDestroyUserdataCallback recv_buffer_destroy_notify;
  gpointer recv_buffer_destroy_userdata;

  //NiceDestroyUserdataCallback send_buffer_destroy_notify;
  //gpointer send_buffer_destroy_userdata;

  guint stream_id;
  guint component_id;

  gchar *recv_buffer;
  //gchar *send_buffer;
  //gsize *send_buffer_len;

  //struct msghdr sendmsg;
  //struct iovec sendvec;
  NiceAsyncPendingWriteOperation* current_write_operation;
  NiceAsyncPendingWriteOperation* socket_write_operation;
  gboolean pendingwrites;

  struct msghdr recvmsg;
  struct iovec recvvec;
  /* To avoid deadlock never lock agent while holding privlock,
     allways release privlock first and lock privlock again when holding
     the agent lock */
  GMutex lock;

};

void local_send_buffer_destroy(gpointer buffer, gpointer userdata)
{
  (void) buffer;
  (void) userdata;
  /* The write buffers are not destroyed here. They are kept around for future
     writes and eventually destroyed as part of the udp socket or agent */
#if 0
  NiceSocket *sock = (NiceSocket*) userdata;
  struct UdpBsdSocketPrivate *priv = sock->priv;

  if (buffer == priv->send_buffer)
  {
    g_assert(priv->send_buffer);
    g_free(priv->send_buffer);
    priv->send_buffer = NULL;
    priv->send_buffer_destroy_notify = NULL;
  }
  else
  {

  }
#endif
}

NiceSocket *
nice_udp_bsd_socket_new (NiceAgent * agent, NiceAddress *addr,
  guint stream_id, guint component_id,
  SocketRXCallback rxcb, SocketTXCallback txcb, gpointer userdata,
  GDestroyNotify destroy_notify)
{
  struct sockaddr_storage name;
  NiceSocket *sock = g_slice_new0 (NiceSocket);
  GSocket *gsock = NULL;
  gboolean gret = FALSE;
  GSocketAddress *gaddr;
  struct UdpBsdSocketPrivate *priv;

  sock->functions = &socket_functions;
  if (addr != NULL) {
    nice_address_copy_to_sockaddr(addr, (struct sockaddr *)&name);
  } else {
    memset (&name, 0, sizeof (name));
    name.ss_family = AF_UNSPEC;
  }

#if 0
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

#endif
  nice_address_set_from_sockaddr (&sock->addr, (struct sockaddr *)&name);

  GAsyncConnectionSocket * conn_sock =  \
    gasync_gasync_create_connection_socket (agent->async,
      NULL, NULL, name.ss_family, SOCK_DGRAM, NULL);

  //nice_agent_set_userdata_wrapper
  void ** socket_userdata_ptr = gasync_connection_socket_get_userdata_ptr(conn_sock);
  *socket_userdata_ptr = sock;

  if (agent->async_userdata_wrapper)
  {
    agent->async_userdata_wrapper(agent, socket_userdata_ptr);
  }

  int conn_socket_fd = gasync_connection_socket_get_fd (conn_sock);

  /* Set up a test server for our library to connect to */
  int errcode = bind (conn_socket_fd, (const struct sockaddr *) &name,
      sizeof (name));
  /* TODO: Should we propagate the errors instead of asserting */
  g_assert (errcode == 0);


  priv = sock->priv = g_slice_new0 (struct UdpBsdSocketPrivate);
  nice_address_init (&priv->niceaddr);

  unsigned int len = sizeof (struct sockaddr_storage);
  g_assert (getsockname (conn_socket_fd, (struct sockaddr *) &priv->listen_address,
          &len) == 0);

  priv->rxcb = rxcb;
  priv->txcb = txcb;
  priv->agent = agent;
  priv->userdata = userdata;
  priv->destroy_notify = destroy_notify;
  priv->stream_id = stream_id;
  priv->component_id = component_id;

  priv->recv_buffer = NULL;
  priv->recv_buffer_destroy_notify = NULL;

  // priv->socket_write_operation =
  g_mutex_init(&priv->lock);

  sock->type = NICE_SOCKET_TYPE_UDP_BSD;
  sock->transport.connection = conn_sock;


  return sock;
}

static gboolean
nice_udp_bsd_socket_find_queued_write_operations_visitor(
  GSFListElement *current_element, gpointer userdata)
{
  NiceAsyncPendingWriteOperation *current_operation = (NiceAsyncPendingWriteOperation*) current_element;
  NiceSocket *sock = (NiceSocket*) userdata;
  return sock == current_operation->socket;
}

static gboolean
nice_udp_bsd_socket_equals_visitor(
  GSFListElement *current_element, gpointer userdata)
{
  return current_element == userdata;
}

static gboolean
socket_close (NiceSocket *sock)
{
  struct UdpBsdSocketPrivate *priv = sock->priv;
  g_mutex_lock(&priv->lock);
  if (priv->recv_buffer)
  {
    g_assert(priv->recv_buffer_destroy_notify);
    priv->recv_buffer_destroy_notify(priv->recv_buffer,
      priv->recv_buffer_destroy_userdata);
    priv->recv_buffer = NULL;
    priv->recv_buffer_destroy_userdata = NULL;
    priv->recv_buffer_destroy_notify = NULL;
  } else if (priv->recv_buffer_destroy_userdata)
  {
    /* Make sure the caller has an opportunity to free userdata */
    priv->recv_buffer_destroy_notify(NULL, priv->recv_buffer_destroy_userdata);
    priv->recv_buffer_destroy_userdata = NULL;
    priv->recv_buffer_destroy_notify = NULL;
  }

  /* TODO: Should we actually remove the pending writes instead of just asserting */
  GSFList * overflow_list = &priv->agent->async_write_overflow;
  g_assert(gsflist_visit_exit(overflow_list->head, nice_udp_bsd_socket_find_queued_write_operations_visitor, sock) == NULL);

  if(priv->socket_write_operation &&
     (priv->socket_write_operation->destroy_callback != local_send_buffer_destroy))
  {
      g_assert(priv->socket_write_operation->destroy_callback);
      priv->socket_write_operation->destroy_callback(priv->socket_write_operation->buffer,
        priv->socket_write_operation->destroy_userdata);
  }

  /* TODO: Clean up any outstanding receive async request */
  g_slice_free (struct UdpBsdSocketPrivate, sock->priv);

  if (sock->transport.fileno) {
    //g_socket_close (sock->transport.fileno, NULL);
    gasync_connection_socket_close( sock->transport.connection ); // NB / TODO: Should wait for close to complete
    gasync_connection_socket_tear_down( sock->transport.connection );
    //g_object_unref (sock->transport.fileno);
    //sock->transport.fileno = NULL;
  }
  g_mutex_unlock(&priv->lock);

  return TRUE;
}

static void
socket_closed (NiceSocket *sock, int result)
{
  (void)sock;
  (void)result;
}

static void
socket_dispose_callback (NiceSocket *sock, GAsyncConnectionSocket *async_socket)
{
  //struct UdpBsdSocketPrivate *priv = sock->priv;
  //g_object_unref(async_socket);
  //g_slice_free (NiceSocket, sock);
}

static void
socket_teardown_callback (NiceSocket *sock)
{
  if (sock->transport.fileno) {
    //g_object_unref (sock->transport.fileno);
    sock->transport.fileno = NULL;
  }
}




/* Start trying to receive data */
static void socket_attach (NiceSocket* sock, GMainContext* ctx)
{
  gchar *recv_buffer = NULL;
  NiceDestroyUserdataCallback buffer_destroy_notify;
  gpointer buffer_destroy_userdata;
  struct UdpBsdSocketPrivate *priv = sock->priv;
  (void)ctx;
  (void)priv;
  g_mutex_lock(&priv->lock);
  if (priv->recv_buffer != NULL)
  {
    g_mutex_unlock(&priv->lock);
    return; /* TODO: Do we need to release this buffer
               and allocate a new one? */
  }
  priv->agent->request_rx_buffer_callback(priv->agent,
    priv->stream_id, priv->component_id, MAX_BUFFER_SIZE, &recv_buffer,
    &buffer_destroy_notify,
    &buffer_destroy_userdata,
    priv->agent->request_rx_buffer_callback_userdata
    );
  if (recv_buffer != NULL)
  {
    g_assert(buffer_destroy_notify != NULL);
    priv->recv_buffer = recv_buffer;
    priv->recv_buffer_destroy_notify = buffer_destroy_notify;
    priv->recv_buffer_destroy_userdata = buffer_destroy_userdata;
    /* Do first recv to start receiving from socket */
    g_mutex_unlock(&priv->lock);
    socket_request_recv(sock, priv->recv_buffer, MAX_BUFFER_SIZE, NULL,
    NULL);
  }
  else
  {
    g_mutex_unlock(&priv->lock);
  }

}
static gsize get_namelen(struct sockaddr_storage const * const addr)
{
  if(addr->ss_family == AF_INET)
  {
    return sizeof(struct sockaddr_in);
  }
  else if(addr->ss_family == AF_INET6)
  {
    return sizeof(struct sockaddr_in6);
  }
  else
  {
    g_assert(FALSE);
    return 0;
  }
}
/* Currently we only use one iovec entry, we may want to refactor this in the
   future when uring using buffer pools to account for the fact that most
   packets are not full 64k size */
static gboolean
socket_request_recv (NiceSocket *sock, const char * buf, gsize buflen,
                     NiceDestroyUserdataCallback * destroy_callback,
                     gpointer * destroy_userdata)
{
  (void) destroy_callback;
  struct UdpBsdSocketPrivate *priv = sock->priv;
  g_mutex_lock(&priv->lock);
  /* Use iovlen to determine if msg, and thus operation is busy */
  if (priv->recvmsg.msg_iovlen != 0)
  {
    g_mutex_unlock(&priv->lock);
    return FALSE;
  }
  if (priv->recv_buffer && priv->recv_buffer != buf)
  {
    priv->recv_buffer_destroy_notify ( priv->recv_buffer, priv->recv_buffer_destroy_userdata);
    priv->recv_buffer_destroy_notify = NULL;
    priv->recv_buffer_destroy_userdata = NULL;
    priv->recv_buffer = NULL;
  }
  if (destroy_callback != NULL)
  {
    priv->recv_buffer_destroy_notify = destroy_callback;
    priv->recv_buffer_destroy_userdata = destroy_userdata;
  }
  memset (&priv->recvmsg, 0, sizeof (struct msghdr));
  memset (buf, 0, buflen); // Satisfy valgrind
  priv->recvmsg.msg_name = &priv->peer_address;
  priv->recvmsg.msg_namelen = get_namelen(&sock->addr);
  priv->recvmsg.msg_iov = &priv->recvvec;
  priv->recvmsg.msg_iovlen = 1;
  priv->recvvec.iov_base = (guint8 *) buf;
  priv->recvvec.iov_len = buflen;
  priv->recvmsg.msg_iovlen = 1;
  GST_DEBUG("Udp socket recv request: %p: %d", sock, buflen);
  g_mutex_unlock(&priv->lock);
  return gasync_connection_socket_recvmsg(sock->transport.connection, &priv->recvmsg,
    0);
}

static void
socket_recvmsg_callback(NiceSocket *sock, struct msghdr * msg, int result)
{
  NiceDestroyUserdataCallback buffer_destroy_notify;
  gpointer buffer_destroy_userdata;
  gboolean transfered_ownership;
  NiceAddress *from;
  struct UdpBsdSocketPrivate *priv = sock->priv;
  if (result < 0) {
    if ( result == -ECANCELED )
    {
      /* Clean up receive buffer */
      g_mutex_lock(&priv->lock);
      if (priv->recv_buffer_destroy_notify)
      {
        buffer_destroy_notify( priv->recv_buffer_destroy_notify, priv->recv_buffer_destroy_userdata);
        priv->recv_buffer = NULL;
      }
      g_mutex_unlock(&priv->lock);
      return;
    }
    else
    {
      g_assert(result == 0); //TODO: Update list of acceptable errors during testing
    }
  }
  g_mutex_lock(&priv->lock);
  GST_DEBUG("Udp socket recv callback: %p (%d): %d", sock, msg->msg_iov->iov_len, result);

  if (result > 0 && msg->msg_name != NULL) {
    struct sockaddr_storage sa;
    g_assert (msg->msg_namelen >= sizeof (struct sockaddr_in));
    nice_address_set_from_sockaddr (&priv->peer_niceaddr, (struct sockaddr *)msg->msg_name);
  }

  g_assert(msg->msg_iovlen == 1); // Currently we use only one io buffer
  priv->recvmsg.msg_iovlen = 0;

  /* recv buffer is given to rxcb, and is not owned by the socket anymore */
  priv->recv_buffer = NULL;
  buffer_destroy_notify = priv->recv_buffer_destroy_notify;
  buffer_destroy_userdata =  priv->recv_buffer_destroy_userdata;
  priv->recv_buffer_destroy_notify = NULL;
  priv->recv_buffer_destroy_userdata = NULL;

  g_mutex_unlock(&priv->lock);
  // How to handle freeing gstreamer buffers used internally for setting up the ice connection?
  transfered_ownership = priv->rxcb(sock, &priv->peer_niceaddr, msg, msg->msg_iov->iov_base,
    result, buffer_destroy_userdata, priv->userdata);

  if (buffer_destroy_userdata)
  {
    /* Make sure the caller has an opportunity to free userdata */
    gpointer recv_buffer;
    if (transfered_ownership)
    {
      recv_buffer = NULL;
    }
    else
    {
      recv_buffer = msg->msg_iov->iov_base;
    }

    buffer_destroy_notify( recv_buffer, buffer_destroy_userdata);
  }
  socket_attach(sock, NULL); /* Request to receive another packet */
}

static void socket_send_enqueued(NiceSocket *sock)
{
  struct UdpBsdSocketPrivate *priv = sock->priv;
  /* Dequeue queued send operations */
  agent_lock (priv->agent);
  g_mutex_lock(&priv->lock);
  /* A new operation was queued while the priv was unlocked, so don't enqueue,
     wait for that to finish */
  if (priv->current_write_operation)
  {
    g_mutex_unlock(&priv->lock);
    agent_unlock (priv->agent);
    return;
  }

  GSFList * overflow_list = &priv->agent->async_write_overflow;
  /* Should not be put in the free list until the sendmsg callback is completed */
  GSFListElement *enqueued_element = gsflist_visit_exit(overflow_list, nice_udp_bsd_socket_find_queued_write_operations_visitor, sock);

  if (enqueued_element == NULL)
  {
    /* No pending writes */
    priv->pendingwrites = FALSE;
    priv->current_write_operation = NULL;
  }
  else
  {
    NiceAsyncPendingWriteOperation* enqueued_operation = (NiceAsyncPendingWriteOperation*) enqueued_element;
    priv->current_write_operation = enqueued_operation;
    g_assert(gasync_connection_socket_sendmsg(sock->transport.connection, &enqueued_operation->msg,
        0));
  }
  g_mutex_unlock(&priv->lock);
  agent_unlock (priv->agent);
}

static gboolean
socket_request_send_internal (NiceSocket *sock, const NiceAddress *to, const char * buf,
                     gsize buflen,
                     NiceDestroyUserdataCallback destroy_callback,
                     gpointer destroy_userdata, gboolean copy_buffer)
{
  NiceAsyncPendingWriteOperation *write_operation;
  struct msghdr *sendmsg;
  struct iovec *io;
  struct UdpBsdSocketPrivate *priv = sock->priv;
  gchar *buffer;

  gsize alloc_bufextra;
  if (copy_buffer)
  {
    alloc_bufextra = buflen - sizeof(gchar);
  }
  else
  {
    alloc_bufextra = 0;
  }

  g_mutex_lock(&priv->lock);
  gboolean enqueue = priv->current_write_operation != NULL;

  if (enqueue)
  {
    g_mutex_unlock(&priv->lock);
    agent_lock (priv->agent);
    g_mutex_lock(&priv->lock);
    priv->pendingwrites = TRUE;

    /* Add sendmsg data to overflow list,
       to send when this operation is complete. */
    GSFList * overflow_list = &priv->agent->async_write_overflow;

    if (overflow_list->free_head == NULL)
    {
      /* No more free operations available, allocate new operation */
      write_operation = g_malloc0(sizeof(NiceAsyncPendingWriteOperation) + alloc_bufextra);
      write_operation->alloc_buflen = buflen;
      (void) gsflist_append_new(overflow_list, (GSFListElement*) write_operation, 0, NULL);
    } else {
      NiceAsyncPendingWriteOperation **tail_next_ptr;
      write_operation = (NiceAsyncPendingWriteOperation *)gsflist_append_free (overflow_list, sizeof(NiceAsyncPendingWriteOperation), (GSFListElement***)&tail_next_ptr);
      if (write_operation->alloc_buflen < buflen)
      {
        /* Reallocate a bigger buffer */
        g_assert(copy_buffer);
        *tail_next_ptr = g_realloc (*tail_next_ptr,
               sizeof(NiceAsyncPendingWriteOperation) + alloc_bufextra);
        write_operation = *tail_next_ptr;
        write_operation->alloc_buflen = buflen;
        memset(write_operation, 0,
               sizeof(NiceAsyncPendingWriteOperation) + alloc_bufextra);
      }
    }
    agent_unlock (priv->agent);
  } else {
    if (priv->socket_write_operation == NULL)
    {
        priv->socket_write_operation = g_malloc0 (sizeof(NiceAsyncPendingWriteOperation) + alloc_bufextra);
        priv->socket_write_operation->alloc_buflen = copy_buffer ? buflen : alloc_bufextra;
    }
    write_operation = priv->socket_write_operation;

    if (copy_buffer)
    {
      if (write_operation->alloc_buflen <= buflen)
      {
        write_operation->alloc_buflen = buflen;
        priv->socket_write_operation = write_operation = g_realloc (
          write_operation,
          sizeof(NiceAsyncPendingWriteOperation) + alloc_bufextra);
        memset(write_operation, 0, sizeof(NiceAsyncPendingWriteOperation) + alloc_bufextra);
      }
    }
  }

  if (to != NULL)
  {
    memset(&write_operation->to, 0, sizeof(struct sockaddr_in));
    nice_address_copy_to_sockaddr (to, (struct sockaddr_in *)&write_operation->to);
  }
  else
  {
    /* TODO: What is it that makes sense to do here */
    memcpy(&write_operation->to, &priv->peer_address, sizeof(struct sockaddr_in));
    g_assert(FALSE);
  }

  write_operation->buflen = buflen;

  if (copy_buffer)
  {
    write_operation->destroy_callback = local_send_buffer_destroy;
    write_operation->destroy_userdata = NULL;
    buffer = (gchar*)&write_operation->buffer;
    memcpy(buffer, buf, buflen);
  }
  else
  {
    g_assert(destroy_callback != local_send_buffer_destroy);
    write_operation->destroy_callback = destroy_callback;
    write_operation->destroy_userdata = destroy_userdata;
    buffer = write_operation->buffer = buf;
  }

  sendmsg = &write_operation->msg;
  io = &write_operation->io;

  memset (sendmsg, 0, sizeof (struct msghdr));
  sendmsg->msg_name = &write_operation->to;
  sendmsg->msg_namelen = get_namelen(&write_operation->to);
  sendmsg->msg_iov = io;
  sendmsg->msg_iovlen = 1;
  io->iov_base = (guint8 *) buffer;
  io->iov_len = buflen;

  /* Makes it possible to match with the socket during iterations of the list */
  write_operation->socket = sock;

  if (enqueue)
  {
    g_mutex_unlock(&priv->lock);
    /* Send enqueued if the current write operation was completed while
       we were unlocked */
    socket_send_enqueued(sock);
    return TRUE;
  }
  else
  {
    gboolean sendmsgret;
    priv->current_write_operation = write_operation;
    sendmsgret = gasync_connection_socket_sendmsg(sock->transport.connection, sendmsg,
      0);
    g_mutex_unlock(&priv->lock);
    return sendmsgret;
  }
}

static gboolean
socket_request_send (NiceSocket *sock, const NiceAddress *to, const char * buf,
                     gsize buflen,
                     NiceDestroyUserdataCallback destroy_callback,
                     gpointer destroy_userdata)
{
  return socket_request_send_internal(sock, to, buf, buflen, destroy_callback, destroy_userdata, FALSE);
}

static void
socket_sendmsg_callback (NiceSocket *sock,  struct msghdr * msg, int result)
{
  NiceDestroyUserdataCallback destroy_callback;
  gpointer destroy_userdata ;
  gboolean ownership_transferred;
  struct UdpBsdSocketPrivate *priv = sock->priv;
  if (result < 0) {
    g_assert(result == 0); //TODO: Update list of acceptable errors during testing
  }

  g_mutex_lock(&priv->lock);
  NiceAsyncPendingWriteOperation * completed_write_operation = priv->current_write_operation;
  GST_DEBUG("Udp socket send callback: %p (%d): %d", sock, msg->msg_iov->iov_len, result);

  g_assert(msg->msg_iovlen == 1); // Currently we use only one io buffer

  gboolean was_enqueued = completed_write_operation != priv->socket_write_operation;
   //msg != priv->csendmsg;

  //priv->sendmsg.msg_iovlen = 0;
  if (priv->txcb)
  {
    g_mutex_unlock(&priv->lock);
    ownership_transferred = priv->txcb(sock, msg->msg_iov->iov_base,
      msg->msg_iov->iov_len, 0, priv->userdata);
    g_mutex_lock(&priv->lock);
  } else
  {
    ownership_transferred = FALSE;
  }
  if (completed_write_operation->destroy_callback != local_send_buffer_destroy)
  {
    completed_write_operation->destroy_callback(
      ownership_transferred ? NULL : msg->msg_iov->iov_base,
      completed_write_operation->destroy_userdata);

    completed_write_operation->buffer = NULL;
  }
  /* Make sure write operation is not enqueued before it is freed */
  completed_write_operation->socket = NULL;
  priv->current_write_operation = NULL;
  g_mutex_unlock(&priv->lock);

  if(was_enqueued)
  {
    agent_lock (priv->agent);
    g_mutex_lock(&priv->lock);

    GSFList * overflow_list = &priv->agent->async_write_overflow;
    gsflist_visit_all_and_free(overflow_list, nice_udp_bsd_socket_equals_visitor, completed_write_operation, FALSE);

    g_mutex_unlock(&priv->lock);
    agent_unlock (priv->agent);
  }

  /* If there are more queued operations make sure they are sent */
  socket_send_enqueued(sock);
}

#if 0
  if(was_enqueued){
  }
  else
  {
    destroy_callback = priv->send_buffer_destroy_notify;
    destroy_userdata = priv->send_buffer_destroy_userdata;
  }
#endif

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
#if 0
  GSocketAddress *gaddr = NULL;
  GError *gerr = NULL;
  gint recvd;

  recvd = g_socket_receive_from (sock->transport.fileno, &gaddr, buf, len, NULL, &gerr);

  if (recvd < 0) {
    if (g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)
        || g_error_matches(gerr, G_IO_ERROR, G_IO_ERROR_FAILED))
      recvd = 0;

    g_error_free (gerr);
  }

  if (recvd > 0 && from != NULL && gaddr != NULL) {
    struct sockaddr_storage sa;

    //g_socket_address_to_native (gaddr, &sa, sizeof (sa), NULL);
    nice_address_set_from_sockaddr (from, (struct sockaddr *)&sa);
  }

  if (gaddr != NULL)
    g_object_unref (gaddr);

  return recvd;
#else
  return 0;
#endif

}

static gint
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  //struct UdpBsdSocketPrivate *priv = sock->priv;
  if(socket_request_send_internal(sock, to, buf, len, local_send_buffer_destroy, sock, TRUE)) // TODO: Use callback
  {
    GST_DEBUG("Udp socket send queued: %p (%d)", sock, len);
    /* Wherever this is used must be updated to ignore it, or wait for
    the async response */
    return -1;
  }
  else
  {
    //g_assert(false);
    GST_INFO("Udp socket send failed: %p (%d)", sock, len);
    return -2;
  }
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return FALSE;
}

static int
socket_get_fd (NiceSocket *sock)
{
  return sock->transport.connection ? gasync_connection_socket_get_fd (sock->transport.connection) : -1;
}
