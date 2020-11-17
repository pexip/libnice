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

#include <gst/gst.h>

#include "tcp-established.h"
#include "agent-priv.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

GST_DEBUG_CATEGORY_EXTERN (niceagent_debug);
#define GST_CAT_DEFAULT niceagent_debug

#define MAX_BUFFER_SIZE 65535

typedef struct {
  NiceAgent          *nice_agent;
  NiceAddress         remote_addr;
  GQueue              send_queue;
  GMainContext       *context;
  GSource            *read_source;
  GSource            *write_source;
  gboolean            error;
  SocketRXCallback    rxcb;
  SocketTXCallback    txcb;
  gpointer            userdata;
  GDestroyNotify      destroy_notify;
  guint8              recv_buff[MAX_BUFFER_SIZE];
  guint               recv_offset;
  gboolean            connect_pending;
  guint               max_tcp_queue_size;
  gint                tx_queue_size_bytes;
  gboolean            rx_enabled;
} TcpEstablishedPriv;

struct to_be_sent {
  guint length;
  gchar *buf;
};

typedef struct {
  NiceAgent          *nice_agent;
  NiceSocket         *sock;
} TcpEstablishedCallbackData;

static void socket_attach (NiceSocket* sock, GMainContext* ctx);
static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gint socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);


static void add_to_be_sent (NiceSocket *sock, const gchar *buf, guint len, gboolean add_to_head);
static void free_to_be_sent (struct to_be_sent *tbs);
static gboolean socket_send_more (GSocket *gsocket, GIOCondition condition,
                                  gpointer data);
static gboolean socket_recv_more (GSocket *gsocket, GIOCondition condition,
                                  gpointer data);
static gint socket_get_tx_queue_size (NiceSocket *sock);
static void socket_set_rx_enabled (NiceSocket *sock, gboolean enabled);
static int socket_get_fd (NiceSocket *sock);

static const NiceSocketFunctionTable socket_functions = {
    .send = socket_send,
    .recv = socket_recv,
    .is_reliable = socket_is_reliable,
    .close = socket_close,
    .get_fd = socket_get_fd,
    .attach = socket_attach,
    .get_tx_queue_size = socket_get_tx_queue_size,
    .set_rx_enabled = socket_set_rx_enabled,
};

static TcpEstablishedCallbackData *
tcp_established_callback_data_new (NiceAgent *agent, NiceSocket *sock)
{
  TcpEstablishedCallbackData *result = g_new0(TcpEstablishedCallbackData, 1);
  result->nice_agent = agent;
  result->sock = sock;
  return result;
}

static void
tcp_established_callback_data_free (TcpEstablishedCallbackData *p)
{
  g_free (p);
}

NiceSocket *
nice_tcp_established_socket_new (GSocket *gsock, GObject *nice_agent,
    NiceAddress *local_addr, const NiceAddress *remote_addr, GMainContext *ctx,
    SocketRXCallback rxcb, SocketTXCallback txcb, gpointer userdata,
    GDestroyNotify destroy_notify, gboolean connect_pending, guint max_tcp_queue_size)
{
  NiceSocket *sock;
  TcpEstablishedPriv *priv;

  g_return_val_if_fail (G_IS_SOCKET (gsock), NULL);
  g_return_val_if_fail (rxcb != NULL, NULL);
  g_return_val_if_fail (txcb != NULL, NULL);

  sock = g_slice_new0 (NiceSocket);
  sock->priv = priv = g_slice_new0 (TcpEstablishedPriv);

  priv->nice_agent = NICE_AGENT (nice_agent);
  priv->context = g_main_context_ref (ctx);
  priv->remote_addr = *remote_addr;
  priv->rxcb = rxcb;
  priv->txcb = txcb;
  priv->userdata = userdata;
  priv->destroy_notify = destroy_notify;
  priv->recv_offset = 0;
  priv->connect_pending = connect_pending;
  priv->max_tcp_queue_size = max_tcp_queue_size;
  priv->rx_enabled = TRUE;

  sock->type = NICE_SOCKET_TYPE_TCP_ESTABLISHED;
  sock->transport.fileno = gsock;
  sock->addr = *local_addr;
  sock->functions = &socket_functions;

  if (max_tcp_queue_size > 0) {
    /*
     * Reduce the tx queue size so the minimum number of packets
     * are queued in the kernel
     */
    gint fd = g_socket_get_fd (gsock);
    gint sendbuff = 2048;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof (gint));
  }

  priv->read_source = g_socket_create_source(sock->transport.fileno, G_IO_IN | G_IO_ERR, NULL);
  g_source_set_callback (priv->read_source, (GSourceFunc) socket_recv_more,
                         tcp_established_callback_data_new(priv->nice_agent, sock),
                         (GDestroyNotify)tcp_established_callback_data_free);
  g_source_attach (priv->read_source, priv->context);
  return sock;
}

static void
socket_attach (NiceSocket* sock, GMainContext* ctx)
{
  TcpEstablishedPriv *priv = sock->priv;
  g_assert(priv->context == ctx);
#if 0
  TcpEstablishedPriv *priv = sock->priv;
  gboolean write_pending = FALSE;

  if (priv->context)
    g_main_context_unref (priv->context);

  if (priv->read_source) {
    g_source_destroy (priv->read_source);
    g_source_unref (priv->read_source);
  }

  if (priv->write_source) {
    write_pending = TRUE;
    g_source_destroy (priv->write_source);
    g_source_unref (priv->write_source);
  }

  priv->context = ctx;
  if (priv->context) {
    g_main_context_ref (priv->context);

    priv->read_source = g_socket_create_source(sock->transport.fileno, G_IO_IN | G_IO_ERR, NULL);
    g_source_set_callback (priv->read_source, (GSourceFunc) socket_recv_more,
                           tcp_established_callback_data_new(priv->nice_agent, sock),
                           (GDestroyNotify)tcp_established_callback_data_free);
    g_source_attach (priv->read_source, priv->context);
    if (write_pending) {
        priv->write_source = g_socket_create_source(sock->transport.fileno, G_IO_OUT, NULL);
        g_source_set_callback (priv->write_source, (GSourceFunc) socket_send_more,
                               tcp_established_callback_data_new(priv->nice_agent, sock),
                               (GDestroyNotify)tcp_established_callback_data_free);
        g_source_attach (priv->write_source, priv->context);
    }
  }
#endif
}

static void
socket_close (NiceSocket *sock)
{
  TcpEstablishedPriv *priv = sock->priv;
  NiceAgent *agent = priv->nice_agent;

  g_assert (agent->agent_mutex_th != NULL);

  if (sock->transport.fileno) {
    g_socket_close (sock->transport.fileno, NULL);
    g_object_unref (sock->transport.fileno);
    sock->transport.fileno = NULL;
  }
  if (priv->read_source) {
    g_source_destroy (priv->read_source);
    g_source_unref (priv->read_source);
  }
  if (priv->write_source) {
    g_source_destroy (priv->write_source);
    g_source_unref (priv->write_source);
  }
  g_queue_foreach (&priv->send_queue, (GFunc) free_to_be_sent, NULL);
  g_queue_clear (&priv->send_queue);

  if (priv->userdata && priv->destroy_notify)
    (priv->destroy_notify)(priv->userdata);

  if (priv->context)
    g_main_context_unref (priv->context);

  g_slice_free(TcpEstablishedPriv, sock->priv);

  g_assert (agent->agent_mutex_th != NULL);
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  //g_assert(false);
  return 0;
}

static gint
socket_recv_internal (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  TcpEstablishedPriv *priv = sock->priv;
  int ret;
  GError *gerr = NULL;

  /* Don't try to access the socket if it had an error */
  if (priv->error)
    return -1;

  ret = g_socket_receive (sock->transport.fileno, buf, len, NULL, &gerr);

  /* recv returns 0 when the peer performed a shutdown.. we must return -1 here
   * so that the agent destroys the g_source */
  if (ret == 0) {
    priv->error = TRUE;
    return -1;
  }

  if (ret < 0) {
    if(g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
      ret = 0;

    g_error_free (gerr);
    return ret;
  }

  if (from)
    *from = priv->remote_addr;
  return ret;
}

static gint
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  TcpEstablishedPriv *priv = sock->priv;
  int ret;
  GError *gerr = NULL;
  gchar buff[MAX_BUFFER_SIZE];

  gchar to_string[NICE_ADDRESS_STRING_LEN];

  nice_address_to_string (to, to_string);

  if (nice_address_equal (to, &priv->remote_addr)) {

    /* Don't try to access the socket if it had an error, otherwise we risk a
       crash with SIGPIPE (Broken pipe) */
    if (priv->error)
      return -1;

    buff[0] = (len >> 8);
    buff[1] = (len & 0xFF);
    memcpy (&buff[2], buf, len);
    len += 2;

    /* First try to send the data, don't send it later if it can be sent now
       this way we avoid allocating memory on every send */
    if (g_socket_is_connected (sock->transport.fileno) &&
        g_queue_is_empty (&priv->send_queue)) {
      ret = g_socket_send (sock->transport.fileno, buff, len, NULL, &gerr);
      if (ret < 0) {
        if (g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
          add_to_be_sent (sock, buff, len, FALSE);
          priv->txcb (sock, buff, len, priv->tx_queue_size_bytes, priv->userdata);
          ret = len;
        }
      } else {
        guint rest = len - ret;
        if (rest > 0) {
          add_to_be_sent (sock, &buff[ret], rest, FALSE);
          ret = len;
        }
      }

      if (gerr != NULL)
        g_error_free (gerr);

      return ret;
    } else {
      add_to_be_sent (sock, buff, len, FALSE);
      if (g_socket_is_connected (sock->transport.fileno)) {
        priv->txcb (sock, buff, len, priv->tx_queue_size_bytes, priv->userdata);
      }
      return len;
    }
  } else {
    gchar remote_string [NICE_ADDRESS_STRING_LEN];

    nice_address_to_string (&priv->remote_addr, remote_string);
    return 0;
  }
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}

static void
parse_rfc4571(NiceSocket* sock, NiceAddress* from)
{
  TcpEstablishedPriv *priv = sock->priv;
  gboolean done = FALSE;

  while (!done) {
    if (priv->recv_offset > 2) {
      guint8 *data = priv->recv_buff;
      guint packet_length = data[0] << 8 | data[1];
      if (packet_length + 2 <= priv->recv_offset) {
        priv->rxcb (sock, from, (gchar *)&data[2], packet_length, priv->userdata);

        if (g_source_is_destroyed (g_main_current_source ())) {
          return;
        }

        /* More data after current packet */
        memmove (&priv->recv_buff[0], &priv->recv_buff[packet_length + 2],
                priv->recv_offset - packet_length - 2);
        priv->recv_offset = priv->recv_offset - packet_length - 2;
      } else {
        done = TRUE;
      }
    } else {
      done = TRUE;
    }
  }
}

/*
 * Returns FALSE if the source should be destroyed.
 */
static gboolean
socket_recv_more (
  GSocket *gsocket,
  GIOCondition condition,
  gpointer data)
{
  gint len;
  TcpEstablishedCallbackData *cbdata = (TcpEstablishedCallbackData *)data;
  NiceAgent *agent = cbdata->nice_agent;
  NiceSocket* sock = NULL;
  TcpEstablishedPriv *priv = NULL;
  NiceAddress from;

  agent_lock (agent);

  if (g_source_is_destroyed (g_main_current_source ())) {
    GST_DEBUG ("tcp-est %p: Source was destroyed. "
        "Avoided race condition in tcp-established.c:socket_recv_more", sock);
    agent_unlock (agent);
    return FALSE;
  } else {
    // Socket still valid
    sock = cbdata->sock;
    priv = sock->priv;
  }

  if (!priv->rx_enabled) {
    /* Socket is suspended so don't read from it */
    agent_unlock (agent);
    return TRUE;
  }

  len = socket_recv_internal (sock, &from, MAX_BUFFER_SIZE-priv->recv_offset, (gchar *)&priv->recv_buff[priv->recv_offset]);

  if (len > 0) {
    priv->recv_offset += len;
    parse_rfc4571(sock, &from);
  } else if (len < 0) {
    GST_DEBUG ("tcp-est %p: socket_recv_more: error from socket %d", sock, len);
    g_source_destroy (priv->read_source);
    g_source_unref (priv->read_source);
    priv->read_source = NULL;
    priv->error = TRUE;
    agent_unlock (agent);
    return FALSE;
  }

  agent_unlock (agent);
  return TRUE;
}

/*
 * Returns FALSE if the source should be destroyed.
 */
static gboolean
socket_send_more (
  GSocket *gsocket,
  GIOCondition condition,
  gpointer data)
{
  TcpEstablishedCallbackData *cbdata = (TcpEstablishedCallbackData *)data;
  NiceSocket *sock = NULL;
  TcpEstablishedPriv *priv = NULL;
  struct to_be_sent *tbs = NULL;
  GError *gerr = NULL;
  NiceAgent *agent = cbdata->nice_agent;

  agent_lock (agent);

  if (g_source_is_destroyed (g_main_current_source ())) {
    GST_DEBUG ("tcp-est %p: Source was destroyed. "
        "Avoided race condition in tcp-established.c:socket_send_more", sock);
    agent_unlock (agent);
    return FALSE;
  } else {
    // Socket still valid
    sock = cbdata->sock;
    priv = sock->priv;
  }

  if (priv->connect_pending) {
    /*
     * First event will be the connect result
     */
    if (!g_socket_check_connect_result (gsocket, &gerr)) {
        GST_DEBUG ("tcp-est %p: connect failed. g_socket_is_connected=%d", sock, g_socket_is_connected (sock->transport.fileno));
    }

    if (gerr) {
      g_error_free (gerr);
      gerr = NULL;
    }
    priv->connect_pending = FALSE;
  }

  while ((tbs = g_queue_pop_head (&priv->send_queue)) != NULL) {
    int ret;

    priv->tx_queue_size_bytes -= tbs->length;

    if(condition & G_IO_HUP) {
      /* connection hangs up */
      ret = -1;
    } else {
      ret = g_socket_send (sock->transport.fileno, tbs->buf, tbs->length, NULL, &gerr);
    }

    if (ret < 0) {
      if(gerr != NULL &&
          g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
        add_to_be_sent (sock, tbs->buf, tbs->length, TRUE);
        g_free (tbs->buf);
        g_slice_free (struct to_be_sent, tbs);
        g_error_free (gerr);
        break;
      }
      if (gerr) {
        g_error_free (gerr);
        gerr = NULL;
      }
    } else {
      guint rest = tbs->length - ret;
      if (rest > 0) {
        add_to_be_sent (sock, &tbs->buf[ret], rest, TRUE);
        g_free (tbs->buf);
        g_slice_free (struct to_be_sent, tbs);
        break;
      }
    }

    g_free (tbs->buf);
    g_slice_free (struct to_be_sent, tbs);
  }

  if (g_queue_is_empty (&priv->send_queue)) {
    g_source_destroy (priv->write_source);
    g_source_unref (priv->write_source);
    priv->write_source = NULL;
    priv->txcb (sock, NULL, 0, 0, priv->userdata);
    agent_unlock (agent);
    return FALSE;
  }

  agent_unlock (agent);
  return TRUE;
}

static void
add_to_be_sent (NiceSocket *sock, const gchar *buf, guint len, gboolean add_to_head)
{
  TcpEstablishedPriv *priv = sock->priv;
  struct to_be_sent *tbs = NULL;
  NiceAgent *agent = priv->nice_agent;

  if (len <= 0)
    return;

  agent_lock (agent);

  if (priv->write_source == NULL) {
    priv->write_source = g_socket_create_source(sock->transport.fileno, G_IO_OUT, NULL);
    g_source_set_callback (priv->write_source, (GSourceFunc) socket_send_more,
                           tcp_established_callback_data_new(priv->nice_agent, sock),
                           (GDestroyNotify)tcp_established_callback_data_free);
    g_source_attach (priv->write_source, priv->context);
  }

  /*
   * Check for queue overflow, we'll allow upto priv->max_tcp_queue_size+1 elements
   * on the queue
   */
  if (!add_to_head && priv->max_tcp_queue_size != 0) {
    while (g_queue_get_length (&priv->send_queue) > priv->max_tcp_queue_size) {

      /*
       * We want to discard the oldest queued data which is at the front of the queue.
       * However we need to be careful as the first element on the queue may be partially
       * transmitted already, we'll discard the second element on the list instead
       */
      struct to_be_sent *pkt;

      pkt = g_queue_pop_nth (&priv->send_queue, 1);
      priv->tx_queue_size_bytes -= pkt->length;
      free_to_be_sent (pkt);
    }
  }

  tbs = g_slice_new0 (struct to_be_sent);
  tbs->buf = g_memdup (buf, len);
  tbs->length = len;

  if (add_to_head) {
    g_queue_push_head (&priv->send_queue, tbs);
  } else {
    g_queue_push_tail (&priv->send_queue, tbs);
  }
  priv->tx_queue_size_bytes += tbs->length;


  agent_unlock (agent);
}

static void
free_to_be_sent (struct to_be_sent *tbs)
{
  g_free (tbs->buf);
  g_slice_free (struct to_be_sent, tbs);
}

static gint
socket_get_tx_queue_size (NiceSocket *sock)
{
  TcpEstablishedPriv *priv = sock->priv;

  return priv->tx_queue_size_bytes;
}

static void
socket_set_rx_enabled (NiceSocket *sock, gboolean enabled)
{
  TcpEstablishedPriv *priv = sock->priv;

  if (enabled) {
    if (priv->read_source == NULL) {
      priv->read_source = g_socket_create_source(sock->transport.fileno, G_IO_IN | G_IO_ERR, NULL);
      g_source_set_callback (priv->read_source, (GSourceFunc) socket_recv_more,
                             tcp_established_callback_data_new(priv->nice_agent, sock),
                             (GDestroyNotify)tcp_established_callback_data_free);
      g_source_attach (priv->read_source, priv->context);
    }
  } else {
    if (priv->read_source != NULL) {
      g_source_destroy (priv->read_source);
      g_source_unref (priv->read_source);
      priv->read_source = NULL;
    }
  }

  priv->rx_enabled = enabled;
}

static int
socket_get_fd (NiceSocket *sock)
{
  return sock->transport.fileno ? g_socket_get_fd(sock->transport.fileno) : -1;
}
