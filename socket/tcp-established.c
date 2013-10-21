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

#include "tcp-established.h"
#include "agent-priv.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#define MAX_BUFFER_SIZE 65535

typedef struct {
  NiceAddress         remote_addr;
  GQueue              send_queue;
  GMainContext       *context;
  GSource            *read_source;
  GSource            *write_source;
  gboolean            error;
  SocketRecvCallback  recv_cb;
  gpointer            userdata;
  GDestroyNotify      destroy_notify;
  gchar               recv_buff[MAX_BUFFER_SIZE];
  guint               recv_offset;
} TcpEstablishedPriv;

struct to_be_sent {
  guint length;
  gchar *buf;
  gboolean can_drop;
};

static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gint socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);


static void add_to_be_sent (NiceSocket *sock, const gchar *buf, guint len,
                            gboolean head);
static void free_to_be_sent (struct to_be_sent *tbs);
static gboolean socket_send_more (GSocket *gsocket, GIOCondition condition,
                                  gpointer data);
static gboolean socket_recv_more (GSocket *gsocket, GIOCondition condition,
                                  gpointer data);


NiceSocket *
nice_tcp_established_socket_new (GSocket *gsock,
                                 NiceAddress *local_addr, NiceAddress *remote_addr, GMainContext *ctx,
                                 SocketRecvCallback cb, gpointer userdata, GDestroyNotify destroy_notify)
{
  NiceSocket *sock;
  TcpEstablishedPriv *priv;

  g_return_val_if_fail (G_IS_SOCKET (gsock), NULL);

  sock = g_slice_new0 (NiceSocket);
  sock->priv = priv = g_slice_new0 (TcpEstablishedPriv);

  priv->context = g_main_context_ref (ctx);
  priv->remote_addr = *remote_addr;
  priv->recv_cb = cb;
  priv->userdata = userdata;
  priv->destroy_notify = destroy_notify;
  priv->recv_offset = 0;

  sock->type = NICE_SOCKET_TYPE_TCP_ESTABLISHED;
  sock->fileno = gsock;
  sock->addr = *local_addr;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;

  priv->read_source = g_socket_create_source(sock->fileno, G_IO_IN | G_IO_ERR, NULL);
  g_source_set_callback (priv->read_source, (GSourceFunc) socket_recv_more, sock, NULL);
  g_source_attach (priv->read_source, priv->context);
  return sock;
}

static void
socket_close (NiceSocket *sock)
{
  TcpEstablishedPriv *priv = sock->priv;

  if (sock->fileno) {
    g_socket_close (sock->fileno, NULL);
    g_object_unref (sock->fileno);
    sock->fileno = NULL;
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
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  TcpEstablishedPriv *priv = sock->priv;
  int ret;
  GError *gerr = NULL;

  /* Don't try to access the socket if it had an error */
  if (priv->error)
    return -1;

  ret = g_socket_receive (sock->fileno, buf, len, NULL, &gerr);

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

  if (nice_address_equal (to, &priv->remote_addr)) {
    nice_debug("tcp-est: Sending on tcp-established %d", len);
    
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
    if (g_socket_is_connected (sock->fileno) &&
        g_queue_is_empty (&priv->send_queue)) {
      ret = g_socket_send (sock->fileno, buff, len, NULL, &gerr);
      if (ret < 0 &&
          g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
        add_to_be_sent (sock, buff, len, FALSE);
        ret = 0;
      }
      if (gerr)
        g_error_free (gerr);
      /* TODO: handle partial sends here */
      return ret;
    } else {
      add_to_be_sent (sock, buff, len, FALSE);
      return len;
    }
  } else {
    nice_debug ("tcp-est: not for us to send");
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
      gchar *data = priv->recv_buff;
      guint16 packet_length = data[0] << 8 | data[1];
      if ( packet_length + 2 <= priv->recv_offset) {
        /* 
         * Have complete packet, deliver it
         */
        if (priv->recv_cb) {
          nice_debug("socket_recv_more: received %d bytes, delivering", packet_length);
          
          (priv->recv_cb)(sock, from, &data[2], packet_length, priv->userdata);
        }
        
        /*
         * More data after current packet 
         */
        memmove(&priv->recv_buff[0], &priv->recv_buff[packet_length + 2], 
                priv->recv_offset - packet_length + 2);
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
  NiceSocket* sock = (NiceSocket *)data;
  TcpEstablishedPriv *priv = sock->priv;
  NiceAddress from;
  
  len = socket_recv (sock, &from, MAX_BUFFER_SIZE-priv->recv_offset, &priv->recv_buff[priv->recv_offset]);
  if (len > 0) {
    priv->recv_offset += len;
    parse_rfc4571(sock, &from);
  } else if (len < 0) {
    nice_debug("socket_recv_more: error from socket %d", len);
    g_source_destroy (priv->read_source);
    g_source_unref (priv->read_source);
    priv->read_source = NULL;
    priv->error = TRUE;
    return FALSE;
  }
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
  NiceSocket *sock = (NiceSocket *) data;
  TcpEstablishedPriv *priv = sock->priv;
  struct to_be_sent *tbs = NULL;
  GError *gerr = NULL;

  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("tcp-est: Source was destroyed. "
        "Avoided race condition in tcp-established.c:socket_send_more");
    return FALSE;
  }

  while ((tbs = g_queue_pop_head (&priv->send_queue)) != NULL) {
    int ret;

    if(condition & G_IO_HUP) {
      /* connection hangs up */
      ret = -1;
    } else {
      ret = g_socket_send (sock->fileno, tbs->buf, tbs->length, NULL, &gerr);
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
      if (gerr)
        g_error_free (gerr);
    } else if (ret < (int) tbs->length) {
      add_to_be_sent (sock, tbs->buf + ret, tbs->length - ret, TRUE);
      g_free (tbs->buf);
      g_slice_free (struct to_be_sent, tbs);
      break;
    }

    g_free (tbs->buf);
    g_slice_free (struct to_be_sent, tbs);
  }

  if (g_queue_is_empty (&priv->send_queue)) {
    g_source_destroy (priv->write_source);
    g_source_unref (priv->write_source);
    priv->write_source = NULL;
    return FALSE;
  }

  return TRUE;
}

static void
add_to_be_sent (NiceSocket *sock, const gchar *buf, guint len, gboolean head)
{
  TcpEstablishedPriv *priv = sock->priv;
  struct to_be_sent *tbs = NULL;

  if (len <= 0)
    return;

  tbs = g_slice_new0 (struct to_be_sent);
  tbs->buf = g_memdup (buf, len);
  tbs->length = len;
  tbs->can_drop = !head;
  if (head)
    g_queue_push_head (&priv->send_queue, tbs);
  else
    g_queue_push_tail (&priv->send_queue, tbs);

  if (priv->write_source == NULL) {
    priv->write_source = g_socket_create_source(sock->fileno, G_IO_OUT, NULL);
    g_source_set_callback (priv->write_source, (GSourceFunc) socket_send_more,
                           sock, NULL);
    g_source_attach (priv->write_source, priv->context);
  }
}

static void
free_to_be_sent (struct to_be_sent *tbs)
{
  g_free (tbs->buf);
  g_slice_free (struct to_be_sent, tbs);
}
