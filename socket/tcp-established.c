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

typedef struct {
  NiceAddress remote_addr;
  GQueue send_queue;
  GMainContext *context;
  GSource *io_source;
  gboolean error;
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


NiceSocket *
nice_tcp_established_socket_new (GSocket *gsock,
    NiceAddress *local_addr, NiceAddress *remote_addr, GMainContext *ctx)
{
  NiceSocket *sock;
  TcpEstablishedPriv *priv;

  g_return_val_if_fail (G_IS_SOCKET (gsock), NULL);

  sock = g_slice_new0 (NiceSocket);
  sock->priv = priv = g_slice_new0 (TcpEstablishedPriv);

  priv->context = g_main_context_ref (ctx);
  priv->remote_addr = *remote_addr;

  sock->type = NICE_SOCKET_TYPE_TCP_ESTABLISHED;
  sock->fileno = gsock;
  sock->addr = *local_addr;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;

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
  if (priv->io_source) {
    g_source_destroy (priv->io_source);
    g_source_unref (priv->io_source);
  }
  g_queue_foreach (&priv->send_queue, (GFunc) free_to_be_sent, NULL);
  g_queue_clear (&priv->send_queue);

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

  /* Don't try to access the socket if it had an error, otherwise we risk a
     crash with SIGPIPE (Broken pipe) */
  if (priv->error)
    return -1;

  /* First try to send the data, don't send it later if it can be sent now
     this way we avoid allocating memory on every send */
  if (g_socket_is_connected (sock->fileno) &&
      g_queue_is_empty (&priv->send_queue)) {
      ret = g_socket_send (sock->fileno, buf, len, NULL, &gerr);
      if (ret < 0 &&
          g_error_matches (gerr, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
        ret = 0;
      if (gerr)
        g_error_free (gerr);
      return ret;
  } else {
    add_to_be_sent (sock, buf, len, FALSE);
    return len;
  }

}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  return TRUE;
}


/*
 * Returns:
 * -1 = error
 * 0 = have more to send
 * 1 = sent everything
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

  agent_lock ();

  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in tcp-established.c:socket_send_more");
    agent_unlock ();
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
    g_source_destroy (priv->io_source);
    g_source_unref (priv->io_source);
    priv->io_source = NULL;

    agent_unlock ();
    return FALSE;
  }

  agent_unlock ();
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

  if (priv->io_source == NULL) {
    priv->io_source = g_socket_create_source(sock->fileno, G_IO_OUT, NULL);
    g_source_set_callback (priv->io_source, (GSourceFunc) socket_send_more,
        sock, NULL);
    g_source_attach (priv->io_source, priv->context);
  }
}

static void
free_to_be_sent (struct to_be_sent *tbs)
{
  g_free (tbs->buf);
  g_slice_free (struct to_be_sent, tbs);
}
