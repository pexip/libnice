/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
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
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>

#include "gstnicesrc.h"

#if GST_CHECK_VERSION(1, 0, 0)
#include <gst/net/gstnetaddressmeta.h>
#else
#include <gst/netbuffer/gstnetbuffer.h>
#endif

GST_DEBUG_CATEGORY_STATIC(nicesrc_debug);
#define GST_CAT_DEFAULT nicesrc_debug

struct _GstNiceSrc
{
  GstElement parent;
  NiceAgent *agent;

  GSList *src_pads;
  GHashTable *socket_addresses;
};

struct _GstNiceSrcClass
{
  GstPushSrcClass parent_class;
};

struct _GstNiceSrcPad
{
  GstPad pad;
  GstNiceSrc *src;

  gboolean stream_started;
  gboolean segment_sent;
  gboolean attached;

  GMainContext *mainctx;
  GMainLoop *mainloop;

  guint stream_id;
  guint component_id;
  //GQueue *outbufs;
  gboolean unlocked;
  GSource *idle_source;
  GstCaps *caps;
};

#define BUFFER_SIZE (65536)

static GstNiceSrcPollState
gst_nice_src_pad_poll_ctx(GstNiceSrcPad *pad);

static GstFlowReturn
gst_nice_src_create(
    GstPushSrc *basesrc,
    GstBuffer **buffer);

static gboolean
gst_nice_src_unlock(
    GstBaseSrc *basesrc);

static gboolean
gst_nice_src_unlock_stop(
    GstBaseSrc *basesrc);

static gboolean
gst_nice_src_pad_negotiate(GstNiceSrcPad *nicepad);

static void
gst_nice_src_set_property(
    GObject *object,
    guint prop_id,
    const GValue *value,
    GParamSpec *pspec);

static void
gst_nice_src_get_property(
    GObject *object,
    guint prop_id,
    GValue *value,
    GParamSpec *pspec);

static void
gst_nice_src_dispose(GObject *object);

static GstStateChangeReturn
gst_nice_src_change_state(
    GstElement *element,
    GstStateChange transition);

static void
gst_nice_src_release_pad (GstElement * element, GstPad * pad);

static GstPad *
gst_nice_src_request_new_pad(GstElement *element,
                             GstPadTemplate *templ, const gchar *name, const GstCaps *caps);


static GstStaticPadTemplate gst_nice_src_src_template =
    GST_STATIC_PAD_TEMPLATE(
        "nicesrcpad_%u_%u",
        GST_PAD_SRC,
        GST_PAD_REQUEST,
        GST_STATIC_CAPS_ANY);

#define gst_nice_src_parent_class parent_class

G_DEFINE_TYPE(GstNiceSrc, gst_nice_src, GST_TYPE_ELEMENT);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM,
  PROP_COMPONENT,
};

G_DEFINE_TYPE(GstNiceSrcPad, gst_nice_src_pad, GST_TYPE_PAD);

/** Function implementations */
/* GstNiceSrcPad */

static void
gst_nice_src_pad_set_property(
    GObject *object,
    guint prop_id,
    const GValue *value,
    GParamSpec *pspec)
{
  GstNiceSrcPad *pad = GST_NICE_SRC_PAD(object);

  switch (prop_id)
  {
  case PROP_STREAM:
    pad->stream_id = g_value_get_uint(value);
    break;

  case PROP_COMPONENT:
    pad->component_id = g_value_get_uint(value);
    break;

  default:
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
    break;
  }
}

static void
gst_nice_src_pad_get_property(
    GObject *object,
    guint prop_id,
    GValue *value,
    GParamSpec *pspec)
{
  GstNiceSrcPad *pad = GST_NICE_SRC_PAD(object);

  switch (prop_id)
  {
  case PROP_STREAM:
    g_value_set_uint(value, pad->stream_id);
    break;

  case PROP_COMPONENT:
    g_value_set_uint(value, pad->component_id);
    break;

  default:
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
    break;
  }
}

static void
gst_nice_src_pad_init(GstNiceSrcPad *pad)
{
  pad->stream_id = 0;
  pad->component_id = 0;
  pad->mainctx = g_main_context_new();
  pad->mainloop = g_main_loop_new(pad->mainctx, FALSE);
  pad->unlocked = FALSE;
  pad->idle_source = NULL;
  pad->caps = gst_caps_new_any();
}

static void
gst_nice_src_pad_finalize(GObject *object)
{
  //GstNiceSrcPad *pad = GST_NICE_SRC_PAD_CAST (object);

  /* NB: The src is not referenced by the pad to avoid reference loops. */

  G_OBJECT_CLASS(gst_nice_src_pad_parent_class)->finalize(object);
}

static void
gst_nice_src_pad_dispose(GObject *object)
{
  GstNiceSrcPad *nicepad = GST_NICE_SRC_PAD_CAST(object);

  GST_OBJECT_LOCK(nicepad);
  if (nicepad->idle_source)
  {
    g_source_destroy(nicepad->idle_source);
    g_source_unref(nicepad->idle_source);
  }
  nicepad->idle_source = NULL;
  if (nicepad->mainloop)
    g_main_loop_unref(nicepad->mainloop);
  nicepad->mainloop = NULL;

  if (nicepad->mainctx)
    g_main_context_unref(nicepad->mainctx);
  nicepad->mainctx = NULL;

  gst_caps_replace(&nicepad->caps, NULL);
  GST_OBJECT_UNLOCK(nicepad);

  G_OBJECT_CLASS(gst_nice_src_pad_parent_class)->dispose(object);
}

static void
gst_nice_src_pad_class_init(GstNiceSrcPadClass *klass)
{
  GObjectClass *gobject_class = (GObjectClass *)klass;
  gobject_class->finalize = gst_nice_src_pad_finalize;
  gobject_class->dispose = gst_nice_src_pad_dispose;

  gobject_class->get_property = gst_nice_src_pad_get_property;
  gobject_class->set_property = gst_nice_src_pad_set_property;

  g_object_class_install_property(gobject_class, PROP_STREAM,
                                  g_param_spec_uint(
                                      "stream",
                                      "Stream ID",
                                      "The ID of the stream to read from",
                                      0,
                                      G_MAXUINT,
                                      0,
                                      G_PARAM_READWRITE));

  g_object_class_install_property(gobject_class, PROP_COMPONENT,
                                  g_param_spec_uint(
                                      "component",
                                      "Component ID",
                                      "The ID of the component to read from",
                                      0,
                                      G_MAXUINT,
                                      0,
                                      G_PARAM_READWRITE));
}

static gboolean
gst_nice_src_pad_event(GstPad *pad, GstObject *parent, GstEvent *event)
{
  GstNiceSrcPad *nice_pad = GST_NICE_SRC_PAD_CAST(pad);
  GstNiceSrc *src = nice_pad->src;
  gboolean ret = TRUE;

  GST_LOG_OBJECT(src, "handling %s event", GST_EVENT_TYPE_NAME(event));

  switch (GST_EVENT_TYPE(event))
  {
  case GST_EVENT_CUSTOM_UPSTREAM:
  {
    if (gst_event_has_name(event, "PexQosOverflow"))
    {
      GST_DEBUG_OBJECT(src, "Suspend TCP receive, QOS received");
      nice_agent_set_rx_enabled(src->agent, nice_pad->stream_id, nice_pad->component_id, FALSE);
      ret = TRUE;
    }
    else if (gst_event_has_name(event, "PexQosUnderflow"))
    {
      GST_DEBUG_OBJECT(src, "Resume TCP receive, QOS received");
      nice_agent_set_rx_enabled(src->agent, nice_pad->stream_id, nice_pad->component_id, TRUE);
      ret = TRUE;
      //} else {
      //  ret = GST_BASE_SRC_CLASS (parent_class)->event (basesrc, event);
    }
    break;
  }

  default:
  {
    GST_LOG_OBJECT(src, "let base class handle event");
    //ret = GST_BASE_SRC_CLASS (parent_class)->event (basesrc, event);
    break;
  }
  }

  return ret;
}

static GstPadLinkReturn
gst_nice_src_pad_link(GstPad *pad, GstObject *parent, GstPad *peer)
{
  GstNiceSrcPad *nice_pad = GST_NICE_SRC_PAD_CAST(pad);
  GstNiceSrc *src = nice_pad->src;
  (void)peer;
  (void)src;

  GST_LOG_OBJECT(nice_pad, "Queue start Nice IO watcher");
  //loop_ctx_add_pad (ev_pad->loop_ctx, ev_pad, self->playing);

  return GST_PAD_LINK_OK;
}

static void
gst_nice_src_pad_unlink(GstPad *pad, GstObject *parent)
{
  GstNiceSrcPad *nice_pad = GST_NICE_SRC_PAD_CAST(pad);
  GstNiceSrc *src = nice_pad->src;
  (void)parent;
  (void)src;

  GST_LOG_OBJECT(nice_pad, "Queue stop Nice IO watcher");
  //loop_ctx_remove_pad (ev_pad->loop_ctx, ev_pad);
  // TODO: Make sure no sockets are conected here, should we disconnect any connected sockets?
}

static GstPad *
gst_nice_src_pad_new(GstPadTemplate *templ, const gchar *name,
                     GstNiceSrc *src)
{
  GstNiceSrcPad *pad;

  pad = g_object_new(GST_TYPE_NICE_SRC_PAD,
                     "name", name, "direction", templ->direction, "template", templ, NULL);

  pad->src = src;
  pad->stream_started = FALSE;

  gst_pad_set_event_function(GST_PAD_CAST(pad), gst_nice_src_pad_event);
  gst_pad_set_link_function(GST_PAD_CAST(pad), GST_DEBUG_FUNCPTR(gst_nice_src_pad_link));
  gst_pad_set_unlink_function(GST_PAD_CAST(pad),
                              GST_DEBUG_FUNCPTR(gst_nice_src_pad_unlink));

  return GST_PAD_CAST(pad);
}

/**** GstNiceSrc ****/
static void
gst_nice_src_class_init(GstNiceSrcClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GstElementClass *gstelement_class = GST_ELEMENT_CLASS(klass);

  gobject_class = (GObjectClass *)klass;
  gobject_class->set_property = gst_nice_src_set_property;
  gobject_class->get_property = gst_nice_src_get_property;
  gobject_class->dispose = gst_nice_src_dispose;

#if GST_CHECK_VERSION(1, 0, 0)
  gst_element_class_set_metadata(gstelement_class,
#else
  gst_element_class_set_details_simple(gstelement_class,
#endif
                                 "ICE source",
                                 "Source",
                                 "Interactive UDP connectivity establishment",
                                 "Dafydd Harries <dafydd.harries@collabora.co.uk>");

  g_object_class_install_property(gobject_class, PROP_AGENT,
                                  g_param_spec_object(
                                      "agent",
                                      "Agent",
                                      "The NiceAgent this source is bound to",
                                      NICE_TYPE_AGENT,
                                      G_PARAM_READWRITE));

#if 0
  g_object_class_install_property (gobject_class, PROP_CAPS,
      g_param_spec_boxed (
          "caps",
          "Caps",
          "The caps of the source pad",
          GST_TYPE_CAPS,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
#endif

  //gstelement_class->request_new_pad =
  //    GST_DEBUG_FUNCPTR (gst_nice_src_src_request_new_pad); //gstelement_class->release_pad = GST_DEBUG_FUNCPTR (gst_nice_src_release_pad);

  //  gstpushsrc_class = (GstPushSrcClass *) klass;
  //  gstpushsrc_class->create = GST_DEBUG_FUNCPTR (gst_nice_src_create);
  //
  //  gstbasesrc_class = (GstBaseSrcClass *) klass;
  //  gstbasesrc_class->unlock = GST_DEBUG_FUNCPTR (gst_nice_src_unlock);
  //  gstbasesrc_class->unlock_stop = GST_DEBUG_FUNCPTR (gst_nice_src_unlock_stop);
  //  gstbasesrc_class->negotiate = GST_DEBUG_FUNCPTR (gst_nice_src_negotiate);
  //  gstbasesrc_class->event = GST_DEBUG_FUNCPTR (gst_nice_src_handle_event);

  gstelement_class->change_state =
      GST_DEBUG_FUNCPTR(gst_nice_src_change_state);

  gstelement_class->request_new_pad =
      GST_DEBUG_FUNCPTR(gst_nice_src_request_new_pad);
  gstelement_class->release_pad = GST_DEBUG_FUNCPTR(gst_nice_src_release_pad);

  gst_element_class_add_pad_template(gstelement_class,
                                     gst_static_pad_template_get(&gst_nice_src_src_template));

  gst_element_class_set_details_simple(gstelement_class, "nIce src",
                                       "Source/Network",
                                       "Communicates trough firewalls",
                                       "Frederik M. J. Vestre <frederik.vestre@pexip.com>");

  GST_DEBUG_CATEGORY_INIT(nicesrc_debug, "nicesrc",
                          0, "libnice source");
}

static guint
gst_nice_src_data_hash(const char *bytes, size_t length, guint h)
{
  /* This was copied from glib byte array, and can probably be optimized
     signifcantly, e.g by hashing words (or SIMD) instead of bytes */
  const signed char *p, *e;
  if (h == 0)
  {
    h = 5381;
  }
  for (p = (signed char *)bytes, e = (signed char *)(bytes + length); p != e; p++)
  {
    h = (h << 5) + h + *p;
  }
  return h;
}

static guint
gst_nice_src_address_hash(gconstpointer key)
{
  const NiceAddress *from = (NiceAddress *)key;

  guint hash = gst_nice_src_data_hash((gpointer)&from->s.addr.sa_family, sizeof(from->s.addr.sa_family), 0);

  switch (from->s.addr.sa_family)
  {
  case AF_INET:
    hash = gst_nice_src_data_hash((gpointer)&from->s.ip4, sizeof(from->s.ip4), hash);
    break;
  case AF_INET6:
    hash = gst_nice_src_data_hash((gpointer)&from->s.ip6, sizeof(from->s.ip6), hash);
    break;
  default:
    GST_ERROR_OBJECT(from, "Unknown address family");
    break;
  }

  return hash;
}

static GSocketAddress *
gst_nice_src_gsocket_addr_create_or_retrieve(GstNiceSrc *src,
                                             const NiceAddress *native_addr)
{
  GSocketAddress *result = g_hash_table_lookup(src->socket_addresses,
                                               native_addr);
  if (G_UNLIKELY(result == NULL))
  {
    /* Convert and insert into hash table if it is not present already */
    switch (native_addr->s.addr.sa_family)
    {
    case AF_INET:
      result = g_socket_address_new_from_native((gpointer)&native_addr->s.ip4,
                                                sizeof(native_addr->s.ip4));
      break;
    case AF_INET6:
      result = g_socket_address_new_from_native((gpointer)&native_addr->s.ip6,
                                                sizeof(native_addr->s.ip6));
      break;
    default:
      GST_ERROR_OBJECT(src, "Unknown address family");
      break;
    }

    if (G_UNLIKELY(result == NULL))
    {
      GST_ERROR_OBJECT(src, "Could not create address gobject");
      return result;
    }

    NiceAddress *key = g_slice_new(NiceAddress);
    memcpy(key, native_addr, sizeof(NiceAddress));

    gst_object_ref(result);
    g_hash_table_insert(src->socket_addresses, key, result);
  }
  else
  {
    gst_object_ref(result);
  }
  return result;
}

static gboolean
gst_nice_src_nice_address_compare(gconstpointer a, gconstpointer b)
{
  const NiceAddress *a_addr = (const NiceAddress *)a;
  const NiceAddress *b_addr = (const NiceAddress *)b;

  if ((a_addr->s.addr.sa_family == b_addr->s.addr.sa_family))
  {
    switch (a_addr->s.addr.sa_family)
    {
    case AF_INET:
      return memcmp(&a_addr->s.ip4, &b_addr->s.ip4, sizeof(a_addr->s.ip4)) == 0;
    case AF_INET6:
      return memcmp(&a_addr->s.ip6, &b_addr->s.ip6, sizeof(a_addr->s.ip6)) == 0;
    }
  }
  return FALSE;
}

static void
gst_nice_src_destroy_hash_key(void *key)
{
  g_slice_free(NiceAddress, key);
}

static void
gst_nice_src_init(GstNiceSrc *src)
{
  GstPad *pad;

  //gst_base_src_set_live (GST_BASE_SRC (src), TRUE);
  //gst_base_src_set_format (GST_BASE_SRC (src), GST_FORMAT_TIME);
  //gst_base_src_set_do_timestamp (GST_BASE_SRC (src), TRUE);
  src->agent = NULL;

  //src->outbufs = g_queue_new ();
  src->socket_addresses = g_hash_table_new_full(gst_nice_src_address_hash,
                                                gst_nice_src_nice_address_compare,
                                                gst_nice_src_destroy_hash_key,
                                                gst_object_unref);
#if 0
  // Todo: Add support for dynamically adding pads as done in pexeviosrc
  pad = gst_pad_new_from_template ((GstPadTemplate*)(&gst_nice_src_src_template), "src");
  GST_DEBUG_OBJECT (src, "setting functions on src pad");

  gst_pad_set_active (pad, TRUE);

  src->srcpad = (GstNiceSrcPad*)pad;
#endif
}

static gboolean
gst_nice_src_pad_send_stream_start(GstNiceSrcPad *nicepad)
{
  gboolean ret;
  gchar *stream_id;
  GstEvent *event;
  const gchar *padname = GST_OBJECT_NAME(nicepad);

  GST_DEBUG_OBJECT(nicepad, "Pushing STREAM_START");
  stream_id = gst_pad_create_stream_id((GstPad *)nicepad, GST_ELEMENT_CAST(nicepad->src),
                                       padname + 4);
  event = gst_event_new_stream_start(stream_id);
  gst_event_set_group_id(event, gst_util_group_id_next());
  ret = gst_pad_push_event((GstPad *)nicepad, event);
  g_free(stream_id);
  return ret;
}

static gboolean
gst_nice_src_pad_send_caps(GstNiceSrcPad *nicepad)
{
  gboolean ret = TRUE;
  GstCaps *caps = gst_pad_peer_query_caps((GstPad *)nicepad, NULL);

  if (caps && !gst_caps_is_empty(caps) && !gst_caps_is_any(caps))
  {
    caps = gst_caps_fixate(caps);
    GST_DEBUG_OBJECT(nicepad, "Pushing CAPS %" GST_PTR_FORMAT, caps);
    ret = gst_pad_push_event((GstPad *)nicepad, gst_event_new_caps(caps));
  }
  else
  {
    GST_WARNING_OBJECT(nicepad, "NOT Pushing CAPS %" GST_PTR_FORMAT, caps);
  }

  if (caps != NULL)
    gst_caps_unref(caps);

  return ret;
}

static gboolean
gst_nice_src_pad_send_segment(GstNiceSrcPad *nicepad)
{
  GstEvent *event;
  GstSegment segment;

  GST_DEBUG_OBJECT(nicepad, "Pushing SEGMENT");
  gst_segment_init(&segment, GST_FORMAT_TIME);
  event = gst_event_new_segment(&segment);
  gst_event_set_seqnum(event, gst_util_seqnum_next());

  return gst_pad_push_event((GstPad *)nicepad, event);
}

/* Called for async sockets */
static void
gst_nice_src_recvmsg_callback(NiceAgent *agent,
                              guint stream_id,
                              guint component_id,
                              guint len,
                              struct msghdr *msg,
                              gpointer data,
                              const NiceAddress *from,
                              const NiceAddress *to)
{
}

static void
gst_nice_src_read_callback(NiceAgent *agent,
                           guint stream_id,
                           guint component_id,
                           guint len,
                           gchar *buf,
                           gpointer data,
                           const NiceAddress *from,
                           const NiceAddress *to)
{
  GstNiceSrcPad *nicesrcpad = GST_NICE_SRC_PAD(data);
  GstNiceSrcPad *nicesrc = nicesrcpad->src;
#if !GST_CHECK_VERSION(1, 0, 0)
  GstNetBuffer *netbuffer = NULL;
#endif
  GstBuffer *buffer = NULL;

  (void)stream_id;
  (void)component_id;

  GST_LOG_OBJECT(agent, "Got buffer, getting out of the main loop");

  GST_OBJECT_LOCK(nicesrcpad->src);
  if (G_UNLIKELY(!nicesrcpad->stream_started))
  {
    GST_OBJECT_UNLOCK(nicesrcpad->src);
    gst_nice_src_pad_send_stream_start(nicesrcpad);
    GST_OBJECT_LOCK(nicesrcpad->src);
    nicesrcpad->stream_started = TRUE;
  }
  if (G_UNLIKELY(!nicesrcpad->segment_sent))
  {
    GST_OBJECT_UNLOCK(nicesrcpad->src);
    gst_nice_src_pad_send_segment(nicesrcpad);
    nicesrcpad->segment_sent = TRUE;
    GST_OBJECT_LOCK(nicesrcpad->src);
  }
  GST_OBJECT_UNLOCK(nicesrcpad->src);
#if GST_CHECK_VERSION(1, 0, 0)
  (void)to;
  /* Not doing buffer pools at the moment, this requres copying far to much code
  from gstbasesrc
  GstFlowReturn status = gst_nice_src_alloc(nicesrc, 0, len, &buffer);
  */
  //if (status != GST_FLOW_OK)
  {
    //GST_LOG_OBJECT (nicesrc, "Could not allocate buffer using common allocator"
    //                           ", allocate using local allocator instead");
    buffer = gst_buffer_new_allocate(NULL, len, NULL);
  }
  gst_buffer_fill(buffer, 0, buf, len);

  if (from != NULL)
  {
    GSocketAddress *saddr = gst_nice_src_gsocket_addr_create_or_retrieve(
        nicesrc, from);
    if (saddr != NULL)
    {
      gst_buffer_add_net_address_meta(buffer, saddr);
      g_object_unref(saddr);
    }
    else
    {
      GST_ERROR_OBJECT(nicesrc, "Could not convert address to GSocketAddress");
    }
  }
#else
  #error "Not supported anymore"
#endif
  //g_queue_push_tail (nicesrc->outbufs, buffer);
  GstFlowReturn flowret;
  if (G_UNLIKELY ((flowret = gst_pad_push (nicesrcpad, buffer)) != GST_FLOW_OK)) {
    GST_ERROR_OBJECT (nicesrcpad,
        "Failed to push incoming datagram buffer (ret: %d)", flowret);
  }
  g_main_loop_quit(nicesrcpad->mainloop);
}
#if 0
static gboolean
gst_nice_src_unlock_idler (gpointer data)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (data);

  GST_OBJECT_LOCK (nicesrc);
  if (nicesrc->unlocked)
    g_main_loop_quit (nicesrc->mainloop);

  if (nicesrc->idle_source) {
    g_source_destroy (nicesrc->idle_source);
    g_source_unref (nicesrc->idle_source);
    nicesrc->idle_source = NULL;
  }
  GST_OBJECT_UNLOCK (nicesrc);

  return FALSE;
}

static gboolean
gst_nice_src_unlock (GstBaseSrc *src)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (src);

  GST_OBJECT_LOCK (src);
  nicesrc->unlocked = TRUE;

  g_main_loop_quit (nicesrc->mainloop);

  if (!nicesrc->idle_source) {
    nicesrc->idle_source = g_idle_source_new ();
    g_source_set_priority (nicesrc->idle_source, G_PRIORITY_HIGH);
    g_source_set_callback (nicesrc->idle_source, gst_nice_src_unlock_idler, src, NULL);
    g_source_attach (nicesrc->idle_source, g_main_loop_get_context (nicesrc->mainloop));
  }
  GST_OBJECT_UNLOCK (src);

  return TRUE;
}

static gboolean
gst_nice_src_unlock_stop (GstBaseSrc *src)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (src);

  GST_OBJECT_LOCK (src);
  nicesrc->unlocked = FALSE;
  if (nicesrc->idle_source) {
    g_source_destroy (nicesrc->idle_source);
    g_source_unref(nicesrc->idle_source);
  }
  nicesrc->idle_source = NULL;
  GST_OBJECT_UNLOCK (src);

  return TRUE;
}
#endif
/* Similar to gst_base_src_default_negotiate except that it always queries
 * downstream for allowed caps. This is because the default behavior never
 * sends a caps-event if the template caps is any. */
static gboolean
gst_nice_src_pad_negotiate(GstNiceSrcPad *nicepad)
{
  GstCaps *caps, *intersect;
  GstNiceSrc *src = nicepad->src;
  gboolean result = FALSE;

  caps = gst_pad_get_allowed_caps(nicepad);
  if (!caps)
    caps = gst_pad_get_pad_template_caps(nicepad);

  GST_OBJECT_LOCK(nicepad);
  intersect = gst_caps_intersect(nicepad->caps, caps);
  GST_OBJECT_UNLOCK(nicepad);

  gst_caps_take(&caps, intersect);

  if (!gst_caps_is_empty(caps))
  {
    if (gst_caps_is_any(caps))
    {
      GST_DEBUG_OBJECT(nicepad, "any caps, negotiation not needed");
      result = TRUE;
    }
    else
    {
#if 0
      // TODO: Copy/ adapt from coordinator
      if (gst_caps_is_fixed (caps)) {
        result = gst_base_src_set_caps (pad, caps);
      }
#endif
    }
    gst_caps_unref(caps);
  }
  else
  {
    GST_DEBUG_OBJECT(nicepad, "no common caps");
  }
  return result;
}

static GstFlowReturn
gst_nice_src_create(
    GstPushSrc *basesrc,
    GstBuffer **buffer)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC(basesrc);

  GST_LOG_OBJECT(nicesrc, "create called");

#if 0
  GST_OBJECT_LOCK (basesrc);
  if (nicesrc->unlocked) {
    GST_OBJECT_UNLOCK (basesrc);
#if GST_CHECK_VERSION(1, 0, 0)
    return GST_FLOW_FLUSHING;
#else
    return GST_FLOW_WRONG_STATE;
#endif
  }
  GST_OBJECT_UNLOCK (basesrc);
#endif

#if 0
  if (g_queue_is_empty (nicesrc->outbufs))
    g_main_loop_run (nicesrc->mainloop);

  *buffer = g_queue_pop_head (nicesrc->outbufs);
  if (*buffer != NULL) {
    GST_LOG_OBJECT (nicesrc, "Got buffer, pushing");
    return GST_FLOW_OK;
  } else {
    GST_LOG_OBJECT (nicesrc, "Got interrupting, returning wrong-state");
#if GST_CHECK_VERSION(1, 0, 0)
    return GST_FLOW_FLUSHING;
#else
    return GST_FLOW_WRONG_STATE;
#endif
  }
#endif
  return GST_FLOW_OK;
}

static void
gst_nice_src_dispose(GObject *object)
{
  GstNiceSrc *src = GST_NICE_SRC(object);
  //g_assert(gst_element_get_state  src)

  if (src->agent)
    g_object_unref(src->agent);
  src->agent = NULL;

#if 0
  if (src->outbufs)
    g_queue_free_full (src->outbufs, (GDestroyNotify)gst_buffer_unref);
  src->outbufs = NULL;
#endif

  while ( src->src_pads )
  {
    GSList *elm = src->src_pads;
    if (elm->data)
    {
      // TODO: Should we forward set state on the source to all the pads instead
      //gst_element_set_state (elm->data, GST_STATE_NULL);
      gst_nice_src_release_pad(src, elm->data);
    }
  }

  g_hash_table_remove_all(src->socket_addresses);
  g_hash_table_unref(src->socket_addresses);
  src->socket_addresses = NULL;

  G_OBJECT_CLASS(gst_nice_src_parent_class)->dispose(object);
}

static void
gst_nice_src_set_property(
    GObject *object,
    guint prop_id,
    const GValue *value,
    GParamSpec *pspec)
{
  GstNiceSrc *src = GST_NICE_SRC(object);

  switch (prop_id)
  {
  case PROP_AGENT:
    if (src->agent)
      GST_ERROR_OBJECT(object,
                       "Changing the agent on a nice src not allowed");
    else
      src->agent = g_value_dup_object(value);
    break;

#if 0
    case PROP_CAPS:
    {
      const GstCaps *new_caps_val = gst_value_get_caps (value);
      GstCaps *new_caps;

      if (new_caps_val == NULL) {
        new_caps = gst_caps_new_any ();
      } else {
        new_caps = gst_caps_copy (new_caps_val);
      }

      GST_OBJECT_LOCK (src);
      //gst_caps_replace (&src->caps, new_caps);
      // TODO: How to handle this?
      GST_OBJECT_UNLOCK (src);

      gst_pad_mark_reconfigure (GST_BASE_SRC_PAD (src));
      break;
    }
#endif

  default:
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
    break;
  }
}

static void
gst_nice_src_get_property(
    GObject *object,
    guint prop_id,
    GValue *value,
    GParamSpec *pspec)
{
  GstNiceSrc *src = GST_NICE_SRC(object);

  switch (prop_id)
  {
  case PROP_AGENT:
    g_value_set_object(value, src->agent);
    break;

#if 0
    case PROP_CAPS:
      GST_OBJECT_LOCK (src);
      gst_value_set_caps (value, src->caps);
      GST_OBJECT_UNLOCK (src);
      break;
#endif
  default:
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
    break;
  }
}

static void
gst_nice_src_log_callback(NiceAgent *agent, guint stream_id, guint component_id, GLogLevelFlags level,
                          gchar *msg, gpointer data)
{
  (void)agent;
  GstBaseSrc *basesrc = GST_BASE_SRC(data);
  GstNiceSrc *nicesrc = GST_NICE_SRC(basesrc);

  switch (level)
  {
  case G_LOG_LEVEL_WARNING:
    GST_WARNING_OBJECT(nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  case G_LOG_LEVEL_INFO:
    GST_INFO_OBJECT(nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  default:
    GST_DEBUG_OBJECT(nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  }
}

NiceAgentPollState gst_nice_src_pad_poll_callback(
  NiceAgent *agent, guint stream_id, guint component_id, gpointer user_data)
{
  GstNiceSrcPad * pad = GST_NICE_SRC_PAD_CAST(user_data);
  
  g_assert(pad->src == NULL || pad->src->agent == agent);
  g_assert(pad->stream_id == stream_id);
  g_assert(pad->component_id == component_id);
    

  return gst_nice_src_pad_poll_ctx(pad);
}

static void
gst_nice_src_pad_change_state(gpointer *pad_ptr, gpointer transition_wrapped)
{
  GstNiceSrcPad *srcpad = GST_NICE_SRC_PAD_CAST(pad_ptr);
  GstStateChange transition = (GstStateChange)transition_wrapped;
  GstState next = GST_STATE_TRANSITION_NEXT(transition);
  switch (next)
  {
  case GST_STATE_READY:
    if(!srcpad->attached)
    {
      nice_agent_attach_recv(srcpad->src->agent, srcpad->stream_id, srcpad->component_id,
                             srcpad->mainctx, gst_nice_src_read_callback, gst_nice_src_recvmsg_callback,
                             (gpointer)srcpad);
      nice_agent_add_component_poll_callback(srcpad->src->agent,
       srcpad->stream_id, srcpad->component_id, gst_nice_src_pad_poll_callback,
       gst_object_ref(srcpad), gst_object_unref);

      srcpad->attached = TRUE;
    }
    break;
  case GST_STATE_NULL:
    if (srcpad->attached)
    {
      nice_agent_attach_recv(srcpad->src->agent, srcpad->stream_id, srcpad->component_id,
                             srcpad->mainctx, NULL, NULL, NULL);
      srcpad->attached = FALSE;
    }
    break;
  }
}

static GstStateChangeReturn
gst_nice_src_change_state(GstElement *element, GstStateChange transition)
{
  GstNiceSrc *src;
  GstStateChangeReturn ret;

  src = GST_NICE_SRC(element);

  GstState next = GST_STATE_TRANSITION_NEXT(transition);
  switch (next)
  {
  case GST_STATE_READY:
    if (src->agent == NULL ) //|| src->src_pads == NULL)
    {
      GST_WARNING_OBJECT(element,
                       "Trying to start Nice source without an agent set");
      g_assert(FALSE);
      return GST_STATE_CHANGE_FAILURE;
    }
    else
    {
      GST_OBJECT_LOCK(src);
      g_slist_foreach(src->src_pads, gst_nice_src_pad_change_state, (gpointer)transition);
      GST_OBJECT_UNLOCK(src);
    }
    break;
  case GST_STATE_NULL:
    GST_OBJECT_LOCK(src);
    g_slist_foreach(src->src_pads, gst_nice_src_pad_change_state, (gpointer)transition);
    GST_OBJECT_UNLOCK(src);
    break;
  default:
    break;
  }

  ret = GST_ELEMENT_CLASS(gst_nice_src_parent_class)->change_state(element, transition);

  return ret;
}

static GstNiceSrcPollState gst_nice_src_pad_poll_system(GstNiceSrcPad *srcpad)
{
  if (G_UNLIKELY(!srcpad->stream_started))
  {
    gst_nice_src_pad_send_stream_start(srcpad);
    srcpad->stream_started = TRUE;
    return GST_NICE_SRC_POLL_SYSTEM_PROCESSED;
  }
  if (G_UNLIKELY(gst_pad_check_reconfigure(GST_PAD_CAST(srcpad))))
  {
    gst_nice_src_pad_send_caps(srcpad);
    return GST_NICE_SRC_POLL_SYSTEM_PROCESSED;
  }

  if (G_UNLIKELY(!srcpad->segment_sent))
  {
    gst_nice_src_pad_send_segment(srcpad);
    srcpad->segment_sent = TRUE;
    return GST_NICE_SRC_POLL_SYSTEM_PROCESSED;
  }
}

/* Handle Gstreamer system events */
static GstNiceSrcPollState gst_nice_src_poll_system(GstNiceSrc *src)
{
  GST_OBJECT_LOCK(src);
  for (GSList *elm = src->src_pads; elm = elm->next; elm != NULL)
  {
    GstNiceSrcPad *srcpad = GST_NICE_SRC_PAD_CAST(elm->data);
    GstNiceSrcPollState ret_state;
    ret_state = gst_nice_src_pad_poll_system(srcpad);
    if (ret_state != GST_NICE_SRC_POLL_EMPTY)
    {
      GST_OBJECT_UNLOCK(src);
      return ret_state;
    }
  }

  GST_OBJECT_UNLOCK(src);
  return GST_NICE_SRC_POLL_EMPTY;
}

static GstNiceSrcPollState
gst_nice_src_pad_poll_ctx(GstNiceSrcPad *pad)
{
  GstNiceSrcPollState result;
  GST_OBJECT_LOCK(pad);
  if(pad->src == NULL)
  {
    result = NICE_AGENT_POLL_EOS;
    goto done;
  }
  gboolean context_processed_element = FALSE;
  if (nice_agent_component_uses_main_context(pad->src->agent, pad->stream_id, pad->component_id))
  {
    if (g_main_context_pending(pad->mainctx))
    {
      GST_OBJECT_UNLOCK(pad);
      context_processed_element = g_main_context_iteration(pad->mainctx, FALSE);
      GST_OBJECT_LOCK(pad);
    }
  }
  if (context_processed_element)
  {
    result = GST_NICE_SRC_POLL_PROCESSED;
  }
  else
  {
    result = GST_NICE_SRC_POLL_EMPTY;
  }
  done:
  GST_OBJECT_UNLOCK(pad);
  if (result != GST_NICE_SRC_POLL_EMPTY)
  {
    GST_DEBUG_OBJECT (pad,
        "Pollpad: %u %u = %u",
        pad->stream_id, pad->component_id, result);
  }
  return result;
}

GstNiceSrcPollState gst_nice_src_poll(GstNiceSrc *src)
{
  GstNiceSrcPollState result = GST_NICE_SRC_POLL_EMPTY;
  gboolean context_processed_element = FALSE;
  GST_OBJECT_LOCK(src);

  //First see if there are any system events that must be managed
  GstNiceSrcPollState system_poll_state_result = gst_nice_src_poll_system(src);
  if (system_poll_state_result != GST_NICE_SRC_POLL_EMPTY)
  {
    GST_OBJECT_UNLOCK(src);
    return system_poll_state_result;
  }

  for (GSList *elm = src->src_pads; elm = elm->next; elm != NULL)
  {
    GstNiceSrcPad *srcpad = GST_NICE_SRC_PAD_CAST(elm->data);

    GstNiceSrcPollState pad_result = gst_nice_src_pad_poll_ctx(srcpad);
    if (pad_result != GST_NICE_SRC_POLL_EMPTY)
    {
      result = NICE_AGENT_POLL_PROCESSED; //pad_result;
      break;
    }
  }
  GST_OBJECT_UNLOCK(src);

  return result;
}

/* TODO: Add more parameters */
void gst_nice_src_handle_receive(GstNiceSrc *src)
{
}

static GstPad *
gst_nice_src_request_new_pad(GstElement *element,
                             GstPadTemplate *templ, const gchar *name, const GstCaps *caps)
{
  GstNiceSrc *src = GST_NICE_SRC_CAST(element);
  GstPad *pad;
  guint stream_id, component_id;

  (void)caps;

  GST_LOG_OBJECT(element, "Request pad: %s", name);

  if (G_UNLIKELY(name == NULL || templ == NULL))
    return NULL;
  else if (sscanf(name, "nicesrcpad_%u_%u", &stream_id, &component_id) != 2)
    return NULL;

  GST_OBJECT_LOCK(src);

  pad = gst_nice_src_pad_new(templ, name, src);

  gst_pad_set_link_function(pad, GST_DEBUG_FUNCPTR(gst_nice_src_pad_link));
  gst_pad_set_unlink_function(pad,
                              GST_DEBUG_FUNCPTR(gst_nice_src_pad_unlink));

  gst_pad_set_active(pad, TRUE);
  src->src_pads = g_slist_prepend(src->src_pads, pad);
  GST_OBJECT_UNLOCK(src);
  gst_element_add_pad(element, pad);
  GST_DEBUG_OBJECT(pad, "Added pad for stream %u component %u", stream_id, component_id);


  return pad;
}

static void
gst_nice_src_release_pad (GstElement * element, GstPad * pad)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC_CAST (element);
  GstNiceSrcPad *nicepad = GST_NICE_SRC_PAD_CAST (pad);

  GST_DEBUG_OBJECT (pad, "Release pad");

  g_assert (gst_pad_set_active (pad, FALSE));
  gst_element_remove_pad (element, pad);

  GST_OBJECT_LOCK(nicesrc);
  if (nicepad->attached)
  {
    nice_agent_attach_recv(nicepad->src->agent, nicepad->stream_id, nicepad->component_id,
                           nicepad->mainctx, NULL, NULL, NULL);
    nicepad->attached = FALSE;
  }

  nicesrc->src_pads = g_slist_remove(nicesrc->src_pads, pad);
  GST_OBJECT_UNLOCK(nicesrc);
  //Free pad?
}
