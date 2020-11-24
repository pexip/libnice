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
# include "config.h"
#endif

#include <string.h>

#include "gstnicesrc.h"
#include "gstnicecoordinator.h"

#if GST_CHECK_VERSION (1,0,0)
#include <gst/net/gstnetaddressmeta.h>
#else
#include <gst/netbuffer/gstnetbuffer.h>
#endif

GST_DEBUG_CATEGORY_STATIC (nicesrc_debug);
#define GST_CAT_DEFAULT nicesrc_debug

struct _GstNiceSrc
{
  GstPushSrc parent;
  GstNiceSrcPad *srcpad;
  NiceAgent *agent;
  guint stream_id;
  guint component_id;
  GMainContext *mainctx;
  GMainLoop *mainloop;
  GQueue *outbufs;
  gboolean unlocked;
  GSource *idle_source;
  GstCaps *caps;
  GHashTable *socket_addresses;

  GstNiceCoordinator *coordinator;
};

struct _GstNiceSrcClass
{
  GstPushSrcClass parent_class;
};

/* Most stuff are stored and managed in the src,
   which is guaranteed to outlive the pad */
struct _GstNiceSrcPad
{
  GstPad pad;
  GstNiceSrc* src;
  gboolean stream_started;
  gboolean segment_sent;
};

#define BUFFER_SIZE (65536)

static GstFlowReturn
gst_nice_src_create (
  GstPushSrc *basesrc,
  GstBuffer **buffer);

static gboolean
gst_nice_src_unlock (
    GstBaseSrc *basesrc);

static gboolean
gst_nice_src_unlock_stop (
    GstBaseSrc *basesrc);

static gboolean
gst_nice_src_negotiate (
    GstBaseSrc * src);

static void
gst_nice_src_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec);

static void
gst_nice_src_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec);


static void
gst_nice_src_dispose (GObject *object);

static GstStateChangeReturn
gst_nice_src_change_state (
    GstElement * element,
    GstStateChange transition);

static GstStaticPadTemplate gst_nice_src_src_template =
GST_STATIC_PAD_TEMPLATE (
    "src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

#define gst_nice_src_parent_class parent_class

G_DEFINE_TYPE (GstNiceSrc, gst_nice_src, GST_TYPE_PUSH_SRC);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM,
  PROP_COMPONENT,
  PROP_COORDINATOR,
//  PROP_CAPS
};

G_DEFINE_TYPE (GstNiceSrcPad, gst_nice_src_pad, GST_TYPE_PUSH_SRC);

/** Function implementations */
/* GstNiceSrcPad */
static void
gst_nice_src_pad_init (GstNiceSrcPad * pad)
{
  (void) pad;
}

static void
gst_nice_src_pad_finalize (GObject * object)
{
  //GstNiceSrcPad *pad = GST_NICE_SRC_PAD_CAST (object);

  /* NB: The src is not referenced by the pad to avoid reference loops. */

  G_OBJECT_CLASS (gst_nice_src_pad_parent_class)->finalize (object);
}

static void
gst_nice_src_pad_class_init (GstNiceSrcPadClass * klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;
  gobject_class->finalize = gst_nice_src_pad_finalize;

#if 0
  gobject_class->get_property = pex_ev_io_src_pad_get_property;
  gobject_class->set_property = pex_ev_io_src_pad_set_property;

  g_object_class_install_property (gobject_class, PROP_ADD_NET_ADDR_META,
      g_param_spec_boolean ("add-net-address-meta", "Add Net Address meta",
          "If we should do add net-address meta", DEFAULT_ADD_NET_ADDR_META,
          G_PARAM_CONSTRUCT | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
#endif
}


static gboolean
gst_nice_src_pad_event (GstPad * pad, GstObject * parent, GstEvent * event)
{
  GstNiceSrcPad *nice_pad = GST_NICE_SRC_PAD_CAST(pad);
  GstNiceSrc *src = nice_pad->src;
  gboolean ret = TRUE;

  GST_LOG_OBJECT (src, "handling %s event", GST_EVENT_TYPE_NAME (event));

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_CUSTOM_UPSTREAM:
    {
      if (gst_event_has_name (event, "PexQosOverflow")) {
        GST_DEBUG_OBJECT (src, "Suspend TCP receive, QOS received");
        nice_agent_set_rx_enabled (src->agent, src->stream_id, src->component_id, FALSE);
        ret = TRUE;
      } else if (gst_event_has_name (event, "PexQosUnderflow")) {
        GST_DEBUG_OBJECT (src, "Resume TCP receive, QOS received");
        nice_agent_set_rx_enabled (src->agent, src->stream_id, src->component_id, TRUE);
        ret = TRUE;
      //} else {
      //  ret = GST_BASE_SRC_CLASS (parent_class)->event (basesrc, event);
      }
      break;
    }

    default:
    {
      GST_LOG_OBJECT (src, "let base class handle event");
      //ret = GST_BASE_SRC_CLASS (parent_class)->event (basesrc, event);
      break;
    }
  }

  return ret;
}

static GstPadLinkReturn
gst_nice_src_pad_link (GstPad * pad, GstObject * parent, GstPad * peer)
{
  GstNiceSrcPad *nice_pad = GST_NICE_SRC_PAD_CAST(pad);
  GstNiceSrc *src = nice_pad->src;
  (void) peer;
  (void) src;

  GST_LOG_OBJECT (nice_pad, "Queue start Nice IO watcher");
  //loop_ctx_add_pad (ev_pad->loop_ctx, ev_pad, self->playing);


  return GST_PAD_LINK_OK;
}

static void
gst_nice_src_pad_unlink (GstPad * pad, GstObject * parent)
{
  GstNiceSrcPad *nice_pad = GST_NICE_SRC_PAD_CAST(pad);
  GstNiceSrc *src = nice_pad->src;
  (void) parent;
  (void) src;

  GST_LOG_OBJECT (nice_pad, "Queue stop Nice IO watcher");
  //loop_ctx_remove_pad (ev_pad->loop_ctx, ev_pad);
  // TODO: Make sure no sockets are conected here, should we disconnect any connected sockets?
}

static GstPad *
gst_nice_src_pad_new (GstPadTemplate * templ, const gchar * name,
  GstNiceSrc* src)
{
  GstNiceSrcPad *pad;

  pad = g_object_new (GST_TYPE_NICE_SRC_PAD,
      "name", name, "direction", templ->direction, "template", templ, NULL);

  pad->src = src;
  pad->stream_started = FALSE;

  gst_pad_set_event_function (GST_PAD_CAST(pad), gst_nice_src_pad_event);
  gst_pad_set_link_function (GST_PAD_CAST(pad), GST_DEBUG_FUNCPTR (gst_nice_src_pad_link));
  gst_pad_set_unlink_function (GST_PAD_CAST(pad),
      GST_DEBUG_FUNCPTR (gst_nice_src_pad_unlink));

  return GST_PAD_CAST (pad);
}

/**** GstNiceSrc ****/
static void
gst_nice_src_class_init (GstNiceSrcClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *gstelement_class = GST_ELEMENT_CLASS (klass);

  gobject_class = (GObjectClass *) klass;
  gobject_class->set_property = gst_nice_src_set_property;
  gobject_class->get_property = gst_nice_src_get_property;
  gobject_class->dispose = gst_nice_src_dispose;

#if GST_CHECK_VERSION (1,0,0)
  gst_element_class_set_metadata (gstelement_class,
#else
  gst_element_class_set_details_simple (gstelement_class,
#endif
      "ICE source",
      "Source",
      "Interactive UDP connectivity establishment",
      "Dafydd Harries <dafydd.harries@collabora.co.uk>");

  g_object_class_install_property (gobject_class, PROP_AGENT,
      g_param_spec_object (
         "agent",
         "Agent",
         "The NiceAgent this source is bound to",
         NICE_TYPE_AGENT,
         G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_STREAM,
      g_param_spec_uint (
         "stream",
         "Stream ID",
         "The ID of the stream to read from",
         0,
         G_MAXUINT,
         0,
         G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_COMPONENT,
      g_param_spec_uint (
         "component",
         "Component ID",
         "The ID of the component to read from",
         0,
         G_MAXUINT,
         0,
         G_PARAM_READWRITE));
  
  g_object_class_install_property (gobject_class, PROP_COORDINATOR,
      g_param_spec_object (
         "coordinator",
         "Coordinator",
         "The this source is bound to",
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
  gstelement_class->change_state =
      GST_DEBUG_FUNCPTR (gst_nice_src_change_state);

//  gstpushsrc_class = (GstPushSrcClass *) klass;
//  gstpushsrc_class->create = GST_DEBUG_FUNCPTR (gst_nice_src_create);
//
//  gstbasesrc_class = (GstBaseSrcClass *) klass;
//  gstbasesrc_class->unlock = GST_DEBUG_FUNCPTR (gst_nice_src_unlock);
//  gstbasesrc_class->unlock_stop = GST_DEBUG_FUNCPTR (gst_nice_src_unlock_stop);
//  gstbasesrc_class->negotiate = GST_DEBUG_FUNCPTR (gst_nice_src_negotiate);
//  gstbasesrc_class->event = GST_DEBUG_FUNCPTR (gst_nice_src_handle_event);

  gstelement_class->change_state = gst_nice_src_change_state;

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&gst_nice_src_src_template));

  gst_element_class_set_details_simple (gstelement_class, "nIce src",
      "Source/Network",
      "Communicates trough firewalls",
      "Frederik M. J. Vestre <frederik.vestre@pexip.com>");

  GST_DEBUG_CATEGORY_INIT (nicesrc_debug, "nicesrc",
      0, "libnice source");



}

static guint
gst_nice_src_data_hash(const char* bytes, size_t length, guint h)
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
gst_nice_src_address_hash (gconstpointer key)
{
  const NiceAddress *from = (NiceAddress *)key;

  guint hash = gst_nice_src_data_hash((gpointer)&from->s.addr.sa_family, sizeof(from->s.addr.sa_family), 0);

  switch (from->s.addr.sa_family) {
    case AF_INET:
      hash = gst_nice_src_data_hash((gpointer)&from->s.ip4, sizeof (from->s.ip4), hash);
      break;
    case AF_INET6:
      hash = gst_nice_src_data_hash((gpointer)&from->s.ip6, sizeof (from->s.ip6), hash);
      break;
    default:
      GST_ERROR_OBJECT (from, "Unknown address family");
      break;
  }

  return hash;
}

static GSocketAddress*
gst_nice_src_gsocket_addr_create_or_retrieve (GstNiceSrc *src,
                                              const NiceAddress *native_addr)
{
  GSocketAddress *result = g_hash_table_lookup(src->socket_addresses,
                                               native_addr);
  if (G_UNLIKELY(result == NULL)) {
    /* Convert and insert into hash table if it is not present already */
    switch (native_addr->s.addr.sa_family) {
      case AF_INET:
        result = g_socket_address_new_from_native ((gpointer)&native_addr->s.ip4,
                                                   sizeof (native_addr->s.ip4));
        break;
      case AF_INET6:
        result = g_socket_address_new_from_native ((gpointer)&native_addr->s.ip6,
                                                   sizeof (native_addr->s.ip6));
        break;
      default:
        GST_ERROR_OBJECT (src, "Unknown address family");
        break;
    }

    if (G_UNLIKELY(result == NULL)) {
        GST_ERROR_OBJECT (src, "Could not create address gobject");
        return result;
    }

    NiceAddress *key = g_slice_new(NiceAddress);
    memcpy(key, native_addr, sizeof(NiceAddress));

    gst_object_ref(result);
    g_hash_table_insert(src->socket_addresses, key, result);
  } else {
    gst_object_ref(result);
  }
  return result;
}

static gboolean
gst_nice_src_nice_address_compare (gconstpointer a, gconstpointer b)
{
    const NiceAddress *a_addr = (const NiceAddress*)a;
    const NiceAddress *b_addr = (const NiceAddress*)b;

    if ((a_addr->s.addr.sa_family == b_addr->s.addr.sa_family))
    {
      switch (a_addr->s.addr.sa_family) {
        case AF_INET:
          return memcmp(&a_addr->s.ip4, &b_addr->s.ip4, sizeof (a_addr->s.ip4)) == 0;
        case AF_INET6:
          return memcmp(&a_addr->s.ip6, &b_addr->s.ip6, sizeof (a_addr->s.ip6)) == 0;
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
gst_nice_src_init (GstNiceSrc *src)
{
  GstPad *pad;

  gst_base_src_set_live (GST_BASE_SRC (src), TRUE);
  gst_base_src_set_format (GST_BASE_SRC (src), GST_FORMAT_TIME);
  gst_base_src_set_do_timestamp (GST_BASE_SRC (src), TRUE);
  src->agent = NULL;
  src->stream_id = 0;
  src->component_id = 0;
  src->mainctx = g_main_context_new ();
  src->mainloop = g_main_loop_new (src->mainctx, FALSE);
  src->unlocked = FALSE;
  src->idle_source = NULL;
  src->outbufs = g_queue_new ();
  src->caps = gst_caps_new_any ();
  src->socket_addresses = g_hash_table_new_full(gst_nice_src_address_hash,
                                                gst_nice_src_nice_address_compare,
                                                gst_nice_src_destroy_hash_key,
                                                gst_object_unref);

  pad = gst_pad_new_from_template ((GstPadTemplate*)(&gst_nice_src_src_template), "src");
  GST_DEBUG_OBJECT (src, "setting functions on src pad");

  gst_pad_set_active (pad, TRUE);

  src->srcpad = (GstNiceSrcPad*)pad;

}

static gboolean
gst_nice_src_send_stream_start (GstNiceSrc * nicesrc)
{
  gboolean ret;
  gchar *stream_id;
  GstEvent *event;
  const gchar *padname = GST_OBJECT_NAME (nicesrc->srcpad);

  GST_DEBUG_OBJECT (nicesrc, "Pushing STREAM_START");
  stream_id = gst_pad_create_stream_id ((GstPad*)nicesrc->srcpad, GST_ELEMENT_CAST (nicesrc),
      padname + 4);
  event = gst_event_new_stream_start (stream_id);
  gst_event_set_group_id (event, gst_util_group_id_next ());
  ret = gst_pad_push_event ((GstPad*)nicesrc->srcpad, event);
  g_free (stream_id);
  return ret;
}

static gboolean
gst_nice_src_send_caps (GstNiceSrc * nicesrc)
{
  gboolean ret = TRUE;
  GstCaps *caps = gst_pad_peer_query_caps ((GstPad*)nicesrc->srcpad, NULL);

  if (caps && !gst_caps_is_empty (caps) && !gst_caps_is_any (caps)) {
    caps = gst_caps_fixate (caps);
    GST_DEBUG_OBJECT (nicesrc, "Pushing CAPS %" GST_PTR_FORMAT, caps);
    ret = gst_pad_push_event ((GstPad*)nicesrc->srcpad, gst_event_new_caps (caps));
  } else {
    GST_WARNING_OBJECT (nicesrc, "NOT Pushing CAPS %" GST_PTR_FORMAT, caps);
  }

  if (caps != NULL)
    gst_caps_unref (caps);

  return ret;
}

static gboolean
gst_nice_src_send_segment (GstNiceSrc * nicesrc)
{
  GstEvent *event;
  GstSegment segment;

  GST_DEBUG_OBJECT (nicesrc, "Pushing SEGMENT");
  gst_segment_init (&segment, GST_FORMAT_TIME);
  event = gst_event_new_segment (&segment);
  gst_event_set_seqnum (event, gst_util_seqnum_next ());

  return gst_pad_push_event ((GstPad*)nicesrc->srcpad, event);
}

/* Called for async sockets */
static void
gst_nice_src_recvmsg_callback (NiceAgent *agent,
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
gst_nice_src_read_callback (NiceAgent *agent,
    guint stream_id,
    guint component_id,
    guint len,
    gchar *buf,
    gpointer data,
    const NiceAddress *from,
    const NiceAddress *to)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (data);
  //GstNiceSrcPad *nicepad = nicesrc->srcpad;
#if !GST_CHECK_VERSION (1,0,0)
  GstNetBuffer *netbuffer = NULL;
#endif
  GstBuffer *buffer = NULL;

  (void)stream_id;
  (void)component_id;

  GST_LOG_OBJECT (agent, "Got buffer, getting out of the main loop");

  if (G_UNLIKELY (!nicesrc->srcpad->stream_started)) {
    gst_nice_src_send_stream_start (nicesrc);
    nicesrc->srcpad->stream_started = TRUE;
  }
#if GST_CHECK_VERSION (1,0,0)
  (void)to;
  /* Not doing buffer pools at the moment, this requres copying far to much code
  from gstbasesrc
  GstFlowReturn status = gst_nice_src_alloc(nicesrc, 0, len, &buffer);
  */
  //if (status != GST_FLOW_OK)
  {
    //GST_LOG_OBJECT (nicesrc, "Could not allocate buffer using common allocator"
    //                           ", allocate using local allocator instead");
    buffer = gst_buffer_new_allocate (NULL, len, NULL);
  }
  gst_buffer_fill (buffer, 0, buf, len);

  if (from != NULL) {
    GSocketAddress * saddr = gst_nice_src_gsocket_addr_create_or_retrieve(
      nicesrc, from);
    if (saddr != NULL) {
      gst_buffer_add_net_address_meta (buffer, saddr);
      g_object_unref (saddr);
    } else {
      GST_ERROR_OBJECT (nicesrc, "Could not convert address to GSocketAddress");
    }
  }
#else
  if (from != NULL && to != NULL) {
    netbuffer = gst_netbuffer_new();

    GST_BUFFER_DATA(netbuffer) = g_memdup(buf, len);
    GST_BUFFER_MALLOCDATA(netbuffer) = GST_BUFFER_DATA(netbuffer);
    GST_BUFFER_SIZE(netbuffer) = len;

    switch (from->s.addr.sa_family) {
    case AF_INET:
      {
        gst_netaddress_set_ip4_address (&netbuffer->from, from->s.ip4.sin_addr.s_addr, from->s.ip4.sin_port);
        gst_netaddress_set_ip4_address (&netbuffer->to, to->s.ip4.sin_addr.s_addr, to->s.ip4.sin_port);
      }
      break;
    case AF_INET6:
      {
        gst_netaddress_set_ip6_address (&netbuffer->from, (guint8 *)(&from->s.ip6.sin6_addr), from->s.ip6.sin6_port);
        gst_netaddress_set_ip6_address (&netbuffer->to, (guint8 *)(&to->s.ip6.sin6_addr), to->s.ip6.sin6_port);
      }
      break;
    default:
      GST_ERROR_OBJECT (nicesrc, "Unknown address family");
      break;
    }


    buffer = GST_BUFFER_CAST(netbuffer);
  } else {
    buffer = gst_buffer_new_and_alloc (len);
    memcpy (GST_BUFFER_DATA (buffer), buf, len);
  }
#endif
  g_queue_push_tail (nicesrc->outbufs, buffer);

  g_main_loop_quit (nicesrc->mainloop);
}

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

/* Similar to gst_base_src_default_negotiate except that it always queries
 * downstream for allowed caps. This is because the default behavior never
 * sends a caps-event if the template caps is any. */
static gboolean
gst_nice_src_negotiate (GstBaseSrc * basesrc)
{
  GstCaps *caps, *intersect;
  GstNiceSrc *src = GST_NICE_SRC_CAST (basesrc);
  gboolean result = FALSE;

  caps = gst_pad_get_allowed_caps (GST_BASE_SRC_PAD (basesrc));
  if (!caps)
    caps = gst_pad_get_pad_template_caps (GST_BASE_SRC_PAD (basesrc));

  GST_OBJECT_LOCK (src);
  intersect = gst_caps_intersect (src->caps, caps);
  GST_OBJECT_UNLOCK (src);

  gst_caps_take (&caps, intersect);

  if (!gst_caps_is_empty (caps)) {
    if (gst_caps_is_any (caps)) {
      GST_DEBUG_OBJECT (basesrc, "any caps, negotiation not needed");
      result = TRUE;
    } else {
      GstBaseSrcClass *bclass = GST_BASE_SRC_GET_CLASS (basesrc);
      if (bclass->fixate)
        caps = bclass->fixate (basesrc, caps);
      GST_DEBUG_OBJECT (basesrc, "fixated to: %" GST_PTR_FORMAT, caps);
      if (gst_caps_is_fixed (caps)) {
        result = gst_base_src_set_caps (basesrc, caps);
      }
    }
    gst_caps_unref (caps);
  } else {
    GST_DEBUG_OBJECT (basesrc, "no common caps");
  }
  return result;
}

static GstFlowReturn
gst_nice_src_create (
  GstPushSrc *basesrc,
  GstBuffer **buffer)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (basesrc);

  GST_LOG_OBJECT (nicesrc, "create called");

  GST_OBJECT_LOCK (basesrc);
  if (nicesrc->unlocked) {
    GST_OBJECT_UNLOCK (basesrc);
#if GST_CHECK_VERSION (1,0,0)
    return GST_FLOW_FLUSHING;
#else
    return GST_FLOW_WRONG_STATE;
#endif
  }
  GST_OBJECT_UNLOCK (basesrc);

  if (g_queue_is_empty (nicesrc->outbufs))
    g_main_loop_run (nicesrc->mainloop);

  *buffer = g_queue_pop_head (nicesrc->outbufs);
  if (*buffer != NULL) {
    GST_LOG_OBJECT (nicesrc, "Got buffer, pushing");
    return GST_FLOW_OK;
  } else {
    GST_LOG_OBJECT (nicesrc, "Got interrupting, returning wrong-state");
#if GST_CHECK_VERSION (1,0,0)
    return GST_FLOW_FLUSHING;
#else
    return GST_FLOW_WRONG_STATE;
#endif
  }

}

static void
gst_nice_src_dispose (GObject *object)
{
  GstNiceSrc *src = GST_NICE_SRC (object);

  if (src->idle_source) {
    g_source_destroy (src->idle_source);
    g_source_unref(src->idle_source);
  }
  src->idle_source = NULL;

  if (src->agent)
    g_object_unref (src->agent);
  src->agent = NULL;

  if (src->mainloop)
    g_main_loop_unref (src->mainloop);
  src->mainloop = NULL;

  if (src->mainctx)
    g_main_context_unref (src->mainctx);
  src->mainctx = NULL;

  if (src->outbufs)
    g_queue_free_full (src->outbufs, (GDestroyNotify)gst_buffer_unref);
  src->outbufs = NULL;

  g_hash_table_remove_all(src->socket_addresses);
  g_hash_table_unref(src->socket_addresses);
  src->socket_addresses = NULL;

  gst_caps_replace (&src->caps, NULL);

  G_OBJECT_CLASS (gst_nice_src_parent_class)->dispose (object);
}

static void
gst_nice_src_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec)
{
  GstNiceSrc *src = GST_NICE_SRC (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      if (src->agent)
        GST_ERROR_OBJECT (object,
            "Changing the agent on a nice src not allowed");
      else
        src->agent = g_value_dup_object (value);
      break;

    case PROP_STREAM:
      src->stream_id = g_value_get_uint (value);
      break;

    case PROP_COMPONENT:
      src->component_id = g_value_get_uint (value);
      break;

    case PROP_COORDINATOR:
      if (src->coordinator)
        GST_ERROR_OBJECT (object,
            "Changing the coordinator on a nice src not allowed");
      else
        src->coordinator = g_value_dup_object (value);
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
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
gst_nice_src_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec)
{
  GstNiceSrc *src = GST_NICE_SRC (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      g_value_set_object (value, src->agent);
      break;

    case PROP_STREAM:
      g_value_set_uint (value, src->stream_id);
      break;

    case PROP_COMPONENT:
      g_value_set_uint (value, src->component_id);
      break;

#if 0
    case PROP_CAPS:
      GST_OBJECT_LOCK (src);
      gst_value_set_caps (value, src->caps);
      GST_OBJECT_UNLOCK (src);
      break;
#endif
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
gst_nice_src_log_callback (NiceAgent *agent, guint stream_id, guint component_id, GLogLevelFlags level,
    gchar *msg, gpointer data)
{
  (void)agent;
  GstBaseSrc *basesrc = GST_BASE_SRC (data);
  GstNiceSrc *nicesrc = GST_NICE_SRC (basesrc);

  switch (level) {
  case G_LOG_LEVEL_WARNING:
    GST_WARNING_OBJECT (nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  case G_LOG_LEVEL_INFO:
    GST_INFO_OBJECT (nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  default:
    GST_DEBUG_OBJECT (nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  }
}

static GstStateChangeReturn
gst_nice_src_change_state (GstElement * element, GstStateChange transition)
{
  GstNiceSrc *src;
  GstStateChangeReturn ret;

  src = GST_NICE_SRC (element);

  switch (transition) {
    case GST_STATE_CHANGE_NULL_TO_READY:
      if (src->agent == NULL || src->stream_id == 0 || src->component_id == 0)
        {
          GST_ERROR_OBJECT (element,
              "Trying to start Nice source without an agent set");
          return GST_STATE_CHANGE_FAILURE;
        }
      else
        {
          nice_agent_attach_recv (src->agent, src->stream_id, src->component_id,
              src->mainctx, gst_nice_src_read_callback, gst_nice_src_recvmsg_callback, (gpointer) src);
        }
      break;
    case GST_STATE_CHANGE_READY_TO_NULL:
      nice_agent_attach_recv (src->agent, src->stream_id, src->component_id,
          src->mainctx, NULL, NULL, NULL);
      break;
    default:
      break;
  }

  ret = GST_ELEMENT_CLASS (gst_nice_src_parent_class)->change_state (element,
      transition);

  return ret;
}

/* Handle Gstreamer system events */
static GstNiceSrcPollState gst_nice_src_poll_system ( GstNiceSrc* src)
{

  if (G_UNLIKELY (!src->srcpad->stream_started)) {
    gst_nice_src_send_stream_start (src);
    src->srcpad->stream_started = TRUE;
  }

  if (G_UNLIKELY (gst_pad_check_reconfigure (GST_PAD_CAST(src->srcpad))))
  {
    gst_nice_src_send_caps (src);
  }

  if (G_UNLIKELY (!src->srcpad->segment_sent)) {
    gst_nice_src_send_segment (src);
    src->srcpad->segment_sent = TRUE;
  }

  return GST_NICE_SRC_POLL_EMPTY;
}

GstNiceSrcPollState gst_nice_src_poll (GstNiceSrc* src)
{
  gboolean context_processed_element = FALSE;
  GST_OBJECT_LOCK (src);

  //First see if there are any system events that must be managed
   GstNiceSrcPollState system_poll_state_result = gst_nice_src_poll_system(src);
  if (system_poll_state_result != GST_NICE_SRC_POLL_EMPTY)
  {
    GST_OBJECT_UNLOCK (src);
    return system_poll_state_result;
  }

  if (nice_agent_component_uses_main_context(src->agent, src->stream_id, src->component_id)) {
    if (g_main_context_pending(src->mainctx)) {
      context_processed_element = g_main_context_iteration (src->mainctx, FALSE);
    }
  }
  GST_OBJECT_UNLOCK (src);

  if(context_processed_element)
  {
    return GST_NICE_SRC_POLL_PROCESSED;
  }
  return GST_NICE_SRC_POLL_EMPTY;
}

/* TODO: Add more parameters */
void gst_nice_src_handle_receive (GstNiceSrc* src)
{

}
