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
#if GST_CHECK_VERSION (1,0,0)
#include <gst/net/gstnetaddressmeta.h>
#else
#include <gst/netbuffer/gstnetbuffer.h>
#endif

GST_DEBUG_CATEGORY_STATIC (nicesrc_debug);
#define GST_CAT_DEFAULT nicesrc_debug


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
  PROP_CAPS
};

static gboolean
gst_nice_src_handle_event (GstBaseSrc *basesrc, GstEvent * event)
{
  GstNiceSrc *src = GST_NICE_SRC_CAST (basesrc);
  gboolean ret = TRUE;

  GST_LOG_OBJECT (src, "handling %s event", GST_EVENT_TYPE_NAME (event));

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_CUSTOM_UPSTREAM:
    {
      if (gst_event_has_name (event, "PexQosOverflow")) {
        GST_INFO_OBJECT (src, "Suspend TCP receive, QOS received");
        nice_agent_set_rx_enabled (src->agent, src->stream_id, src->component_id, FALSE);
        ret = TRUE;
      } else if (gst_event_has_name (event, "PexQosUnderflow")) {
        GST_INFO_OBJECT (src, "Resume TCP receive, QOS received");
        nice_agent_set_rx_enabled (src->agent, src->stream_id, src->component_id, TRUE);
        ret = TRUE;
      } else {
        ret = GST_BASE_SRC_CLASS (parent_class)->event (basesrc, event);
      }
      break;
    }

    default:
    {
      GST_LOG_OBJECT (src, "let base class handle event");
      ret = GST_BASE_SRC_CLASS (parent_class)->event (basesrc, event);
      break;
    }
  }

  return ret;
}

static void
gst_nice_src_class_init (GstNiceSrcClass *klass)
{
  GstPushSrcClass *gstpushsrc_class;
  GstBaseSrcClass *gstbasesrc_class;
  GstElementClass *gstelement_class;
  GObjectClass *gobject_class;

  GST_DEBUG_CATEGORY_INIT (nicesrc_debug, "nicesrc",
      0, "libnice source");

  gstpushsrc_class = (GstPushSrcClass *) klass;
  gstpushsrc_class->create = GST_DEBUG_FUNCPTR (gst_nice_src_create);

  gstbasesrc_class = (GstBaseSrcClass *) klass;
  gstbasesrc_class->unlock = GST_DEBUG_FUNCPTR (gst_nice_src_unlock);
  gstbasesrc_class->unlock_stop = GST_DEBUG_FUNCPTR (gst_nice_src_unlock_stop);
  gstbasesrc_class->negotiate = GST_DEBUG_FUNCPTR (gst_nice_src_negotiate);
  gstbasesrc_class->event = GST_DEBUG_FUNCPTR (gst_nice_src_handle_event);

  gobject_class = (GObjectClass *) klass;
  gobject_class->set_property = gst_nice_src_set_property;
  gobject_class->get_property = gst_nice_src_get_property;
  gobject_class->dispose = gst_nice_src_dispose;

  gstelement_class = (GstElementClass *) klass;
  gstelement_class->change_state = gst_nice_src_change_state;

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&gst_nice_src_src_template));
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

  g_object_class_install_property (gobject_class, PROP_CAPS,
      g_param_spec_boxed (
          "caps",
          "Caps",
          "The caps of the source pad",
          GST_TYPE_CAPS,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gst_nice_src_init (GstNiceSrc *src)
{
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
  GstBaseSrc *basesrc = GST_BASE_SRC (data);
  GstNiceSrc *nicesrc = GST_NICE_SRC (basesrc);
#if !GST_CHECK_VERSION (1,0,0)
  GstNetBuffer *netbuffer = NULL;
#endif
  GstBuffer *buffer = NULL;

  (void)stream_id;
  (void)component_id;

  GST_LOG_OBJECT (agent, "Got buffer, getting out of the main loop");

#if GST_CHECK_VERSION (1,0,0)
  (void)to;
  buffer = gst_buffer_new_allocate (NULL, len, NULL);
  gst_buffer_fill (buffer, 0, buf, len);

  if (from != NULL) {
    GSocketAddress * saddr;
    switch (from->s.addr.sa_family) {
      case AF_INET:
        if ((saddr = g_socket_address_new_from_native ((gpointer)&from->s.ip4, sizeof (from->s.ip4))) != NULL) {
          gst_buffer_add_net_address_meta (buffer, saddr);
          g_object_unref (saddr);
        }
        break;
      case AF_INET6:
        if ((saddr = g_socket_address_new_from_native ((gpointer)&from->s.ip6, sizeof (from->s.ip6))) != NULL) {
          gst_buffer_add_net_address_meta (buffer, saddr);
          g_object_unref (saddr);
        }
        break;
      default:
        GST_ERROR_OBJECT (nicesrc, "Unknown address family");
        break;
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
      gst_caps_replace (&src->caps, new_caps);
      GST_OBJECT_UNLOCK (src);

      gst_pad_mark_reconfigure (GST_BASE_SRC_PAD (src));
      break;
    }

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

    case PROP_CAPS:
      GST_OBJECT_LOCK (src);
      gst_value_set_caps (value, src->caps);
      GST_OBJECT_UNLOCK (src);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
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
              src->mainctx, gst_nice_src_read_callback, (gpointer) src);
        }
      break;
    case GST_STATE_CHANGE_READY_TO_NULL:
      nice_agent_attach_recv (src->agent, src->stream_id, src->component_id,
          src->mainctx, NULL, NULL);
      break;
    default:
      break;
  }

  ret = GST_ELEMENT_CLASS (gst_nice_src_parent_class)->change_state (element,
      transition);

  return ret;
}


