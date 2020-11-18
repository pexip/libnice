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

#include "gstnicesink.h"

#include <gst/net/gsttxfeedback.h>

GST_DEBUG_CATEGORY_STATIC (nicesink_debug);
#define GST_CAT_DEFAULT nicesink_debug

static GstFlowReturn
gst_nice_sink_render (
  GstBaseSink *basesink,
  GstBuffer *buffer);

static void
gst_nice_sink_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec);

static void
gst_nice_sink_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec);

static void
gst_nice_sink_dispose (GObject *object);

static GstStateChangeReturn
gst_nice_sink_change_state (
    GstElement * element,
    GstStateChange transition);

static GstStaticPadTemplate gst_nice_sink_sink_template =
GST_STATIC_PAD_TEMPLATE (
    "sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

G_DEFINE_TYPE (GstNiceSink, gst_nice_sink, GST_TYPE_BASE_SINK);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM,
  PROP_COMPONENT,
  PROP_MAINLOOP
};


static void
gst_nice_sink_class_init (GstNiceSinkClass *klass)
{
  GstBaseSinkClass *gstbasesink_class;
  GstElementClass *gstelement_class;
  GObjectClass *gobject_class;

  GST_DEBUG_CATEGORY_INIT (nicesink_debug, "nicesink",
      0, "libnice sink");

  gstbasesink_class = (GstBaseSinkClass *) klass;
  gstbasesink_class->render = GST_DEBUG_FUNCPTR (gst_nice_sink_render);

  gobject_class = (GObjectClass *) klass;
  gobject_class->set_property = gst_nice_sink_set_property;
  gobject_class->get_property = gst_nice_sink_get_property;
  gobject_class->dispose = gst_nice_sink_dispose;

  gstelement_class = (GstElementClass *) klass;
  gstelement_class->change_state = gst_nice_sink_change_state;

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&gst_nice_sink_sink_template));
#if GST_CHECK_VERSION (1,0,0)
  gst_element_class_set_metadata (gstelement_class,
#else
  gst_element_class_set_details_simple (gstelement_class,
#endif
    "ICE sink",
    "Sink",
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

  g_object_class_install_property (gobject_class, PROP_MAINLOOP,
      g_param_spec_pointer (
         "mainloop",
         "Main loop",
         "The main loop used to drive agent functions",
         G_PARAM_READWRITE));
}

static void
gst_nice_sink_init (GstNiceSink *sink)
{
  (void)sink;
}

static void
gst_nice_sink_dispose (GObject *object)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  if (sink->agent != NULL) {
    g_object_unref (sink->agent);
    sink->agent = NULL;
  }

  if (sink->mainloop)
  {
    g_main_loop_unref (sink->mainloop);
  }
  sink->mainloop = NULL;

  G_OBJECT_CLASS (gst_nice_sink_parent_class)->dispose (object);
}

static void
_set_time_on_buffer (GstNiceSink * sink, GstBuffer *buffer)
{
  GstClock *clock = GST_ELEMENT_CLOCK (sink);
  GstClockTime base_time = GST_ELEMENT_CAST (sink)->base_time;
  GstClockTime now;
  GstTxFeedbackMeta *meta;

  if (clock == NULL)
    return;

  now = gst_clock_get_time (clock) - base_time;
  meta = gst_buffer_get_tx_feedback_meta (buffer);
  if (meta)
    gst_tx_feedback_meta_set_tx_time (meta, now);
}

static GstFlowReturn
gst_nice_sink_render (GstBaseSink *basesink, GstBuffer *buffer)
{
  GstNiceSink *nicesink = GST_NICE_SINK (basesink);

#if GST_CHECK_VERSION (1,0,0)
  GstMapInfo info;

  gst_buffer_map (buffer, &info, GST_MAP_READ);
  GST_INFO_OBJECT (nicesink->agent, "Sending buffer with length %d", info.size);

  nice_agent_send (nicesink->agent, nicesink->stream_id,
      nicesink->component_id, info.size, (gchar *) info.data);

  gst_buffer_unmap (buffer, &info);
#else
  nice_agent_send (nicesink->agent, nicesink->stream_id,
      nicesink->component_id, GST_BUFFER_SIZE (buffer),
      (gchar *) GST_BUFFER_DATA (buffer));
#endif

  _set_time_on_buffer (nicesink, buffer);

  return GST_FLOW_OK;
}

static void
gst_nice_sink_on_overflow (GstNiceSink * sink,
    guint stream_id, guint component_id, NiceAgent * agent)
{
  (void) agent;

  if (stream_id == sink->stream_id && component_id == sink->component_id) {
    GST_DEBUG_OBJECT (sink, "Sink overflow for stream %d, component %d", stream_id, component_id);

#if GST_CHECK_VERSION (1,0,0)
    gst_pad_push_event (GST_BASE_SINK_PAD (sink),
        gst_event_new_custom (GST_EVENT_CUSTOM_UPSTREAM, gst_structure_new_empty ("PexQosOverflow")));
#else
    gst_pad_push_event (GST_BASE_SINK_PAD (sink),
        gst_event_new_custom (GST_EVENT_CUSTOM_UPSTREAM, gst_structure_new_empty ("PexQosOverflow")));
#endif
  }
}

static void
gst_nice_sink_on_writable (GstNiceSink * sink,
    guint stream_id, guint component_id, NiceAgent * agent)
{
  (void) agent;

  if (stream_id == sink->stream_id && component_id == sink->component_id) {
    GST_DEBUG_OBJECT (sink, "Sink underflow for stream %d, component %d", stream_id, component_id);

#if GST_CHECK_VERSION (1,0,0)
    gst_pad_push_event (GST_BASE_SINK_PAD (sink),
        gst_event_new_custom (GST_EVENT_CUSTOM_UPSTREAM, gst_structure_new_empty ("PexQosUnderflow")));
#else
    gst_pad_push_event (GST_BASE_SINK_PAD (sink),
        gst_event_new_custom (GST_EVENT_CUSTOM_UPSTREAM, gst_structure_new_empty ("PexQosUnderflow")));
#endif
  }
}

static void
gst_nice_sink_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      if (sink->agent) {
        GST_ERROR_OBJECT (object,
            "Changing the agent on a nice sink not allowed");
      } else {
        sink->agent = g_value_dup_object (value);
      }
      break;

    case PROP_MAINLOOP:
      if (sink->mainloop) {
        GST_ERROR_OBJECT (object,
            "Changing the mainloop on a nice sink not allowed");
      } else {
        sink->mainloop = g_value_get_pointer (value);
        g_main_loop_ref(sink->mainloop);
      }
      break;

    case PROP_STREAM:
      sink->stream_id = g_value_get_uint (value);
      break;

    case PROP_COMPONENT:
      sink->component_id = g_value_get_uint (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
gst_nice_sink_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      g_value_set_object (value, sink->agent);
      break;

    case PROP_MAINLOOP:
      g_value_set_pointer (value, sink->mainloop);
      break;

    case PROP_STREAM:
      g_value_set_uint (value, sink->stream_id);
      break;

    case PROP_COMPONENT:
      g_value_set_uint (value, sink->component_id);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static int disconnect_signals_inside_mainloop(void *data)
{
  GstNiceSink *sink = GST_NICE_SINK (data);

  /* Run this on the papanice thread, and wait for it to complete before
   changing the gstreamer state */
  g_signal_handler_disconnect (sink->agent, sink->overflow_hid);
  g_signal_handler_disconnect (sink->agent, sink->writable_hid);
  g_mutex_lock(&sink->signal_disconnection_complete_mutex);
  sink->signal_disconnection_complete = TRUE;
  g_cond_signal(&sink->signal_disconnection_complete_cond);
  g_mutex_unlock(&sink->signal_disconnection_complete_mutex);
  return 0;
}

static void run_disconnect_signals_in_mainloop(GstNiceSink * sink)
{
  /* NB: The g_main_loop_is_running test function may still be racy */
  if ((sink->mainloop != NULL) &&
      (g_main_loop_is_running (sink->mainloop)))
  {
    GSource *source = g_idle_source_new ();
    g_source_set_callback (source, disconnect_signals_inside_mainloop, (gpointer*)sink, NULL);
    g_source_attach (source, g_main_loop_get_context(sink->mainloop));
    g_source_unref (source);

    /* Wait for reactor to complete our asynchronous function */
    g_mutex_lock(&sink->signal_disconnection_complete_mutex);
    while (!sink->signal_disconnection_complete)
    {
      g_cond_wait(&sink->signal_disconnection_complete_cond, &sink->signal_disconnection_complete_mutex);
    }
    g_mutex_unlock(&sink->signal_disconnection_complete_mutex);
  }
  else
  {
    disconnect_signals_inside_mainloop(sink);
  }
}

static GstStateChangeReturn
gst_nice_sink_change_state (GstElement * element, GstStateChange transition)
{
  GstNiceSink *sink;
  GstStateChangeReturn ret;

  sink = GST_NICE_SINK (element);

  switch (transition) {
    case GST_STATE_CHANGE_NULL_TO_READY:
      if (sink->agent == NULL) {
          GST_ERROR_OBJECT (element,
              "Trying to start Nice sink without an agent set");
          return GST_STATE_CHANGE_FAILURE;
      } else {
        sink->overflow_hid = g_signal_connect_swapped (sink->agent,
            "reliable-transport-overflow",
            G_CALLBACK (gst_nice_sink_on_overflow), sink);
        sink->writable_hid = g_signal_connect_swapped (sink->agent,
            "reliable-transport-writable",
            G_CALLBACK (gst_nice_sink_on_writable), sink);
      }
      break;
    case GST_STATE_CHANGE_READY_TO_NULL:
      if (sink->agent != NULL) {
        run_disconnect_signals_in_mainloop(sink);
      }
      break;
    default:
      break;
  }

  ret = GST_ELEMENT_CLASS (gst_nice_sink_parent_class)->change_state (element,
      transition);

  return ret;
}
