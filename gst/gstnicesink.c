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
static void
gst_nice_sink_finalize (GObject *object);

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
  PROP_MAINLOOP,
  PROP_SEND_FAILURES,
  PROP_LAST_SEND_ERROR,
  PROP_ERROR_ON_SUSTAINED_FAILURE,
  PROP_SUSTAINED_FAILURE_TIMEOUT
};

/* Interval between periodic warnings while a send failure run continues.
 * Throttled by elapsed time, not by packet count, since this element can
 * see thousands of buffers per second. */
#define GST_NICE_SINK_FAILURE_REPORT_INTERVAL (5 * G_USEC_PER_SEC)

#define GST_NICE_SINK_DEFAULT_SUSTAINED_FAILURE_TIMEOUT 30000


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
  gobject_class->finalize = gst_nice_sink_finalize;

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

  g_object_class_install_property (gobject_class, PROP_SEND_FAILURES,
      g_param_spec_uint64 (
         "send-failures",
         "Send failures",
         "Cumulative number of buffers that could not be sent to the agent",
         0,
         G_MAXUINT64,
         0,
         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_LAST_SEND_ERROR,
      g_param_spec_int (
         "last-send-error",
         "Last send error",
         "The value last returned by nice_agent_send() for a failed send",
         G_MININT,
         G_MAXINT,
         0,
         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class,
      PROP_ERROR_ON_SUSTAINED_FAILURE,
      g_param_spec_boolean (
         "error-on-sustained-failure",
         "Error on sustained failure",
         "Post a bus error and return a flow error once sends have been "
         "failing for longer than sustained-failure-timeout",
         FALSE,
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class,
      PROP_SUSTAINED_FAILURE_TIMEOUT,
      g_param_spec_uint (
         "sustained-failure-timeout",
         "Sustained failure timeout",
         "How long (in ms) sends must fail continuously before escalating, "
         "only used when error-on-sustained-failure is set",
         1,
         G_MAXUINT,
         GST_NICE_SINK_DEFAULT_SUSTAINED_FAILURE_TIMEOUT,
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gst_nice_sink_init (GstNiceSink *sink)
{
  g_mutex_init (&sink->signal_disconnection_complete_mutex);
  g_cond_init (&sink->signal_disconnection_complete_cond);
  sink->sustained_failure_timeout =
      GST_NICE_SINK_DEFAULT_SUSTAINED_FAILURE_TIMEOUT;
}

static void
gst_nice_sink_dispose (GObject *object)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  if (sink->agent != NULL) {
    g_object_unref (sink->agent);
    sink->agent = NULL;
  }

  if (sink->mainloop) {
    g_main_loop_unref (sink->mainloop);
    sink->mainloop = NULL;
  }

  G_OBJECT_CLASS (gst_nice_sink_parent_class)->dispose (object);
}

static void
gst_nice_sink_finalize (GObject *object)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  g_mutex_clear (&sink->signal_disconnection_complete_mutex);
  g_cond_clear (&sink->signal_disconnection_complete_cond);

  G_OBJECT_CLASS (gst_nice_sink_parent_class)->finalize (object);
}

static void
_set_time_on_buffer (GstNiceSink * sink, GstBuffer *buffer)
{
  GstClock *clock = GST_ELEMENT_CLOCK (sink);
  GstClockTime now;
  GstTxFeedbackMeta *meta;

  if (clock == NULL)
    return;

  now = gst_clock_get_time (clock);
  meta = gst_buffer_get_tx_feedback_meta (buffer);
  if (meta)
    gst_tx_feedback_meta_set_tx_time (meta, now);
}

static void
gst_nice_sink_push_upstream_event (GstNiceSink * sink, GstStructure * s)
{
  gst_pad_push_event (GST_BASE_SINK_PAD (sink),
      gst_event_new_custom (GST_EVENT_CUSTOM_UPSTREAM, s));
}

/* Handles a send that did not fully succeed. Returns the flow return to use:
 * GST_FLOW_OK unless escalation has been explicitly enabled and the failure
 * run has lasted longer than the configured timeout. */
static GstFlowReturn
gst_nice_sink_handle_send_failure (GstNiceSink * sink, gint send_ret,
    guint size)
{
  gint64 now = g_get_monotonic_time ();

  sink->send_failures++;
  sink->last_send_error = send_ret;
  sink->failure_run_packets++;
  sink->failure_run_bytes += size;

  if (!sink->send_failing) {
    sink->send_failing = TRUE;
    sink->escalated = FALSE;
    sink->failure_run_start = now;
    sink->failure_last_report = now;

    GST_WARNING_OBJECT (sink, "Send failure on stream %u component %u: "
        "nice_agent_send() returned %d for a %u byte buffer, dropping",
        sink->stream_id, sink->component_id, send_ret, size);

    gst_nice_sink_push_upstream_event (sink,
        gst_structure_new ("PexNiceSendFailureStarted",
            "stream-id", G_TYPE_UINT, sink->stream_id,
            "component-id", G_TYPE_UINT, sink->component_id,
            "error", G_TYPE_INT, send_ret, NULL));
  } else if (now - sink->failure_last_report >=
      GST_NICE_SINK_FAILURE_REPORT_INTERVAL) {
    sink->failure_last_report = now;

    GST_WARNING_OBJECT (sink, "Sends still failing on stream %u component %u: "
        "%" G_GUINT64_FORMAT " packets (%" G_GUINT64_FORMAT " bytes) dropped "
        "over %" G_GINT64_FORMAT " ms, last error %d",
        sink->stream_id, sink->component_id, sink->failure_run_packets,
        sink->failure_run_bytes, (now - sink->failure_run_start) / 1000,
        send_ret);
  }

  if (sink->error_on_sustained_failure) {
    if (!sink->escalated && now - sink->failure_run_start >=
        (gint64) sink->sustained_failure_timeout * 1000) {
      sink->escalated = TRUE;
      GST_ELEMENT_ERROR (sink, RESOURCE, WRITE,
          ("Failed to send media for more than %u ms",
              sink->sustained_failure_timeout),
          ("stream %u component %u: %" G_GUINT64_FORMAT " packets dropped, "
              "last error %d", sink->stream_id, sink->component_id,
              sink->failure_run_packets, send_ret));
    }

    if (sink->escalated)
      return GST_FLOW_ERROR;
  }

  return GST_FLOW_OK;
}

static void
gst_nice_sink_handle_send_success (GstNiceSink * sink, guint size)
{
  if (G_UNLIKELY (sink->send_failing)) {
    gint64 duration = g_get_monotonic_time () - sink->failure_run_start;

    GST_WARNING_OBJECT (sink, "Sends recovered on stream %u component %u "
        "after %" G_GINT64_FORMAT " ms: %" G_GUINT64_FORMAT " packets (%"
        G_GUINT64_FORMAT " bytes) were dropped", sink->stream_id,
        sink->component_id, duration / 1000, sink->failure_run_packets,
        sink->failure_run_bytes);

    gst_nice_sink_push_upstream_event (sink,
        gst_structure_new ("PexNiceSendFailureStopped",
            "stream-id", G_TYPE_UINT, sink->stream_id,
            "component-id", G_TYPE_UINT, sink->component_id,
            "duration-ms", G_TYPE_UINT64, (guint64) (duration / 1000),
            "dropped-packets", G_TYPE_UINT64, sink->failure_run_packets,
            "dropped-bytes", G_TYPE_UINT64, sink->failure_run_bytes, NULL));

    sink->send_failing = FALSE;
    sink->escalated = FALSE;
    sink->failure_run_packets = 0;
    sink->failure_run_bytes = 0;
  }

  GST_LOG_OBJECT (sink, "Sent %u bytes on stream %u component %u", size,
      sink->stream_id, sink->component_id);
}

static GstFlowReturn
gst_nice_sink_render (GstBaseSink *basesink, GstBuffer *buffer)
{
  GstNiceSink *nicesink = GST_NICE_SINK (basesink);
  guint size;
  gint ret;
  gboolean sent;

#if GST_CHECK_VERSION (1,0,0)
  GstMapInfo info;

  gst_buffer_map (buffer, &info, GST_MAP_READ);
  size = info.size;

  ret = nice_agent_send (nicesink->agent, nicesink->stream_id,
      nicesink->component_id, info.size, (gchar *) info.data);

  gst_buffer_unmap (buffer, &info);
#else
  size = GST_BUFFER_SIZE (buffer);
  ret = nice_agent_send (nicesink->agent, nicesink->stream_id,
      nicesink->component_id, GST_BUFFER_SIZE (buffer),
      (gchar *) GST_BUFFER_DATA (buffer));
#endif

  /* nice_agent_send() returns the number of bytes sent, or a negative error
   * code (in particular -1 when the component has no selected pair yet).
   * The socket backends in this tree either take the whole buffer - the TCP
   * one queues whatever the kernel would not take and still reports the full
   * length - or fail, so a short write means the packet was not delivered
   * whatever the transport is, and must not be conflated with success. */
  sent = (ret >= 0 && (guint) ret >= size);

  if (G_LIKELY (sent)) {
    gst_nice_sink_handle_send_success (nicesink, size);
    _set_time_on_buffer (nicesink, buffer);
    return GST_FLOW_OK;
  }

  return gst_nice_sink_handle_send_failure (nicesink, ret, size);
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

    case PROP_ERROR_ON_SUSTAINED_FAILURE:
      sink->error_on_sustained_failure = g_value_get_boolean (value);
      break;

    case PROP_SUSTAINED_FAILURE_TIMEOUT:
      sink->sustained_failure_timeout = g_value_get_uint (value);
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

    case PROP_SEND_FAILURES:
      g_value_set_uint64 (value, sink->send_failures);
      break;

    case PROP_LAST_SEND_ERROR:
      g_value_set_int (value, sink->last_send_error);
      break;

    case PROP_ERROR_ON_SUSTAINED_FAILURE:
      g_value_set_boolean (value, sink->error_on_sustained_failure);
      break;

    case PROP_SUSTAINED_FAILURE_TIMEOUT:
      g_value_set_uint (value, sink->sustained_failure_timeout);
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
