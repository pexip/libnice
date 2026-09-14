/*
 * This file is part of the Nice GLib ICE library.
 *
 * Regression test for nicesink dropping the return value of
 * nice_agent_send(). A send blackout used to be completely invisible:
 * render() returned GST_FLOW_OK unconditionally and stamped TX-feedback
 * timestamps on packets that never left the host.
 *
 * The test drives a GstNiceSink directly (no pipeline) against a real
 * NiceAgent, first with no selected pair at all (every send fails), then
 * with a selected remote candidate pointing at a locally bound UDP socket
 * (every send succeeds), and checks the diagnostics, the upstream events
 * and the TX-feedback behaviour across both transitions.
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
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include <gio/gio.h>

#include <gst/gst.h>
#include <gst/net/gsttxfeedback.h>

#include "gstnicesink.h"

/* A GstTxFeedback implementation that just counts the feedback calls. */
typedef struct
{
  GObject parent;
  guint tx_count;
} TestTxFeedback;

typedef struct
{
  GObjectClass parent_class;
} TestTxFeedbackClass;

static void test_tx_feedback_init_iface (GstTxFeedbackInterface * iface);

#define TEST_TYPE_TX_FEEDBACK (test_tx_feedback_get_type ())
G_DEFINE_TYPE_WITH_CODE (TestTxFeedback, test_tx_feedback, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE (GST_TYPE_TX_FEEDBACK, test_tx_feedback_init_iface));

static void
test_tx_feedback_cb (GstTxFeedback * feedback, guint64 buffer_id,
    GstClockTime ts)
{
  TestTxFeedback *self = (TestTxFeedback *) feedback;

  (void) buffer_id;
  (void) ts;

  self->tx_count++;
}

static void
test_tx_feedback_init_iface (GstTxFeedbackInterface * iface)
{
  iface->tx_feedback = test_tx_feedback_cb;
}

static void
test_tx_feedback_init (TestTxFeedback * self)
{
  self->tx_count = 0;
}

static void
test_tx_feedback_class_init (TestTxFeedbackClass * klass)
{
  (void) klass;
}

/* Upstream events pushed by the sink land here. */
static GList *upstream_events = NULL;

static gboolean
src_event_func (GstPad * pad, GstObject * parent, GstEvent * event)
{
  (void) pad;
  (void) parent;

  upstream_events = g_list_append (upstream_events, event);
  return TRUE;
}

static guint
count_upstream_events (const gchar * name)
{
  GList *item;
  guint count = 0;

  for (item = upstream_events; item; item = item->next) {
    const GstStructure *s = gst_event_get_structure (item->data);

    if (s != NULL && gst_structure_has_name (s, name))
      count++;
  }

  return count;
}

static const GstStructure *
find_upstream_event (const gchar * name)
{
  GList *item;

  for (item = upstream_events; item; item = item->next) {
    const GstStructure *s = gst_event_get_structure (item->data);

    if (s != NULL && gst_structure_has_name (s, name))
      return s;
  }

  return NULL;
}

static void
clear_upstream_events (void)
{
  g_list_free_full (upstream_events, (GDestroyNotify) gst_event_unref);
  upstream_events = NULL;
}

static GstFlowReturn
push_buffer (GstPad * srcpad, TestTxFeedback * feedback)
{
  GstBuffer *buffer = gst_buffer_new_allocate (NULL, 32, NULL);

  gst_buffer_memset (buffer, 0, 0xac, 32);
  if (feedback != NULL)
    gst_buffer_add_tx_feedback_meta (buffer, 42, GST_TX_FEEDBACK (feedback));

  return gst_pad_push (srcpad, buffer);
}

static guint64
get_send_failures (GstElement * sink)
{
  guint64 failures = 0;

  g_object_get (sink, "send-failures", &failures, NULL);
  return failures;
}

static gboolean
gathering_done_cb (NiceAgent * agent, guint stream_id, gpointer user_data)
{
  (void) agent;
  (void) stream_id;

  *((gboolean *) user_data) = TRUE;
  return TRUE;
}

/* Binds a UDP socket on loopback and returns a remote candidate pointing
 * at it, so that sends from the agent actually succeed. */
static NiceCandidate *
make_loopback_candidate (GSocket ** sock_out)
{
  GSocket *sock;
  GSocketAddress *addr;
  NiceCandidate *candidate;
  GError *error = NULL;
  guint16 port;

  sock = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
      G_SOCKET_PROTOCOL_UDP, &error);
  g_assert_no_error (error);

  addr = g_inet_socket_address_new_from_string ("127.0.0.1", 0);
  g_socket_bind (sock, addr, TRUE, &error);
  g_assert_no_error (error);
  g_object_unref (addr);

  addr = g_socket_get_local_address (sock, &error);
  g_assert_no_error (error);
  port = g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr));
  g_object_unref (addr);

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  candidate->component_id = 1;
  candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;
  g_strlcpy (candidate->foundation, "1", NICE_CANDIDATE_MAX_FOUNDATION);
  nice_address_set_from_string (&candidate->addr, "127.0.0.1");
  nice_address_set_port (&candidate->addr, port);

  *sock_out = sock;
  return candidate;
}

int
main (int argc, char *argv[])
{
  GMainContext *context;
  NiceAgent *agent;
  GstElement *sink;
  GstPad *srcpad;
  GstSegment segment;
  GstClock *clock;
  TestTxFeedback *feedback;
  NiceCandidate *candidate;
  GSocket *sock = NULL;
  GSList *remote = NULL;
  const GstStructure *s;
  gboolean gathering_done = FALSE;
  guint64 dropped_packets = 0;
  guint64 dropped_bytes = 0;
  guint stream_id;
  guint i;
  gint64 deadline;
  gint last_error = 0;

  gst_init (&argc, &argv);

  context = g_main_context_new ();
  agent = nice_agent_new (context, NICE_COMPATIBILITY_RFC5245,
      NICE_COMPATIBILITY_RFC5245);
  {
    NiceAddress baseaddr;

    nice_address_init (&baseaddr);
    g_assert_true (nice_address_set_from_string (&baseaddr, "127.0.0.1"));
    nice_agent_add_local_address (agent, &baseaddr);
  }
  stream_id = nice_agent_add_stream (agent, 1);
  g_assert_cmpuint (stream_id, >, 0);
  nice_agent_set_transport (agent, stream_id, 1, NICE_CANDIDATE_TRANSPORT_UDP);

  sink = g_object_new (GST_TYPE_NICE_SINK, NULL);
  g_object_set (sink, "agent", agent, "stream", stream_id, "component", 1,
      "sync", FALSE, "async", FALSE, NULL);

  srcpad = gst_pad_new ("src", GST_PAD_SRC);
  gst_pad_set_event_function (srcpad, src_event_func);
  g_assert_cmpint (gst_pad_link (srcpad, GST_BASE_SINK_PAD (sink)),
      ==, GST_PAD_LINK_OK);
  gst_pad_set_active (srcpad, TRUE);

  /* The sink is not in a pipeline, so give it a clock explicitly: without
   * one it would never stamp TX-feedback timestamps at all. */
  clock = gst_system_clock_obtain ();
  gst_element_set_clock (sink, clock);

  g_assert_cmpint (gst_element_set_state (sink, GST_STATE_PLAYING), !=,
      GST_STATE_CHANGE_FAILURE);

  gst_pad_push_event (srcpad, gst_event_new_stream_start ("nicesink-test"));
  gst_segment_init (&segment, GST_FORMAT_TIME);
  gst_pad_push_event (srcpad, gst_event_new_segment (&segment));

  feedback = g_object_new (TEST_TYPE_TX_FEEDBACK, NULL);

  /* Phase 1: no selected pair, so every send fails. The flow return must
   * stay GST_FLOW_OK, the failures must be counted, the failure event must
   * be emitted exactly once and no TX feedback may be reported. */
  for (i = 0; i < 10; i++)
    g_assert_cmpint (push_buffer (srcpad, feedback), ==, GST_FLOW_OK);

  g_assert_cmpuint (get_send_failures (sink), ==, 10);
  g_object_get (sink, "last-send-error", &last_error, NULL);
  g_assert_cmpint (last_error, <, 0);
  g_assert_cmpuint (feedback->tx_count, ==, 0);
  g_assert_cmpuint (count_upstream_events ("PexNiceSendFailureStarted"), ==, 1);
  g_assert_cmpuint (count_upstream_events ("PexNiceSendFailureStopped"), ==, 0);

  s = find_upstream_event ("PexNiceSendFailureStarted");
  g_assert_nonnull (s);
  g_assert_true (gst_structure_has_field (s, "stream-id"));
  g_assert_true (gst_structure_has_field (s, "component-id"));
  g_assert_true (gst_structure_has_field (s, "error"));

  /* Opt-in escalation: once enabled and the outage has lasted longer than
   * the configured timeout, render() reports the failure upstream. */
  g_object_set (sink, "error-on-sustained-failure", TRUE,
      "sustained-failure-timeout", 1, NULL);
  g_usleep (5000);
  g_assert_cmpint (push_buffer (srcpad, feedback), ==, GST_FLOW_ERROR);
  g_assert_cmpuint (get_send_failures (sink), ==, 11);
  g_assert_cmpuint (feedback->tx_count, ==, 0);

  /* Back to the default: failures stay non-fatal. */
  g_object_set (sink, "error-on-sustained-failure", FALSE, NULL);
  g_assert_cmpint (push_buffer (srcpad, feedback), ==, GST_FLOW_OK);
  g_assert_cmpuint (get_send_failures (sink), ==, 12);

  /* Phase 2: give the agent a usable pair so that sends succeed again. */
  g_signal_connect (agent, "candidate-gathering-done",
      G_CALLBACK (gathering_done_cb), &gathering_done);
  nice_agent_gather_candidates (agent, stream_id);

  deadline = g_get_monotonic_time () + 10 * G_USEC_PER_SEC;
  while (!gathering_done && g_get_monotonic_time () < deadline)
    g_main_context_iteration (context, FALSE);
  g_assert_true (gathering_done);

  candidate = make_loopback_candidate (&sock);
  candidate->stream_id = stream_id;
  remote = g_slist_append (remote, candidate);
  g_assert_cmpint (nice_agent_set_remote_candidates (agent, stream_id, 1,
          remote), >, 0);
  g_assert_true (nice_agent_set_selected_remote_candidate (agent, stream_id, 1,
          candidate));

  clear_upstream_events ();

  g_assert_cmpint (push_buffer (srcpad, feedback), ==, GST_FLOW_OK);

  /* Recovery: the outage is reported once, with the accurate counts, and
   * TX feedback is stamped again now that the buffer really was sent. */
  g_assert_cmpuint (feedback->tx_count, ==, 1);
  g_assert_cmpuint (get_send_failures (sink), ==, 12);
  g_assert_cmpuint (count_upstream_events ("PexNiceSendFailureStopped"), ==, 1);
  g_assert_cmpuint (count_upstream_events ("PexNiceSendFailureStarted"), ==, 0);

  s = find_upstream_event ("PexNiceSendFailureStopped");
  g_assert_nonnull (s);
  g_assert_true (gst_structure_get_uint64 (s, "dropped-packets",
          &dropped_packets));
  g_assert_cmpuint (dropped_packets, ==, 12);
  g_assert_true (gst_structure_get_uint64 (s, "dropped-bytes", &dropped_bytes));
  g_assert_cmpuint (dropped_bytes, ==, 12 * 32);
  g_assert_true (gst_structure_has_field (s, "duration-ms"));

  /* A further successful send must not re-report anything. */
  clear_upstream_events ();
  g_assert_cmpint (push_buffer (srcpad, feedback), ==, GST_FLOW_OK);
  g_assert_cmpuint (feedback->tx_count, ==, 2);
  g_assert_cmpuint (count_upstream_events ("PexNiceSendFailureStopped"), ==, 0);
  g_assert_cmpuint (get_send_failures (sink), ==, 12);

  gst_element_set_state (sink, GST_STATE_NULL);
  gst_pad_set_active (srcpad, FALSE);

  clear_upstream_events ();
  g_object_unref (feedback);
  gst_object_unref (clock);
  gst_object_unref (srcpad);
  gst_object_unref (sink);
  g_slist_free_full (remote, (GDestroyNotify) nice_candidate_free);
  g_object_unref (sock);
  g_object_unref (agent);
  g_main_context_unref (context);

  return 0;
}
