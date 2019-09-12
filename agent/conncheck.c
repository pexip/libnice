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
 *   Kai Vehmanen, Nokia
 *   Youness Alaoui, Collabora Ltd.
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

/*
 * @file conncheck.c
 * @brief ICE connectivity checks
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <string.h>

#include <glib.h>
#include <gst/gst.h>

#include "debug.h"

#include "agent.h"
#include "agent-priv.h"
#include "conncheck.h"
#include "discovery.h"
#include "stun/usages/ice.h"
#include "stun/usages/bind.h"
#include "stun/usages/turn.h"
#include "stun/utils.h"

GST_DEBUG_CATEGORY_EXTERN (niceagent_debug);
#define GST_CAT_DEFAULT niceagent_debug

static const char* priv_state_to_string(NiceCheckState state);
static void priv_update_check_list_failed_components (NiceAgent *agent, Stream *stream);
static void priv_update_check_list_state_for_ready (NiceAgent *agent, Stream *stream, Component *component);
static guint priv_prune_pending_checks (NiceAgent *agent, Stream *stream, guint component_id);
static gboolean priv_schedule_triggered_check (NiceAgent *agent, Stream *stream, Component *component, NiceSocket *local_socket, NiceCandidate *remote_cand, gboolean use_candidate);
static void priv_mark_pair_nominated (NiceAgent *agent, Stream *stream, Component *component, NiceSocket *local_socket, NiceCandidate *remotecand);
static size_t priv_create_username (NiceAgent *agent, Stream *stream,
                                    guint component_id, NiceCandidate *remote, NiceCandidate *local,
                                    uint8_t *dest, guint dest_len, gboolean inbound);
static size_t priv_get_password (NiceAgent *agent, Stream *stream,
                                 NiceCandidate *remote, uint8_t **password);

static const char* priv_state_to_string(NiceCheckState state)
{
  switch (state) {
  case NICE_CHECK_WAITING: return "WAITING";
  case NICE_CHECK_IN_PROGRESS: return "IN_PROGRESS";
  case NICE_CHECK_SUCCEEDED: return "SUCCEEDED";
  case NICE_CHECK_FAILED: return "FAILED";
  case NICE_CHECK_FROZEN: return "FROZEN";
  case NICE_CHECK_CANCELLED: return "CANCELLED";
  }
  return "(invalid)";
}

static void priv_print_check_pair (NiceAgent* agent, Stream* stream, CandidateCheckPair* p)
{
  gchar* lcand_str;
  gchar* rcand_str;
  gchar  addr_str[NICE_ADDRESS_STRING_LEN];

  nice_address_to_string (&p->local->addr, addr_str);
  lcand_str = g_strdup_printf ("%s %s:%u/%s", candidate_type_to_string (p->local->type),
      addr_str, nice_address_get_port (&p->local->addr),
      candidate_transport_to_string (p->local->transport));

  nice_address_to_string (&p->remote->addr, addr_str);
  rcand_str = g_strdup_printf ("%s %s:%u/%s", candidate_type_to_string (p->remote->type),
      addr_str, nice_address_get_port (&p->remote->addr),
      candidate_transport_to_string (p->remote->transport));

  GST_DEBUG_OBJECT (agent, "%u/%u:   %s %s -> %s %s nom=%s",
      stream->id, p->component_id,
      p->foundation,
      lcand_str, rcand_str,
      priv_state_to_string (p->state),
      p->nominated ? "YES" : "NO");

  g_free (lcand_str);
  g_free (rcand_str);
}

static void priv_print_check_list (NiceAgent* agent, Stream* stream, GSList* list, const char *name)
{
  GSList *i;

  GST_DEBUG_OBJECT (agent, "%u/*: %s:", stream->id, name);
  if (list) {
    for (i = list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      priv_print_check_pair (agent, stream, p);
    }
  } else {
    GST_DEBUG_OBJECT (agent, "%u/*:   *empty*", stream->id);
  }
}

static void priv_print_stream_diagnostics (NiceAgent* agent, Stream* stream)
{
  guint state_count[NICE_CHECK_STATE_LAST + 1];
  GSList *i;

  memset (state_count, 0, sizeof(state_count));

  /*
   * Stream summary
   */
  for (i = stream->conncheck_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;

    g_assert (p->state < sizeof(state_count)/sizeof(state_count[0]));
    state_count[p->state]++;
  }

  GST_DEBUG_OBJECT (agent, "%u/*: timer tick #%u: %u checks (frozen:%u, in-progress:%u, "
      "waiting:%u, succeeded:%u, "
      "failed:%u, cancelled:%u)",
      stream->id, stream->tick_counter,
      g_slist_length(stream->conncheck_list),
      state_count[NICE_CHECK_FROZEN], state_count[NICE_CHECK_IN_PROGRESS],
      state_count[NICE_CHECK_WAITING], state_count[NICE_CHECK_SUCCEEDED],
      state_count[NICE_CHECK_FAILED], state_count[NICE_CHECK_CANCELLED]);

  priv_print_check_list (agent, stream, stream->conncheck_list, "Check list");
  priv_print_check_list (agent, stream, stream->valid_list, "Valid list");
}

static int priv_timer_expired (GTimeVal *timer, GTimeVal *now)
{
  return (now->tv_sec == timer->tv_sec) ?
    now->tv_usec >= timer->tv_usec :
    now->tv_sec >= timer->tv_sec;
}

static void priv_set_pair_state (NiceAgent* agent, CandidateCheckPair* pair, NiceCheckState new_state)
{
  if (new_state == NICE_CHECK_SUCCEEDED && pair->valid_pair == NULL) {
    /*
     * This condition can occur if two check pairs with different local addresses generate the same
     * valid pair (e.g. a misbehaving NAT is assigning the same peer reflexive address to different local
     * addresses). The pair that has already generated the valid pair will be in state succeeded so we can
     * ignore this pair*/
    GST_DEBUG_OBJECT (agent, "%u/%u: pair %p(%s) cannot change state %s -> %s as no valid pair generated",
        pair->stream_id, pair->component_id,
        pair, pair->foundation,
        priv_state_to_string(pair->state), priv_state_to_string (new_state));
  } else {
    GST_DEBUG_OBJECT (agent, "%u/%u: pair %p(%s) change state %s -> %s",
        pair->stream_id, pair->component_id,
        pair, pair->foundation,
        priv_state_to_string(pair->state), priv_state_to_string (new_state));
    pair->state = new_state;
  }
}

static CandidateCheckPair* priv_alloc_check_pair (NiceAgent* agent, Stream* stream)
{
  CandidateCheckPair *pair = g_slice_new0 (CandidateCheckPair);

  stream->conncheck_heap = g_slist_prepend (stream->conncheck_heap, pair);

  return pair;
}

/*
 * Convert TURN lifetime into a refresh interval IN MILLISECONDS. Refresh 30 seconds before
 * expiry, turn message parsing has already checked against a minimum supported lifetime of
 * 60 seconds
 */
static uint32_t priv_turn_lifetime_to_refresh_interval(uint32_t lifetime)
{
  return (lifetime - 30) * 1000;
}

/*
 * For debug check that the connectivity check list is always sorted correctly
 */
static gboolean priv_conn_check_list_is_ordered (GSList *conn_check_list)
{
  if (conn_check_list) {
    GSList *i;
    CandidateCheckPair* prev = NULL;

    for (i = conn_check_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;
      if (!prev) {
        prev = p;
      } else {
        if (prev->priority < p->priority) {
          return FALSE;
        } else {
          prev = p;
        }
      }
    }
  }

  return TRUE;
}

/*
 * Finds the next connectivity check in WAITING state
 */
static CandidateCheckPair *priv_conn_check_find_next_waiting (GSList *conn_check_list)
{
  GSList *i;

  /*
   * List is sorted in priority order to first waiting check has
   * the highest priority
   */
  g_assert (priv_conn_check_list_is_ordered (conn_check_list));

  for (i = conn_check_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->state == NICE_CHECK_WAITING)
      return p;
  }

  return NULL;
}

/*
 * Returns TRUE if all pairs on the streams checklist are in state frozen
 */
static gboolean priv_check_list_is_frozen (NiceAgent* agent, Stream* stream)
{
  GSList* i;

  for (i = stream->conncheck_list; i; i = g_slist_next(i)) {
    CandidateCheckPair* pair = i->data;

    g_assert (pair->stream_id == stream->id);

    if (pair->state != NICE_CHECK_FROZEN) {
      return FALSE;
    }
  }
  return TRUE;
}

/*
 * Initiates a new connectivity check for a ICE candidate pair.
 *
 * @return TRUE on success, FALSE on error
 */
static gboolean priv_conn_check_initiate (NiceAgent *agent, CandidateCheckPair *pair)
{
  /* XXX: from ID-16 onwards, the checks should not be sent
   * immediately, but be put into the "triggered queue",
   * see  "7.2.1.4 Triggered Checks"
   */
  g_get_current_time (&pair->next_tick);
  g_time_val_add (&pair->next_tick, agent->timer_ta * 1000);
  priv_set_pair_state (agent, pair, NICE_CHECK_IN_PROGRESS);
  conn_check_send (agent, pair);
  return TRUE;
}

/*
 * Implements the unfreezing of a stream as described in RFC 5245 section
 * 5.7.4
 *
 * "For all pairs with the same foundation, it sets the state of
 *  the pair with the lowest component ID to Waiting.  If there is
 *  more than one such pair, the one with the highest priority is
 *  used."
 *
 * (and also sect 7.1.3.2.3 (Updating Pair States))
 * "If the check list is frozen, and there are no pairs in the
 *  check list whose foundation matches a pair in the valid list
 *  under consideration, the agent
 *
 *  +  groups together all of the pairs with the same foundation,
 *  and
 *
 *  +  for each group, sets the state of the pair with the lowest
 *  component ID to Waiting.  If there is more than one such
 *  pair, the one with the highest priority is used."
 */
static void priv_conn_check_unfreeze_stream (NiceAgent *agent, Stream* stream)
{
  GSList *j;
  GHashTable *foundation_map = NULL;
  GHashTableIter iter;
  gpointer key, value;

  /*
   * Check invariants
   */
  g_assert (priv_check_list_is_frozen (agent, stream));
  g_assert (priv_conn_check_list_is_ordered (stream->conncheck_list));
  g_assert (priv_conn_check_list_is_ordered (stream->valid_list));

  /*
   * Build up a map of pair foundation -> list of pairs
   */
  foundation_map = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL); // TODO: sort out destroy functions

  for (j = stream->conncheck_list; j ; j = j->next) {
    CandidateCheckPair *p = j->data;
    CandidateCheckPair *existing_pair = g_hash_table_lookup (foundation_map, p->foundation);

    if (existing_pair) {
      /*
       * This foundation has already been seen. Since the conncheck_list is sorted from
       * highest to lowest priority then we know that this pair must be lower priority than
       * this existing_pair. Given that we will only replace the existing pair if we
       * have a lower component id
       */
      if (p->component_id < existing_pair->component_id) {
        g_hash_table_insert (foundation_map, p->foundation, p);
      }
    } else {
      /*
       * This foundation has not been seen before this must be the highest priority
       */
      g_hash_table_insert (foundation_map, p->foundation, p);
    }
  }

  /*
   * foundation_map now contains the highest priority pair for the first component
   * of each unique foundation. Unfreeze them all
   */
  g_hash_table_iter_init (&iter, foundation_map);
  while (g_hash_table_iter_next (&iter, &key, &value)) {
    CandidateCheckPair *pair = value;

    GST_DEBUG_OBJECT (agent, "%u/%u: Pair %p(%s) unfrozen.",
        pair->stream_id, pair->component_id, pair, pair->foundation);
    priv_set_pair_state(agent, pair, NICE_CHECK_WAITING);
  }

  g_hash_table_destroy (foundation_map);
}

/*
 * JBFIXME: Is this still required now that we have priv_conn_check_unfreeze_stream which implements RFC 5245?
 *
 * Unfreezes the next connectivity check in the list. Follows the
 * algorithm (2.) defined in 5.7.4 (Computing States) of the ICE spec
 * (ID-19), with some exceptions (see comments in code).
 *
 * See also sect 7.1.2.2.3 (Updating Pair States), and
 * priv_conn_check_unfreeze_related().
 *
 * @return TRUE on success, and FALSE if no frozen candidates were found.
 */
static gboolean priv_conn_check_unfreeze_next (NiceAgent *agent)
{
  CandidateCheckPair *pair = NULL;
  GSList *i, *j;

  /* XXX: the unfreezing is implemented a bit differently than in the
   *      current ICE spec, but should still be interoperate:
   *   - checks are not grouped by foundation
   *   - one frozen check is unfrozen (lowest component-id, highest
   *     priority)
   */

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;

    /* Check invariants */
    g_assert (priv_conn_check_list_is_ordered (stream->conncheck_list));
    g_assert (priv_conn_check_list_is_ordered (stream->valid_list));

    for (j = stream->conncheck_list; j ; j = j->next) {
      CandidateCheckPair *p = j->data;

      if (p->state == NICE_CHECK_FROZEN) {
        pair = p;
        break;
      }
    }

    if (pair)
      break;
  }

  if (pair) {
    GST_DEBUG_OBJECT (agent, "%u/%u: Pair %p(%s) unfrozen.",
        pair->stream_id, pair->component_id, pair, pair->foundation);
    priv_set_pair_state(agent, pair, NICE_CHECK_WAITING);
    return TRUE;
  }

  return FALSE;
}

/*
 * Returns TRUE if all components of the given stream have at least one entry on the
 * valid list. Used as part of the unfreeze_related algorithm to determine if this
 * stream is "complete" before we start unfreezing checks in other streams.
 */
static gboolean priv_all_components_have_valid_pair (NiceAgent* agent, Stream* stream)
{
  GSList *i;
  gboolean *component_valid = NULL;
  gboolean result = TRUE;
  guint j;

  component_valid = g_new0(gboolean, stream->n_components);

  for (i = stream->valid_list; i; i = i->next) {
    CandidateCheckPair *pair = i->data;

    g_assert (pair->component_id != 0);
    g_assert (pair->component_id - 1 < stream->n_components);
    component_valid [pair->component_id - 1] = TRUE;
  }

  for (j = 0; j < stream->n_components; j++) {
    if (!component_valid [j]) {
      result = FALSE;
    }
  }

  g_free (component_valid);
  return result;
}

/*
 * Helper function for implementing section 7.1.3.2.3 (Updating pair states)
 *
 * Go through the check list for the stream and unfreeze any pairs whose foundation
 * matches a pair on the supplied valid list (which may be from a different stream)
 *
 * Returns the number of pairs that are unfrozen.
 */
static guint priv_unfreeze_checks_for_valid_pairs (NiceAgent* agent, Stream* stream, GSList* valid_list)
{
  guint unfrozen = 0;
  GSList *i;
  GSList *j;

  for (i = stream->conncheck_list; i; i = g_slist_next (i)) {
    CandidateCheckPair *p = i->data;

    /*
     * Compare the foundation with every pair on the valid list
     */
    for (j = valid_list; j; j = g_slist_next (j)) {
      CandidateCheckPair *valid_pair = j->data;

      if (p->state == NICE_CHECK_FROZEN &&
          strcmp (p->foundation, valid_pair->foundation) == 0) {
        GST_DEBUG_OBJECT (agent, "%u/%u: Unfreezing other stream check %p(%s) (after successful check %p(%s)).",
            p->stream_id, p->component_id,
            p, p->foundation,
            valid_pair, valid_pair->foundation);
        priv_set_pair_state (agent, p, NICE_CHECK_WAITING);
        unfrozen++;
      }
    }
  }

  return unfrozen;
}

/*
 * Unfreezes all "related" connectivity check in the list after
 * check 'ok_check' has successfully completed.
 *
 * See sect 7.1.3.2.3 (Updating Pair States) of RFC 5245
 *
 */
static void priv_conn_check_unfreeze_related (NiceAgent *agent, Stream *stream, CandidateCheckPair *ok_check)
{
  GSList *i;

  if (ok_check->state == NICE_CHECK_SUCCEEDED) {
    g_assert (stream);
    g_assert (stream->id == ok_check->stream_id);

    /* step: perform the step (1) of 'Updating Pair States' */
    g_assert (priv_conn_check_list_is_ordered (stream->conncheck_list));
    g_assert (priv_conn_check_list_is_ordered (stream->valid_list));

    for (i = stream->conncheck_list; i ; i = i->next) {
      CandidateCheckPair *p = i->data;

      if (p->stream_id == ok_check->stream_id) {
        if (p->state == NICE_CHECK_FROZEN &&
            strcmp (p->foundation, ok_check->foundation) == 0) {
          GST_DEBUG_OBJECT (agent, "%u/%u: Unfreezing check %p(%s) (after successful check %p(%s)).",
              p->stream_id, p->component_id,
              p, p->foundation,
              ok_check, ok_check->foundation);
          priv_set_pair_state (agent, p, NICE_CHECK_WAITING);
        }
      }
    }

    /*
     * Section 7.1.3.2.3 Updating Pair States part 2
     * 2.  If there is a pair in the valid list for every component of this
     *    media stream (where this is the actual number of components being
     *    used, in cases where the number of components signaled in the SDP
     *    differs from offerer to answerer), the success of this check may
     *    unfreeze checks for other media streams.  Note that this step is
     *    followed not just the first time the valid list under
     *    consideration has a pair for every component, but every
     *    subsequent time a check succeeds and adds yet another pair to
     *    that valid list.  The agent examines the check list for each
     *    other media stream in turn:
     *    ...
     */
    if (priv_all_components_have_valid_pair (agent, stream)) {

      for (i = agent->streams; i ; i = i->next) {
        Stream *s = i->data;

        if (s != stream) {
          g_assert (priv_conn_check_list_is_ordered (s->conncheck_list));
          g_assert (priv_conn_check_list_is_ordered (s->valid_list));

          if ( !priv_check_list_is_frozen (agent, s)) {
            /*
             * "If the check list is active, the agent changes the state of
             * all Frozen pairs in that check list whose foundation matches a
             * pair in the valid list under consideration to Waiting."
             *
             */
            priv_unfreeze_checks_for_valid_pairs (agent, s, s->valid_list);
          } else {
            /*
             * "If the check list is frozen, and there is at least one pair in
             * the check list whose foundation matches a pair in the valid
             * list under consideration, the state of all pairs in the check
             * list whose foundation matches a pair in the valid list under
             * consideration is set to Waiting.  This will cause the check
             * list to become active, and ordinary checks will begin for it,
             * as described in Section 5.8."
             *
             */
            guint unfrozen = priv_unfreeze_checks_for_valid_pairs (agent, s, s->valid_list);

            if (unfrozen == 0) {
              /*
               * If the check list is frozen, and there are no pairs in the
               * check list whose foundation matches a pair in the valid list
               * under consideration, the agent
               *
               *  + groups together all of the pairs with the same foundation,
               *
               *  and
               *
               *  + for each group, sets the state of the pair with the lowest
               *    component ID to Waiting.  If there is more than one such
               *    pair, the one with the highest priority is used.
               */
              priv_conn_check_unfreeze_stream (agent, s);
            }
          }
        }
      }
    }
  }
}

static void priv_tick_in_progress_check (NiceAgent* agent, Stream* stream, CandidateCheckPair* p, GTimeVal *now)
{
  if (p->stun_message.buffer == NULL) {
    GST_DEBUG_OBJECT (agent, "%u/%u: STUN connectivity check was cancelled for pair %p(%s), marking as done.",
        p->stream_id, p->component_id,
        p, p->foundation);
    priv_set_pair_state (agent, p, NICE_CHECK_FAILED);
  } else if (priv_timer_expired (&p->next_tick, now)) {
    switch (stun_timer_refresh (&p->timer)) {
    case STUN_USAGE_TIMER_RETURN_TIMEOUT:
      {
        /* case: error, abort processing */
        StunTransactionId id;
        GST_DEBUG_OBJECT (agent, "%u/%u: Retransmissions failed, giving up on connectivity check %p(%s)",
            p->stream_id, p->component_id,
            p, p->foundation);
        priv_set_pair_state (agent, p, NICE_CHECK_FAILED);

        stun_message_id (&p->stun_message, id);
        stun_agent_forget_transaction (&agent->stun_agent, id);

        p->stun_message.buffer = NULL;
        p->stun_message.buffer_len = 0;
        break;
      }
    case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
      {
        /* case: not ready, so schedule a new timeout */
        unsigned int timeout = stun_timer_remainder (&p->timer);
        GST_DEBUG_OBJECT (agent, "%u/%u:STUN transaction retransmitted (timeout %dms) for pair %p(%s)",
            p->stream_id, p->component_id,
            timeout,
            p, p->foundation);

        nice_socket_send (p->local->sockptr, &p->remote->addr,
                          stun_message_length (&p->stun_message),
                          (gchar *)p->stun_buffer);

        /* note: convert from milli to microseconds for g_time_val_add() */
        p->next_tick = *now;
        g_time_val_add (&p->next_tick, timeout * 1000);
        break;
      }
    case STUN_USAGE_TIMER_RETURN_SUCCESS:
      {
        unsigned int timeout = stun_timer_remainder (&p->timer);
        /* note: convert from milli to microseconds for g_time_val_add() */
        p->next_tick = *now;
        g_time_val_add (&p->next_tick, timeout * 1000);
        break;
      }
    }
  }
}

static gboolean is_microsoft_tcp_pair (NiceAgent *agent, CandidateCheckPair *p)
{
  return (agent->compatibility == NICE_COMPATIBILITY_OC2007R2) &&
    (p->local->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE ||
     p->local->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE);

}

static CandidateCheckPair* priv_find_pair_with_matching_foundation (NiceAgent* agent, Stream* stream, CandidateCheckPair* p, guint component_id)
{
  (void)agent;
  GSList* i;

  for (i = stream->conncheck_list; i; i = g_slist_next (i)) {
    CandidateCheckPair *p1 = i->data;
    if ( p1->component_id == component_id &&
         strcmp (p->foundation, p1->foundation) == 0 ) {
      return p1;
    }
  }
  return NULL;
}

static gboolean priv_stream_needs_rtcp_pair (NiceAgent * agent, Stream *stream, CandidateCheckPair* rtp_pair)
{
  Component *component;

  if (rtp_pair && is_microsoft_tcp_pair (agent, rtp_pair))
    return FALSE;

  if (stream->n_components < 2)
    return FALSE;

  if (!agent_find_component (agent, stream->id, NICE_COMPONENT_TYPE_RTCP, NULL, &component))
    return FALSE;

  if (stream->rtcp_mux)
    return FALSE;

  return TRUE;
}

static gboolean priv_attempt_to_nominate_pair (NiceAgent *agent, Stream *stream, CandidateCheckPair* rtp_pair)
{
  if (rtp_pair->component_id == NICE_COMPONENT_TYPE_RTP && rtp_pair->state == NICE_CHECK_SUCCEEDED) {

    if (!priv_stream_needs_rtcp_pair (agent, stream, rtp_pair)) {
      /*
       *  For Microsoft TCP streams we may not have an RTCP pair (as rtcp-mux will always be enabled). In this
       *  case just go ahead and nominate the RTP pair
       */
      rtp_pair->nominated = TRUE;
      GST_DEBUG_OBJECT (agent, "%u/*: Microsoft TCP pair, nominating without RTCP",
          stream->id);
      priv_print_check_pair (agent, stream, rtp_pair);
      priv_conn_check_initiate (agent, rtp_pair);
      return TRUE;

    } else {
      CandidateCheckPair *rtcp_pair = priv_find_pair_with_matching_foundation(agent, stream, rtp_pair, NICE_COMPONENT_TYPE_RTCP);

      if (rtcp_pair != NULL && rtcp_pair->state == NICE_CHECK_SUCCEEDED) {
        rtp_pair->nominated = TRUE;
        rtcp_pair->nominated = TRUE;
        GST_DEBUG_OBJECT (agent, "%u/*: Have matching RTP & RTCP succeeded pairs, nominating...", stream->id);
        priv_print_check_pair (agent, stream, rtp_pair);
        priv_print_check_pair (agent, stream, rtcp_pair);
        priv_conn_check_initiate (agent, rtp_pair);
        priv_conn_check_initiate (agent, rtcp_pair);
        return TRUE;
      }

    }
  }
  return FALSE;
}

static void priv_nominate_any_successful_pair (NiceAgent *agent, Stream *stream)
{
  /*
   * Find the higher priority succeeded pair for RTP that has a matching succeeded pair for
   * RTCP (or doesn't need one e.g. TCP pairs in Microsoft mode
   */
  GSList* i;

  for (i = stream->conncheck_list; i; i = g_slist_next (i)) {
    CandidateCheckPair *rtp_pair = i->data;
    if (priv_attempt_to_nominate_pair (agent, stream, rtp_pair)) {
      break;
    }
  }
}

static void priv_nominate_highest_priority_successful_pair (NiceAgent* agent, Stream *stream)
{
  GSList* i = stream->conncheck_list;
  GSList* j = NULL;

  for (i = stream->conncheck_list; i; i = g_slist_next (i)) {
    CandidateCheckPair *rtp_pair = stream->conncheck_list->data;
    if (rtp_pair->component_id == NICE_COMPONENT_TYPE_RTP) {
      if (!priv_attempt_to_nominate_pair (agent, stream, rtp_pair) &&
          rtp_pair->local->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE) {
        /*
         * if the highest priority is TCP active and we have a TCP passive with the same
         * local and remote candidate types that has succeeded then use that instead (as the media
         * path generated is the same)
         */
        GST_DEBUG_OBJECT (agent, "%u/*: Regular nomination, highest priority is TCP active...",
            stream->id);
        priv_print_check_pair (agent, stream, rtp_pair);

        for(j = g_slist_next(i); j; j = g_slist_next(j)) {
          CandidateCheckPair *p = j->data;

          if (p->component_id == rtp_pair->component_id &&
              p->local->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE &&
              p->local->type == rtp_pair->local->type &&
              p->remote->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
            GST_DEBUG_OBJECT (agent, "%u/*: Regular nomination, highest priority is TCP active, attempting to nominate highest priority TCP passive",
                stream->id);
            priv_print_check_pair (agent, stream, p);
            priv_attempt_to_nominate_pair (agent, stream, p);
            break;
          }
        }
      }
      break;
    }
  }
}

static gboolean priv_check_for_regular_nomination (NiceAgent* agent, Stream *stream, GTimeVal *now)
{
  guint   succeeded = 0, nominated = 0;
  GSList  *i;

  if (!agent->controlling_mode || agent->aggressive_mode) {
    return FALSE;
  }

  /*
   * Get counts of succedded and nominated pairs on the valid list for the first component
   */
  for (i = stream->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == NICE_COMPONENT_TYPE_RTP &&
        p->state == NICE_CHECK_SUCCEEDED) {
      ++succeeded;
      if (p->nominated == TRUE) {
        ++nominated;
      }
    }
  }

  if (nominated > 0) {
    /* We've already nominated pairs, nothing to do */
    GST_DEBUG_OBJECT (agent, "%u/*: Checking for regular nomination, already nominated (succeeded=%u nominated=%u)",
        stream->id, succeeded, nominated);
    return FALSE;
  }

  if (succeeded == 0) {
    /* Can't nominate if nothing succeeded */
    GST_DEBUG_OBJECT (agent, "%u/*: Checking for regular nomination, nothing succeeded (succeeded=%u nominated=%u)",
        stream->id, succeeded, nominated);
    return FALSE;
  }

  if (stream->tick_counter * agent->timer_ta > agent->regular_nomination_timeout) {
    GST_DEBUG_OBJECT (agent, "%u/*: Checking for regular nomination succeeded=%u nominated=%u",
        stream->id, succeeded, nominated);
    priv_nominate_any_successful_pair (agent, stream);
  } else {
    /* Only nominate if the highest priority pair has succeeded */
    GST_DEBUG_OBJECT (agent, "%u/*: Checking if highest priority pair has succeeded succeeded=%u nominated=%u",
        stream->id, succeeded, nominated);
    priv_nominate_highest_priority_successful_pair (agent, stream);
  }

  return TRUE;
}

/*
 * Helper function for connectivity check timer callback that
 * runs through the stream specific part of the state machine.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_conn_check_tick_stream (Stream *stream, NiceAgent *agent, GTimeVal *now)
{
  gboolean keep_timer_going = FALSE;
  GSList *i;

  keep_timer_going = priv_check_for_regular_nomination(agent, stream, now);

  for (i = stream->conncheck_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;

    /*
     * Tick any in-progress checks first as this could cause them to
     * change state (timeout etc)
     */
    if (p->state == NICE_CHECK_IN_PROGRESS) {
      priv_tick_in_progress_check (agent, stream, p, now);
    }

    /*
     * Keep the timer going as long as there is work to be done
     */
    if (p->state == NICE_CHECK_IN_PROGRESS ||
        p->state == NICE_CHECK_FROZEN ||
        p->state == NICE_CHECK_WAITING) {
      keep_timer_going = TRUE;
    }
  }

  if (stream->tick_counter++ % 50 == 0) {
    priv_print_stream_diagnostics (agent, stream);
    GST_DEBUG_OBJECT (agent, "%u/*: %s keep_timer_going = %u",
        stream->id, G_STRFUNC, keep_timer_going);
  }

  return keep_timer_going;
}


/*
 * Timer callback that handles initiating and managing connectivity
 * checks (paced by the Ta timer).
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_conn_check_tick_unlocked (gpointer pointer)
{
  CandidateCheckPair *pair = NULL;
  NiceAgent *agent = pointer;
  gboolean keep_timer_going = FALSE;
  GSList *i, *j;
  GTimeVal now;

  /* step: process ongoing STUN transactions */
  g_get_current_time (&now);

  /* step: find the highest priority waiting check and send it */
  for (i = agent->streams; i ; i = i->next) {
    Stream *stream = i->data;

    pair = priv_conn_check_find_next_waiting (stream->conncheck_list);
    if (pair)
      break;
  }

  if (pair) {
    priv_conn_check_initiate (agent, pair);
    keep_timer_going = TRUE;
  } else {
    keep_timer_going = priv_conn_check_unfreeze_next (agent);
  }

  for (j = agent->streams; j; j = j->next) {
    Stream *stream = j->data;
    gboolean res =
      priv_conn_check_tick_stream (stream, agent, &now);
    if (res)
      keep_timer_going = res;
  }

  /* step: stop timer if no work left */
  if (keep_timer_going != TRUE) {
    for (i = agent->streams; i; i = i->next) {
      Stream *stream = i->data;
      priv_update_check_list_failed_components (agent, stream);
      for (j = stream->components; j; j = j->next) {
        Component *component = j->data;
        priv_update_check_list_state_for_ready (agent, stream, component);
      }
    }

    /* Stopping the timer so destroy the source.. this will allow
       the timer to be reset if we get a set_remote_candidates after this
       point */
    if (agent->conncheck_timer_source != NULL) {
      g_source_destroy (agent->conncheck_timer_source);
      g_source_unref (agent->conncheck_timer_source);
      agent->conncheck_timer_source = NULL;
    }

    /* XXX: what to signal, is all processing now really done? */
  }

  return keep_timer_going;
}

static gboolean priv_conn_check_tick (gpointer pointer)
{
  NiceAgent *agent = pointer;
  gboolean ret;

  agent_lock (agent);
  if (g_source_is_destroyed (g_main_current_source ())) {
    agent_unlock (agent);
    return FALSE;
  }
  ret = priv_conn_check_tick_unlocked (pointer);
  agent_unlock (agent);

  return ret;
}

/*
 * Timer callback that handles initiating and managing connectivity
 * checks (paced by the Ta timer).
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_conn_keepalive_tick_unlocked (NiceAgent *agent)
{
  GSList *i, *j, *k;
  int errors = 0;
  gboolean ret = FALSE;
  size_t buf_len = 0;

  /* case 1: session established and media flowing
   *         (ref ICE sect 10 "Keepalives" ID-19)  */
  for (i = agent->streams; i; i = i->next) {

    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *component = j->data;
      if (component->selected_pair.local != NULL) {
        CandidatePair *p = &component->selected_pair;

        buf_len = stun_usage_bind_keepalive (&agent->stun_agent,
                                             &p->keepalive.stun_message, p->keepalive.stun_buffer,
                                             sizeof(p->keepalive.stun_buffer));

        if (buf_len > 0) {
          nice_socket_send (p->local->sockptr, &p->remote->addr, buf_len,
                            (gchar *)p->keepalive.stun_buffer);

          GST_DEBUG_OBJECT (agent, "%u/%u: stun_bind_keepalive for pair %p(%s:%s) res %d.",
              stream->id, component->id, p, p->local->foundation, p->remote->foundation, (int) buf_len);
        } else {
          ++errors;
        }
      }
    }
  }

  /* case 2: connectivity establishment ongoing
   *         (ref ICE sect 4.1.1.4 "Keeping Candidates Alive" ID-19)  */
  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *component = j->data;
      gchar *stun_server_ip = NULL;
      guint stun_server_port;

      if (component->stun_server_ip != NULL) {
        stun_server_ip = component->stun_server_ip;
        stun_server_port = component->stun_server_port;
      } else {
        stun_server_ip = agent->stun_server_ip;
        stun_server_port = agent->stun_server_port;
      }

      if (component->id == NICE_COMPONENT_TYPE_RTCP && !priv_stream_needs_rtcp_pair (agent, stream, NULL)) {
        GST_DEBUG_OBJECT (agent, "%u/%u: Not sending STUN keepalive as rtcp-mux in use", stream->id, component->id);
        continue;
      }

      if (component->state < NICE_COMPONENT_STATE_READY &&
          stun_server_ip) {
        NiceAddress stun_server;
        if (nice_address_set_from_string (&stun_server, stun_server_ip)) {
          StunAgent stun_agent;
          uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE];
          StunMessage stun_message;
          size_t buffer_len = 0;

          nice_address_set_port (&stun_server, stun_server_port);

          stun_agent_init (&stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
                           STUN_COMPATIBILITY_RFC5389,
                           (agent->turn_compatibility == NICE_COMPATIBILITY_OC2007R2 ?
                            STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES : 0));

          buffer_len = stun_usage_bind_create (&stun_agent,
                                               &stun_message, stun_buffer, sizeof(stun_buffer));

          for (k = component->local_candidates; k; k = k->next) {
            NiceCandidate *candidate = (NiceCandidate *) k->data;
            if (candidate->type == NICE_CANDIDATE_TYPE_HOST && candidate->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
              /* send the conncheck */
              GST_DEBUG_OBJECT (agent, "%u/%u: resending STUN on %s to keep the candidate alive.",
                  candidate->stream_id, candidate->component_id,
                  candidate->foundation);
              nice_socket_send (candidate->sockptr, &stun_server,
                                buffer_len, (gchar *)stun_buffer);
            }
          }
        }
      }
    }
  }

  if (errors) {
    GST_DEBUG_OBJECT (agent, "stopping keepalive timer");
    goto done;
  }

  ret = TRUE;

 done:
  return ret;
}

static gboolean priv_conn_keepalive_tick (gpointer pointer)
{
  NiceAgent *agent = pointer;
  gboolean ret;

  agent_lock (agent);
  if (g_source_is_destroyed (g_main_current_source ())) {
    agent_unlock (agent);
    return FALSE;
  }

  ret = priv_conn_keepalive_tick_unlocked (agent);
  if (ret == FALSE) {
    if (agent->keepalive_timer_source) {
      g_source_destroy (agent->keepalive_timer_source);
      g_source_unref (agent->keepalive_timer_source);
      agent->keepalive_timer_source = NULL;
    }
  }
  agent_unlock (agent);
  return ret;
}


static gboolean priv_turn_allocate_refresh_retransmissions_tick (gpointer pointer)
{
  CandidateRefresh *cand = (CandidateRefresh *) pointer;
  NiceAgent *agent = cand->agent;

  agent_lock (agent);

  /* A race condition might happen where the mutex above waits for the lock
   * and in the meantime another thread destroys the source.
   * In that case, we don't need to run our retransmission tick since it should
   * have been cancelled */
  if (g_source_is_destroyed (g_main_current_source ())) {
    agent_unlock (agent);
    return FALSE;
  }


  g_source_destroy (cand->tick_source);
  g_source_unref (cand->tick_source);
  cand->tick_source = NULL;

  switch (stun_timer_refresh (&cand->timer)) {
  case STUN_USAGE_TIMER_RETURN_TIMEOUT:
    {
      /* Time out */
      StunTransactionId id;

      stun_message_id (&cand->stun_message, id);
      stun_agent_forget_transaction (&cand->stun_agent, id);

      agent_signal_turn_allocation_failure(cand->agent,
                                           cand->stream->id,
                                           cand->component->id,
                                           &cand->server,
                                           NULL,
                                           "Allocate/Refresh timed out");
      refresh_cancel (cand);
      break;
    }
  case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
    /* Retransmit */
    nice_socket_send (cand->nicesock, &cand->server,
                      stun_message_length (&cand->stun_message), (gchar *)cand->stun_buffer);

    cand->tick_source = agent_timeout_add_with_context (cand->agent,
                                                        stun_timer_remainder (&cand->timer),
                                                        priv_turn_allocate_refresh_retransmissions_tick, cand);
    break;
  case STUN_USAGE_TIMER_RETURN_SUCCESS:
    cand->tick_source = agent_timeout_add_with_context (cand->agent,
                                                        stun_timer_remainder (&cand->timer),
                                                        priv_turn_allocate_refresh_retransmissions_tick, cand);
    break;
  }


  agent_unlock (agent);
  return FALSE;
}

static void priv_turn_allocate_refresh_tick_unlocked (CandidateRefresh *cand)
{
  uint8_t *username;
  size_t username_len;
  uint8_t *password;
  size_t password_len;
  size_t buffer_len = 0;
  StunUsageTurnCompatibility turn_compat =
    agent_to_turn_compatibility (cand->agent);

  username = (uint8_t *)cand->turn->username;
  username_len = (size_t) strlen (cand->turn->username);
  password = (uint8_t *)cand->turn->password;
  password_len = (size_t) strlen (cand->turn->password);

  if (turn_compat == STUN_USAGE_TURN_COMPATIBILITY_MSN ||
      turn_compat == STUN_USAGE_TURN_COMPATIBILITY_OC2007) {
    username = g_base64_decode ((gchar *)username, &username_len);
    password = g_base64_decode ((gchar *)password, &password_len);
  }

  buffer_len = stun_usage_turn_create_refresh (&cand->stun_agent,
                                               &cand->stun_message,  cand->stun_buffer, sizeof(cand->stun_buffer),
                                               cand->stun_resp_msg.buffer == NULL ? NULL : &cand->stun_resp_msg, -1,
                                               username, username_len,
                                               password, password_len,
                                               turn_compat);

  if (turn_compat == STUN_USAGE_TURN_COMPATIBILITY_MSN ||
      turn_compat == STUN_USAGE_TURN_COMPATIBILITY_OC2007) {
    g_free (cand->msn_turn_username);
    g_free (cand->msn_turn_password);
    cand->msn_turn_username = username;
    cand->msn_turn_password = password;
  }

  GST_DEBUG_OBJECT (cand->agent, "%u/%u: Sending allocate Refresh %u",
      cand->stream->id, cand->component->id, buffer_len);

  if (cand->tick_source != NULL) {
    g_source_destroy (cand->tick_source);
    g_source_unref (cand->tick_source);
    cand->tick_source = NULL;
  }

  if (buffer_len > 0) {
    struct sockaddr_storage server_address;

    stun_timer_start (&cand->timer, STUN_TIMER_DEFAULT_TIMEOUT,
                      STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);

    nice_address_copy_to_sockaddr(&cand->server, (struct sockaddr *)&server_address);
    stun_message_log(&cand->stun_message, TRUE, (struct sockaddr *)&server_address);

    /* send the refresh */
    nice_socket_send (cand->nicesock, &cand->server,
                      buffer_len, (gchar *)cand->stun_buffer);

    cand->tick_source = agent_timeout_add_with_context (cand->agent,
                                                        stun_timer_remainder (&cand->timer),
                                                        priv_turn_allocate_refresh_retransmissions_tick, cand);
  }

}


/*
 * Timer callback that handles refreshing TURN allocations
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_turn_allocate_refresh_tick (gpointer pointer)
{
  CandidateRefresh *cand = (CandidateRefresh *) pointer;
  NiceAgent *agent = cand->agent;

  agent_lock (agent);
  if (g_source_is_destroyed (g_main_current_source ())) {
    agent_unlock (agent);
    return FALSE;
  }

  priv_turn_allocate_refresh_tick_unlocked (cand);
  agent_unlock (agent);

  return FALSE;
}


/*
 * Initiates the next pending connectivity check.
 *
 * @return TRUE if a pending check was scheduled
 */
gboolean conn_check_schedule_next (NiceAgent *agent)
{
  gboolean res = priv_conn_check_unfreeze_next (agent);

  /* step: call once imediately */
  res = priv_conn_check_tick_unlocked ((gpointer) agent);

  /* step: schedule timer if not running yet */
  if (res && agent->conncheck_timer_source == NULL) {
    agent->conncheck_timer_source = agent_timeout_add_with_context (agent, agent->timer_ta, priv_conn_check_tick, agent);
  }

  /* step: also start the keepalive timer */
  if (agent->keepalive_timer_source == NULL) {
    agent->keepalive_timer_source = agent_timeout_add_with_context (agent, NICE_AGENT_TIMER_TR_DEFAULT, priv_conn_keepalive_tick, agent);
  }

  return res;
}

/*
 * Compares two connectivity check items. Checkpairs are sorted
 * in descending priority order, with highest priority item at
 * the start of the list.
 */
gint conn_check_compare (const CandidateCheckPair *a, const CandidateCheckPair *b)
{
  if (a->priority > b->priority)
    return -1;
  else if (a->priority < b->priority)
    return 1;
  return 0;
}

/*
 * Preprocesses a new connectivity check by going through list
 * of a any stored early incoming connectivity checks from
 * the remote peer. If a matching incoming check has been already
 * received, update the state of the new outgoing check 'pair'.
 *
 * @param agent context pointer
 * @param stream which stream (of the agent)
 * @param component pointer to component object to which 'pair'has been added
 * @param pair newly added connectivity check
 */
static void priv_preprocess_conn_check_pending_data (NiceAgent *agent, Stream *stream, Component *component, CandidateCheckPair *pair)
{
  GSList *i;
  for (i = component->incoming_checks; i; i = i->next) {
    IncomingCheck *icheck = i->data;

    /*
     * This socket comparison works because we can't possibly receive any early
     * checks from a relay candidate as we haven't set up permissions until
     * we receive the remote-candidates
     */
    if (nice_address_equal (&icheck->from, &pair->remote->addr) &&
        icheck->local_socket == pair->local->sockptr) {
      GST_DEBUG_OBJECT (agent, "%u/%u: Updating check %p(%s) with stored early-icheck %p",
          stream->id, component->id,
          pair, pair->foundation,
          icheck);

      if (icheck->use_candidate)
        priv_mark_pair_nominated (agent, stream, component, icheck->local_socket, pair->remote);

      priv_schedule_triggered_check (agent, stream, component, icheck->local_socket, pair->remote, icheck->use_candidate);
    }
  }
}

/*
 * Handle any processing steps for connectivity checks after
 * remote candidates have been set. This function handles
 * the special case where answerer has sent us connectivity
 * checks before the answer (containing candidate information),
 * reaches us. The special case is documented in sect 7.2
 * if ICE spec (ID-19).
 */
void conn_check_remote_candidates_set(NiceAgent *agent, guint stream_id, guint component_id)
{
  GSList *j, *k, *l, *m, *n;

  Stream *stream;
  Component *component;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    GST_DEBUG_OBJECT (agent, "%u/%u: %s illegal stream/component combination",
        stream_id, component_id, G_STRLOC);
  }

  for (j = stream->conncheck_list; j ; j = j->next) {
    CandidateCheckPair *pair = j->data;

    if (pair->component_id == component_id) {
      /*
       * perform delayed processing of spec steps section 7.2.1.4 and section 7.2.1.5
       */
      priv_preprocess_conn_check_pending_data (agent, stream, component, pair);
    }
  }

  for (k = component->incoming_checks; k; k = k->next) {
    IncomingCheck *icheck = k->data;
    gboolean match = FALSE;

    GST_DEBUG_OBJECT (agent, "%u/%u: checking stored incoming check",
        stream_id, component_id);

    /*
     * sect 7.2.1.3., "Learning Peer Reflexive Candidates", has to
     * be handled separately
     */
    for (l = component->remote_candidates; l; l = l->next) {
      NiceCandidate *cand = l->data;
      if (nice_address_equal (&icheck->from, &cand->addr)) {
        GST_DEBUG_OBJECT (agent, "%u/%u: found match for stored conncheck", stream_id, component_id);
        match = TRUE;
        break;
      }
    }

    if (match != TRUE) {
      /*
       * We have gotten an incoming connectivity check from
       * an address that is not a known remote candidate
       */
      NiceCandidate *local_candidate = NULL;
      NiceCandidate *remote_candidate = NULL;
      gchar from_addr_string[INET6_ADDRSTRLEN];

      nice_address_to_string (&icheck->from, from_addr_string);

      if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2) {
        /*
         * We need to find which local candidate was used
         */
        uint8_t uname[NICE_STREAM_MAX_UNAME];
        guint uname_len;

        GST_DEBUG_OBJECT (agent, "%u/%u: We have a peer-reflexive candidate in a stored pending check",
            stream->id, component->id);

        for (m = component->remote_candidates;
             m != NULL && remote_candidate == NULL; m = m->next) {
          for (n = component->local_candidates; n; n = n->next) {
            NiceCandidate *rcand = m->data;
            NiceCandidate *lcand = n->data;

            uname_len = priv_create_username (agent, stream,
                                              component->id,  rcand, lcand,
                                              uname, sizeof (uname), TRUE);

            if (icheck->username &&
                uname_len == icheck->username_len &&
                memcmp (uname, icheck->username, icheck->username_len) == 0) {
              local_candidate = lcand;
              remote_candidate = rcand;
              break;
            }
          }
        }
      }

      if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2 &&
          local_candidate == NULL) {
        /* if we couldn't match the username, then the matching remote
         * candidate hasn't been received yet.. we must wait */
        GST_DEBUG_OBJECT (agent, "Username check failed. pending check has "
            "to wait to be processed. username=%s from=%s:%u",
            icheck->username,
            from_addr_string, nice_address_get_port(&icheck->from));
      } else {
        NiceCandidate *candidate;

        GST_DEBUG_OBJECT (agent, "%u/%u: Discovered peer reflexive from early i-check from=%s:%u",
            stream->id, component->id,
            from_addr_string, nice_address_get_port(&icheck->from));
        candidate =
          discovery_learn_remote_peer_reflexive_candidate (agent,
                                                           stream,
                                                           component,
                                                           icheck->priority,
                                                           &icheck->from,
                                                           icheck->local_socket,
                                                           remote_candidate);
        if (candidate) {
          if (icheck->use_candidate)
            priv_mark_pair_nominated (agent, stream, component, icheck->local_socket, candidate);

          priv_schedule_triggered_check (agent, stream, component, icheck->local_socket, candidate, icheck->use_candidate);
        }
      }
    }
  }

  /* Once we process the pending checks, we should free them to avoid
   * reprocessing them again if a dribble-mode set_remote_candidates
   * is called */
  for (m = component->incoming_checks; m; m = m->next) {
    IncomingCheck *icheck = m->data;
    g_free (icheck->username);
    g_slice_free (IncomingCheck, icheck);
  }
  g_slist_free (component->incoming_checks);
  component->incoming_checks = NULL;
}


/*
 * Changes the selected pair for the component if 'pair' is nominated
 * and has higher priority than the currently selected pair. See
 * ICE sect 11.1.1. "Procedures for Full Implementations" (ID-19).
 */
static gboolean priv_update_selected_pair (NiceAgent *agent, Component *component, CandidateCheckPair *pair)
{
  g_assert (component);
  g_assert (pair);
  if (pair->priority > component->selected_pair.priority) {
    GST_DEBUG_OBJECT (agent, "%u/%u: changing selected pair to %p(%s) "
        "(old-prio:%" G_GUINT64_FORMAT " prio:%" G_GUINT64_FORMAT ").",
        pair->local->stream_id, component->id,
        pair, pair->foundation,
        component->selected_pair.priority,
        pair->priority);
    component_update_selected_pair (component, pair->local, pair->remote, pair->priority);

    priv_conn_keepalive_tick_unlocked (agent);

    agent_signal_new_selected_pair (agent, pair->stream_id, component->id,
                                    pair->local, pair->remote);
  }

  return TRUE;
}

/*
 * Updates the check list state.
 *
 * Implements parts of the algorithm described in
 * ICE sect 8.1.2. "Updating States" (ID-19): if for any
 * component, all checks have been completed and have
 * failed, mark that component's state to NICE_CHECK_FAILED.
 *
 * Sends a component state changesignal via 'agent'.
 */
static void priv_update_check_list_failed_components (NiceAgent *agent, Stream *stream)
{
  GSList *i;
  /* note: emitting a signal might cause the client
   *       to remove the stream, thus the component count
   *       must be fetched before entering the loop*/
  guint c, components = stream->n_components;

  /* note: iterate the conncheck list for each component separately */
  for (c = 0; c < components; c++) {
    Component *comp = NULL;
    if (!agent_find_component (agent, stream->id, c+1, NULL, &comp))
      continue;

    for (i = stream->conncheck_list; i; i = i->next) {
      CandidateCheckPair *p = i->data;

      if (p->stream_id == stream->id &&
          p->component_id == (c + 1)) {
        if (p->state != NICE_CHECK_FAILED)
          break;
      }
    }

    /* note: all checks have failed
     * Set the component to FAILED only if it actually had remote candidates
     * that failed.. */
    if (i == NULL && comp != NULL && comp->remote_candidates != NULL)
      agent_signal_component_state_change (agent,
                                           stream->id,
                                           (c + 1), /* component-id */
                                           NICE_COMPONENT_STATE_FAILED);
  }
}

/*
 * Updates the check list state for a stream component.
 *
 * Implements the algorithm described in ICE sect 8.1.2
 * "Updating States" (ID-19) as it applies to checks of
 * a certain component. If there are any nominated pairs,
 * ICE processing may be concluded, and component state is
 * changed to READY.
 *
 * Sends a component state changesignal via 'agent'.
 */
static void priv_update_check_list_state_for_ready (NiceAgent *agent, Stream *stream, Component *component)
{
  GSList *i;
  guint succeeded = 0, nominated = 0;

  g_assert (component);

  /*
   * search for at least one nominated pair on the valid list
   */
  for (i = stream->valid_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component->id &&
        p->state == NICE_CHECK_SUCCEEDED) {
      ++succeeded;
      if (p->nominated == TRUE) {
        ++nominated;
      }
    }
  }

  GST_DEBUG_OBJECT (agent, "%u/%u: valid list status: %u nominated, %u succeeded",
      stream->id, component->id, nominated, succeeded);
  if (nominated > 0) {
    /* Only go to READY if no checks are left in progress. If there are
     * any that are kept, then this function will be called again when the
     * conncheck tick timer finishes them all */
    if (priv_prune_pending_checks (agent, stream, component->id) == 0) {
      agent_signal_component_state_change (agent, stream->id,
                                           component->id, NICE_COMPONENT_STATE_READY);
    }
  }
}

/*
 * The remote party has signalled that the candidate pair
 * described by 'component' and 'remotecand' is nominated
 * for use.
 * Implements section 7.2.1.5 Updating the Nominated Flag
 */
static void priv_mark_pair_nominated (NiceAgent *agent, Stream *stream, Component *component, NiceSocket* local_socket, NiceCandidate *remotecand)
{
  GSList *i;

  g_assert (component);

  if (!agent->controlling_mode)  {

    for (i = stream->conncheck_list; i; i = i->next) {
      CandidateCheckPair *pair = i->data;
      /*
       * Use the local_socket to identify the correct local base pair.
       */
      if (pair->remote == remotecand &&
          pair->local->sockptr == local_socket) {
        if (pair->state == NICE_CHECK_SUCCEEDED) {
          /*
           * "If the state of this pair is Succeeded, it means that the check
           *  generated by this pair produced a successful response.  This would
           *  have caused the agent to construct a valid pair when that success
           *  response was received (see Section 7.1.3.2.2).  The agent now sets
           *  the nominated flag in the valid pair to true.  This may end ICE
           *  processing for this media stream; see Section 8."
           */
          CandidateCheckPair *valid_pair = pair->valid_pair;

          g_assert (valid_pair != NULL);

          GST_DEBUG_OBJECT (agent, "%u/%u: marking valid pair %p(%s) as nominated",
              stream->id, component->id, valid_pair, valid_pair->foundation);
          valid_pair->nominated = TRUE;

          priv_update_selected_pair (agent, component, pair->valid_pair);
          priv_update_check_list_state_for_ready (agent, stream, component);

        } else {
          /*
           * Mark the base pair as nominated so that if it later succeeds the valid pair
           * will be created with the nominated flag already set.
           */
          GST_DEBUG_OBJECT (agent, "%u/%u: marking checklist pair %p(%s) as nominated",
              stream->id, component->id, pair, pair->foundation);
          pair->nominated = TRUE;
        }
      }
    }
  }
}

/*
 * Add a check pair to the valid list after a successful check
 */
static void priv_add_pair_to_valid_list (NiceAgent *agent, Stream *stream, Component *component, CandidateCheckPair *valid_pair, CandidateCheckPair *base_pair)
{
  GSList *i;

  GST_DEBUG_OBJECT (agent, "%u/%u: Adding pair %p(%s) local-transport:%s to the valid list. pri=%" G_GUINT64_FORMAT,
      stream->id, component->id,
      valid_pair, valid_pair->foundation, candidate_transport_to_string (valid_pair->local->transport),
      valid_pair->priority);
  /*
   * Prevent elements appearing more than once (which can happen due to retransmissions)
   */
  i = g_slist_find (stream->valid_list, valid_pair);
  if (i == NULL) {
    base_pair->valid_pair = valid_pair;
    stream->valid_list = g_slist_insert_sorted (stream->valid_list, valid_pair,
                                                (GCompareFunc)conn_check_compare);
  } else {
    /*
     * This can happen if we get different mapped addresses returned STUN responses. Ignore all but the first valid pair
     * generated by a given base pair
     */
    CandidateCheckPair *existing_valid_pair = i->data;

    GST_DEBUG_OBJECT (agent, "%u/%u: Duplicate valid pair for %p(%s) base_pair %p(%s) local-transport:%s",
        stream->id, component->id,
        existing_valid_pair, existing_valid_pair->foundation,
        base_pair, base_pair->foundation, candidate_transport_to_string (base_pair->local->transport));
  }
}

/*
 * Remove a single conncheck pair from a stream. Ensures the pair is removed
 * from both the checklist and the valid list for this stream
 */
static void priv_delete_conncheck (Stream* stream, CandidateCheckPair* pair)
{
  stream->conncheck_list = g_slist_remove (stream->conncheck_list, pair);
  stream->valid_list = g_slist_remove (stream->valid_list, pair);
  stream->conncheck_heap = g_slist_remove (stream->conncheck_heap, pair);
  conn_check_free_item (pair, NULL);
}

/*
 * Enforces the upper limit for connectivity checks as described
 * in ICE spec section 5.7.3 (ID-19). See also
 * conn_check_add_for_remote_candidate().
 */
static void priv_limit_conn_check_list_size (NiceAgent *agent, Stream* stream, guint upper_limit)
{
  guint list_len = g_slist_length (stream->conncheck_list);

  g_assert (upper_limit > 0);

  while (g_slist_length (stream->conncheck_list) > upper_limit) {
    GSList* item = NULL;

    GST_DEBUG_OBJECT (agent, "%u/*: Pruning candidates. Conncheck list has %d elements. "
        "Maximum connchecks allowed : %d",
        stream->id, list_len, upper_limit);

    /*
     * Remove the lowest priority check pair
     */
    item = g_slist_last (stream->conncheck_list);
    priv_delete_conncheck (stream, item->data);
  }
}

/*
 * Creates a new connectivity check pair and adds it to
 * the agent's list of checks.
 */
static void priv_add_new_check_pair (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *local, NiceCandidate *remote, NiceCheckState initial_state, gboolean use_candidate)
{
  Stream *stream = agent_find_stream (agent, stream_id);
  CandidateCheckPair *pair = priv_alloc_check_pair (agent, stream);

  pair->agent = agent;
  pair->stream_id = stream_id;
  pair->component_id = component->id;;
  pair->local = local;
  pair->remote = remote;
  g_snprintf (pair->foundation, NICE_CANDIDATE_PAIR_MAX_FOUNDATION, "%s:%s", local->foundation, remote->foundation);

  pair->priority = agent_candidate_pair_priority (agent, local, remote);
  pair->state = initial_state;
  pair->nominated = use_candidate;
  pair->controlling = agent->controlling_mode;

  stream->conncheck_list = g_slist_insert_sorted (stream->conncheck_list, pair,
                                                  (GCompareFunc)conn_check_compare);

  GST_DEBUG_OBJECT (agent, "%u/%u: added a new conncheck %p foundation:'%s' state:%s use-cand:%d conncheck-count=%u",
      stream_id,
      component->id, pair, pair->foundation, priv_state_to_string(initial_state), use_candidate,
      g_slist_length (stream->conncheck_list));

  priv_print_check_list (agent, stream, stream->conncheck_list, "Check list");

  /* implement the hard upper limit for number of  checks (see sect 5.7.3 RFC 5245 and 3.1.4.8.2.1 of MS-ICE2): */
  priv_limit_conn_check_list_size (agent, stream, agent->max_conn_checks);
}

/*
 * Returns TRUE iff the two candidates supplied have compatible transports as specified in
 * RFC 6544 section 6.2
 */
static gboolean priv_compatible_transport(NiceCandidate *local, NiceCandidate *remote)
{
  gboolean res = FALSE;

  if (local->transport == NICE_CANDIDATE_TRANSPORT_UDP &&
      remote->transport == NICE_CANDIDATE_TRANSPORT_UDP) {
    res = TRUE;
  } else if (local->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE &&
             remote->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE) {
    res = TRUE;
  } else if (local->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE &&
             remote->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE) {
    res = TRUE;
  }
  return res;
}

gboolean conn_check_add_for_candidate_pair (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *local, NiceCandidate *remote)
{
  gboolean ret = FALSE;
  /*
   * Note: do not create pairs where the local candidate is a srv-reflexive
   * (ICE 5.7.3. "Pruning the pairs" ID-9)
   * This works because we will always have a host candidate with the same
   * base address as the server reflexive and hence can guarantee that the server
   * reflexive candidate should be pruned without further checks.
   */
  if (local->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
    return FALSE;
  }


  /*
   * note: match pairs only if transport and address family are the same
   *
   * RFC 6544 says that we shouldn't form check pairs for local TCP passive candidates.
   * However if we don't then the connectivity check state machinery can end up terminating
   * too soon since it thinks we don't have any more pairs to try. By creating a pair here
   * we will keep the pair in state IN_PROGRESS long enough to give the remote peer time
   * to connect to us
   */
  if (priv_compatible_transport(local, remote) &&
      nice_address_get_family(&local->addr) == nice_address_get_family(&remote->addr)) {

    priv_add_new_check_pair (agent, stream_id, component, local, remote, NICE_CHECK_FROZEN, FALSE);
    ret = TRUE;

    /*
     * JBFIXME: move this to when the initial check list is actually constructed and the stream
     * actually transitions to the RUNNING state
     */
    if (component->state < NICE_COMPONENT_STATE_CONNECTED) {
      agent_signal_component_state_change (agent,
                                           stream_id,
                                           component->id,
                                           NICE_COMPONENT_STATE_CONNECTING);
    }
  }

  return ret;
}

/*
 * Forms new candidate pairs by matching the new remote candidate
 * 'remote_cand' with all existing local candidates of 'component'.
 * Implements the logic described in ICE sect 5.7.1. "Forming Candidate
 * Pairs" (ID-19).
 *
 * @param agent context
 * @param component pointer to the component
 * @param remote remote candidate to match with
 *
 * @return number of checks added, negative on fatal errors
 */
void conn_check_add_for_remote_candidate (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *remote)
{
  GSList *i;

  for (i = component->local_candidates; i ; i = i->next) {
    NiceCandidate *local = i->data;
    conn_check_add_for_candidate_pair (agent, stream_id, component, local, remote);
  }
}

/*
 * Forms new candidate pairs by matching the new local candidate
 * 'local_cand' with all existing remote candidates of 'component'.
 *
 * @param agent context
 * @param component pointer to the component
 * @param local local candidate to match with
 *
 * @return number of checks added, negative on fatal errors
 */
void conn_check_add_for_local_candidate (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *local)
{
  GSList *i;
  for (i = component->remote_candidates; i ; i = i->next) {
    NiceCandidate *remote = i->data;
    conn_check_add_for_candidate_pair (agent, stream_id, component, local, remote);
  }
}

/*
 * Frees the CandidateCheckPair structure pointer to
 * by 'user data'. Compatible with g_slist_foreach().
 */
void conn_check_free_item (gpointer data, gpointer user_data)
{
  CandidateCheckPair *pair = data;
  g_assert (user_data == NULL);
  pair->stun_message.buffer = NULL;
  pair->stun_message.buffer_len = 0;
  g_slice_free (CandidateCheckPair, pair);
}

/*
 * Frees all resources of all connectivity checks.
 */
void conn_check_prune_all_streams (NiceAgent *agent)
{
  GSList *i;
  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    conn_check_prune_stream (agent, stream);
  }

  if (agent->conncheck_timer_source != NULL) {
    g_source_destroy (agent->conncheck_timer_source);
    g_source_unref (agent->conncheck_timer_source);
    agent->conncheck_timer_source = NULL;
  }
}

/*
 * Prunes the list of connectivity checks for items related
 * to stream 'stream_id'.
 *
 * @return TRUE on success, FALSE on a fatal error
 */
void conn_check_prune_stream (NiceAgent *agent, Stream *stream)
{
  GST_DEBUG_OBJECT (agent, "freeing conncheck_list of stream %p", stream);
  if (stream->conncheck_heap) {
    g_slist_foreach (stream->conncheck_heap, conn_check_free_item, NULL);
    g_slist_free (stream->conncheck_heap);
    stream->conncheck_heap = NULL;
  }
  if (stream->conncheck_list) {
    g_slist_free (stream->conncheck_list);
    stream->conncheck_list = NULL;
  }
  if (stream->valid_list) {
    g_slist_free (stream->valid_list);
    stream->valid_list = NULL;
  }
}

/*
 * Fills 'dest' with a username string for use in an outbound connectivity
 * checks. No more than 'dest_len' characters (including terminating
 * NULL) is ever written to the 'dest'.
 */
static
size_t priv_gen_username (NiceAgent *agent, guint component_id,
                          gchar *remote, gchar *local, uint8_t *dest, guint dest_len)
{
  guint len = 0;
  gsize remote_len = strlen (remote);
  gsize local_len = strlen (local);

  if (remote_len > 0 && local_len > 0) {
    if (agent->compatibility == NICE_COMPATIBILITY_RFC5245 &&
        dest_len >= remote_len + local_len + 1) {
      memcpy (dest, remote, remote_len);
      len += remote_len;
      memcpy (dest + len, ":", 1);
      len++;
      memcpy (dest + len, local, local_len);
      len += local_len;
    } else if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2 &&
               dest_len >= remote_len + local_len + 4 ) {
      memcpy (dest, remote, remote_len);
      len += remote_len;
      memcpy (dest + len, ":", 1);
      len++;
      memcpy (dest + len, local, local_len);
      len += local_len;
      if (len % 4 != 0) {
        memset (dest + len, 0, 4 - (len % 4));
        len += 4 - (len % 4);
      }
    }
  }

  return len;
}

/*
 * Fills 'dest' with a username string for use in an outbound connectivity
 * checks. No more than 'dest_len' characters (including terminating
 * NULL) is ever written to the 'dest'.
 */
static
size_t priv_create_username (NiceAgent *agent, Stream *stream,
                             guint component_id, NiceCandidate *remote, NiceCandidate *local,
                             uint8_t *dest, guint dest_len, gboolean inbound)
{
  gchar *local_username = NULL;
  gchar *remote_username = NULL;


  if (remote && remote->username) {
    remote_username = remote->username;
  }

  if (local && local->username) {
    local_username = local->username;
  }

  if (stream) {
    if (remote_username == NULL) {
      remote_username = stream->remote_ufrag;
    }
    if (local_username == NULL) {
      local_username = stream->local_ufrag;
    }
  }

  if (local_username && remote_username) {
    if (inbound) {
      return priv_gen_username (agent, component_id,
                                local_username, remote_username, dest, dest_len);
    } else {
      return priv_gen_username (agent, component_id,
                                remote_username, local_username, dest, dest_len);
    }
  }

  return 0;
}

/*
 * Returns a password string for use in an outbound connectivity
 * check.
 */
static
size_t priv_get_password (NiceAgent *agent, Stream *stream,
                          NiceCandidate *remote, uint8_t **password)
{
  if (remote && remote->password) {
    *password = (uint8_t *)remote->password;
    return strlen (remote->password);
  }

  if (stream) {
    *password = (uint8_t *)stream->remote_password;
    return strlen (stream->remote_password);
  }

  return 0;
}

/*
 * Attempt to locate a suitable candidate identifier to use when communicating
 * with a remote Lync client. Contrary to the MS-ICE2 documentation this is not
 * always the foundation of the local candidate we are sending from (or it's base
 * in the case of a peer-derived candidate). Instead it appears that we must
 * set it to the foundation of the server reflexive candidate that corresponds with
 * this base
 */
static gchar *priv_get_candidate_identifier (NiceAgent *agent, CandidateCheckPair *pair)
{
  if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2 &&
      pair->local->type == NICE_CANDIDATE_TYPE_HOST &&
      pair->remote->type == NICE_CANDIDATE_TYPE_RELAYED &&
      pair->local->transport == NICE_CANDIDATE_TRANSPORT_UDP)
  {
    Stream *stream = NULL;
    Component *component = NULL;
    GSList *k;

    agent_find_component (agent, pair->local->stream_id, pair->local->component_id,
                       &stream, &component);

    g_assert (stream != NULL);
    g_assert (component != NULL);

    for (k = component->local_candidates; k; k = k->next)
    {
      NiceCandidate *candidate = k->data;

      if (candidate->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
          nice_address_equal (&candidate->base_addr, &pair->local->addr))
      {
        GST_DEBUG_OBJECT (agent, "%u/%u: Using server reflexive candidate identifier %s rather than local identifier %s",
            stream->id, component->id,
            candidate->foundation,
            pair->local->foundation);
        return candidate->foundation;
      }
    }
  }

  return pair->local->foundation;
}

/*
 * Sends a connectivity check over candidate pair 'pair'.
 *
 * @return zero on success, non-zero on error
 */
int conn_check_send (NiceAgent *agent, CandidateCheckPair *pair)
{

  /* note: following information is supplied:
   *  - username (for USERNAME attribute)
   *  - password (for MESSAGE-INTEGRITY)
   *  - priority (for PRIORITY)
   *  - ICE-CONTROLLED/ICE-CONTROLLING (for role conflicts)
   *  - USE-CANDIDATE (if sent by the controlling agent)
   */
  guint32 priority = agent_candidate_ice_priority (agent, pair->local, NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);

  uint8_t uname[NICE_STREAM_MAX_UNAME];
  size_t uname_len =
    priv_create_username (agent, agent_find_stream (agent, pair->stream_id),
                          pair->component_id, pair->remote, pair->local, uname, sizeof (uname), FALSE);
  uint8_t *password = NULL;
  size_t password_len = priv_get_password (agent,
                                           agent_find_stream (agent, pair->stream_id), pair->remote, &password);

  bool controlling = agent->controlling_mode;
  /* XXX: add API to support different nomination modes: */
  bool cand_use = controlling;
  size_t buffer_len;
  unsigned int timeout;
  gchar tmpbuf[INET6_ADDRSTRLEN];

  nice_address_to_string (&pair->remote->addr, tmpbuf);

  if (cand_use && agent->aggressive_mode)
    pair->nominated = controlling;

  nice_address_to_string (&pair->remote->addr, tmpbuf);
  GST_DEBUG_OBJECT (agent, "%u/%u: STUN-CC Sending Request to '%s:%u', pair=%s, priority=%u use-cand:%d",
      pair->stream_id, pair->component_id,
      tmpbuf, nice_address_get_port (&pair->remote->addr),
      pair->foundation, priority, cand_use);

  if (uname_len > 0) {

    buffer_len = stun_usage_ice_conncheck_create (&agent->stun_agent,
        &pair->stun_message, pair->stun_buffer, sizeof(pair->stun_buffer),
        uname, uname_len, password, password_len,
        pair->nominated, controlling, priority,
        agent->tie_breaker,
        priv_get_candidate_identifier (agent, pair),
        agent_to_ice_compatibility (agent));

    if (buffer_len > 0) {
      stun_timer_start (&pair->timer, agent->conncheck_timeout, agent->conncheck_retransmissions);

      GST_DEBUG_OBJECT (agent, "%u/%u: Sending conncheck msg len=%u to %s",
          pair->stream_id, pair->component_id, buffer_len, tmpbuf);

      /* Don't send to the discard port */
      if (nice_address_get_port (&pair->remote->addr) != 9) {
        /* send the conncheck */
        nice_socket_send (pair->local->sockptr, &pair->remote->addr,
                          buffer_len, (gchar *)pair->stun_buffer);
      }

      timeout = stun_timer_remainder (&pair->timer);
      /* note: convert from milli to microseconds for g_time_val_add() */
      g_get_current_time (&pair->next_tick);
      g_time_val_add (&pair->next_tick, timeout * 1000);
    } else {
      GST_DEBUG_OBJECT (agent, "buffer is empty, cancelling conncheck");
      pair->stun_message.buffer = NULL;
      pair->stun_message.buffer_len = 0;
      return -1;
    }
  } else {
    GST_DEBUG_OBJECT (agent, "no credentials found, cancelling conncheck");
    pair->stun_message.buffer = NULL;
    pair->stun_message.buffer_len = 0;
    return -1;
  }

  return 0;
}

/*
 * Equivalent of priv_prune_pending_checks but with different logic to handle when
 * we are controller and running in regular nomination mode
 */
static guint priv_prune_pending_checks_regular_nomination (NiceAgent *agent, Stream *stream, guint component_id)
{
  GSList *i;
  guint in_progress = 0;

  GST_DEBUG_OBJECT (agent, "%u/%u: Pruning pending checks.",
      stream->id, component_id);

  /* step: cancel all FROZEN and WAITING pairs for the component */
  for (i = stream->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component_id) {

      switch (p->state) {
      case NICE_CHECK_WAITING:
      case NICE_CHECK_FROZEN:
        priv_set_pair_state (agent, p, NICE_CHECK_CANCELLED);
        break;

      case NICE_CHECK_IN_PROGRESS:
        /*
         * The nominated pairs go back to the IN_PROGRESS state whilst waiting for the
         * remote party to respond. Any other in progress checks can be cancelled though
         */
        if (!p->nominated) {
          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          priv_set_pair_state (agent, p, NICE_CHECK_CANCELLED);
        } else {
          /* We must keep the higher priority pairs running because if a udp
           * packet was lost, we might end up using a bad candidate */
          GST_DEBUG_OBJECT (agent, "%u/%u: pair %p(%s) kept IN_PROGRESS because it's a nominated pair",
              stream->id, component_id, p, p->foundation);
          in_progress++;
        }
        break;

      case NICE_CHECK_SUCCEEDED:
      case NICE_CHECK_FAILED:
      case NICE_CHECK_CANCELLED:
        /* Do nothing */
        break;
      }
    }
  }

  return in_progress;
}

static guint priv_prune_pending_checks_aggressive_or_controlled (NiceAgent *agent, Stream *stream, guint component_id)
{
  GSList *i;
  guint64 highest_nominated_priority = 0;
  guint in_progress = 0;
  CandidateCheckPair *highest_nominated_pair = NULL;
  gboolean prune_all_checks = FALSE;


  for (i = stream->valid_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component_id &&
        p->nominated == TRUE) {
      if (p->priority > highest_nominated_priority) {
        highest_nominated_priority = p->priority;
        highest_nominated_pair = p;
      }
    }
  }

  GST_DEBUG_OBJECT (agent, "%u/%u: Pruning pending checks. Highest nominated pair %s priority "
      "is %" G_GUINT64_FORMAT,
      stream->id, component_id, highest_nominated_pair->foundation, highest_nominated_priority);

  /*
   * For Microsoft TCP once we have a nominated RTP pair then cancel all outstanding pairs for any
   * component of this stream as we know the Lync client will not nominate any more
   */
  if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2 &&
      !agent->controlling_mode &&
      highest_nominated_pair != NULL &&
      component_id == NICE_COMPONENT_TYPE_RTP &&
      (highest_nominated_pair->local->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE ||
       highest_nominated_pair->local->transport == NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE)) {
    GST_DEBUG_OBJECT (agent, "%u/%u: RDP call, pruning all checks highest_nominated_pair = %p(%s)",
        stream->id, component_id,
        highest_nominated_pair, highest_nominated_pair->foundation);
    prune_all_checks = TRUE;
  }

  /* step: cancel all FROZEN and WAITING pairs for the component */
  for (i = stream->conncheck_list; i; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component_id || prune_all_checks) {
      gboolean controlling_microsoft = FALSE;

      if (agent->controlling_mode && agent->compatibility == NICE_COMPATIBILITY_OC2007R2) {
        /*
         * To work around the fact that we don't do regular nomination we'll keep all
         * higher priority pairs running when talking to microsoft so that we should
         * eventually converge on the highest priority working pairs in all cases
         */
        controlling_microsoft = TRUE;
      }

      if (p->state == NICE_CHECK_FROZEN ||
          p->state == NICE_CHECK_WAITING) {
        if (!controlling_microsoft) {
          priv_set_pair_state (agent, p, NICE_CHECK_CANCELLED);
        } else {
          /* Microsoft mode only cancel if it's lower priority */
          if ((highest_nominated_priority != 0 && p->priority < highest_nominated_priority ) ||
              prune_all_checks) {
            priv_set_pair_state (agent, p, NICE_CHECK_CANCELLED);
          } else {
            GST_DEBUG_OBJECT (agent, "%u/%u: pair %p(%s) kept %s because microsoft mode and priority %"
                G_GUINT64_FORMAT " is higher than currently nominated pair %s %"
                G_GUINT64_FORMAT, stream->id, component_id, p, p->foundation,
                priv_state_to_string (p->state),
                p->priority, highest_nominated_pair->foundation,
                highest_nominated_priority);
            in_progress++;
          }
        }
      }

      /* note: a SHOULD level req. in ICE 8.1.2. "Updating States" (ID-19) */
      if (p->state == NICE_CHECK_IN_PROGRESS) {
        if ((highest_nominated_priority != 0 && p->priority < highest_nominated_priority ) ||
            prune_all_checks ||
            (highest_nominated_pair != NULL && agent->compatibility == NICE_COMPATIBILITY_OC2007R2 && !agent->controlling_mode)) {
          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          priv_set_pair_state (agent, p, NICE_CHECK_CANCELLED);
        } else {
          /* We must keep the higher priority pairs running because if a udp
           * packet was lost, we might end up using a bad candidate */
          GST_DEBUG_OBJECT (agent, "%u/%u: pair %p(%s) kept IN_PROGRESS because priority %"
              G_GUINT64_FORMAT " is higher than currently nominated pair %s %"
              G_GUINT64_FORMAT, stream->id, component_id, p, p->foundation, p->priority, highest_nominated_pair->foundation,
              highest_nominated_priority);
          in_progress++;
        }
      }
    }
  }

  return in_progress;
}

/*
 * Implemented the pruning steps described in ICE sect 8.1.2
 * "Updating States" (ID-19) after a pair has been nominated.
 *
 * @see priv_update_check_list_state_failed_components()
 */
static guint priv_prune_pending_checks (NiceAgent *agent, Stream *stream, guint component_id)
{
  if (agent->controlling_mode && !agent->aggressive_mode) {
    return priv_prune_pending_checks_regular_nomination (agent, stream, component_id);
  } else {
    return priv_prune_pending_checks_aggressive_or_controlled (agent, stream, component_id);
  }
}

/*
 * Schedules a triggered check after a successfully inbound
 * connectivity check. Implements ICE sect 7.2.1.4 "Triggered Checks" (ID-19).
 *
 * @param agent self pointer
 * @param component the check is related to
 * @param local_socket socket from which the inbound check was received
 * @param remote_cand remote candidate from which the inbound check was sent
 * @param use_candidate whether the original check had USE-CANDIDATE attribute set
 */
static gboolean priv_schedule_triggered_check (NiceAgent *agent, Stream *stream, Component *component, NiceSocket *local_socket, NiceCandidate *remote_cand, gboolean use_candidate)
{
  GSList *i;
  NiceCandidate *local = NULL;

  for (i = stream->conncheck_list; i ; i = i->next) {
    CandidateCheckPair *p = i->data;
    if (p->component_id == component->id &&
        p->remote == remote_cand &&
        p->local->sockptr == local_socket) {

      GST_DEBUG_OBJECT (agent, "%u/%u: Found a matching pair %p(%s) for triggered check.",
          p->local->stream_id, p->local->component_id,
          p, p->foundation);

      if (p->state == NICE_CHECK_WAITING ||
          p->state == NICE_CHECK_FROZEN)
        priv_conn_check_initiate (agent, p);
      else if (p->state == NICE_CHECK_IN_PROGRESS) {
        /* XXX: according to ICE 7.2.1.4 "Triggered Checks" (ID-19),
         * we should cancel the existing one, instead we reset our timer, so
         * we'll resend the existing transactions faster if needed...? :P
         */
        GST_DEBUG_OBJECT (agent, "check already in progress, "
            "restarting the timer again?: %s ..",
            p->timer_restarted ? "no" : "yes");
        if (!p->timer_restarted) {
          stun_timer_start (&p->timer, agent->conncheck_timeout, agent->conncheck_retransmissions);
          p->timer_restarted = TRUE;
        }
      }
      else if (p->state == NICE_CHECK_SUCCEEDED) {
        GST_DEBUG_OBJECT (agent, "Skipping triggered check, already completed..");
        /* note: this is a bit unsure corner-case -- let's do the
           same state update as for processing responses to our own checks */
        priv_update_check_list_state_for_ready (agent, stream, component);

        /* note: to take care of the controlling-controlling case in
         *       aggressive nomination mode, send a new triggered
         *       check to nominate the pair */
        if (agent->controlling_mode)
          priv_conn_check_initiate (agent, p);
      } else if (p->state == NICE_CHECK_FAILED) {
        /* 7.2.1.4 Triggered Checks
         * If the state of the pair is Failed, it is changed to Waiting
         and the agent MUST create a new connectivity check for that
         pair (representing a new STUN Binding request transaction), by
         enqueueing the pair in the triggered check queue. */
        priv_conn_check_initiate (agent, p);
      }

      /* note: the spec says the we SHOULD retransmit in-progress
       *       checks immediately, but we won't do that now */

      return TRUE;
    }
  }

  for (i = component->local_candidates; i ; i = i->next) {
    local = i->data;
    if (local->sockptr == local_socket)
      break;
  }

  if (i) {
    GST_DEBUG_OBJECT (agent, "Adding a triggered check to conn.check list (local=%p). WAITING", local);
    priv_add_new_check_pair (agent, stream->id, component, local, remote_cand, NICE_CHECK_WAITING, use_candidate);
    return TRUE;
  }
  else {
    GST_DEBUG_OBJECT (agent, "Didn't find a matching pair for triggered check (remote-cand=%p).", remote_cand);
    return FALSE;
  }
}


/*
 * Sends a reply to an successfully received STUN connectivity
 * check request. Implements parts of the ICE spec section 7.2 (STUN
 * Server Procedures).
 *
 * @param agent context pointer
 * @param stream which stream (of the agent)
 * @param component which component (of the stream)
 * @param rcand remote candidate from which the request came, if NULL,
 *        the response is sent immediately but no other processing is done
 * @param toaddr address to which reply is sent
 * @param socket the socket over which the request came
 * @param rbuf_len length of STUN message to send
 * @param rbuf buffer containing the STUN message to send
 * @param use_candidate whether the request had USE_CANDIDATE attribute
 *
 * @pre (rcand == NULL || nice_address_equal(rcand->addr, toaddr) == TRUE)
 */
static void priv_reply_to_conn_check (NiceAgent *agent, Stream *stream, Component *component, NiceCandidate *rcand, const NiceAddress *toaddr, NiceSocket *socket, size_t  rbuf_len, uint8_t *rbuf, gboolean use_candidate)
{
  gchar tmpbuf[INET6_ADDRSTRLEN];

  g_assert (rcand == NULL || nice_address_equal_full(&rcand->addr, toaddr, rcand->transport != NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE) == TRUE);

  nice_address_to_string (toaddr, tmpbuf);
  GST_LOG_OBJECT (agent, "%u/%u: STUN-CC Sending Response to '%s:%u', socket=%u, len=%u, cand=%p (c-id:%u), use-cand=%d.",
      stream->id, component->id,
      tmpbuf,
      nice_address_get_port (toaddr),
      socket->fileno ? g_socket_get_fd(socket->fileno) : 0,
      (unsigned)rbuf_len,
      rcand, component->id,
      (int)use_candidate);

  nice_socket_send (socket, toaddr, rbuf_len, (const gchar*)rbuf);

  if (rcand) {
    /*
     * note: upon successful check, make the reserve check immediately
     */
    priv_schedule_triggered_check (agent, stream, component, socket, rcand, use_candidate);

    if (use_candidate)
      priv_mark_pair_nominated (agent, stream, component, socket, rcand);
  }
}

/*
 * Stores information of an incoming STUN connectivity check
 * for later use. This is only needed when a check is received
 * before we get information about the remote candidates (via
 * SDP or other signaling means).
 *
 * @return non-zero on error, zero on success
 */
static int priv_store_pending_check (NiceAgent *agent, Stream *stream, Component *component,
                                     const NiceAddress *from, NiceSocket *socket, uint8_t *username,
                                     uint16_t username_len, uint32_t priority, gboolean use_candidate)
{
  IncomingCheck *icheck;
  gchar          from_string[NICE_ADDRESS_STRING_LEN] = {0};


  if (component->incoming_checks &&
      g_slist_length (component->incoming_checks) >=
      NICE_AGENT_MAX_REMOTE_CANDIDATES) {
    GST_WARNING_OBJECT (agent, "%u/%u: WARN: unable to store information for early incoming check.",
        stream->id, component->id);
    return -1;
  }

  icheck = g_slice_new0 (IncomingCheck);
  component->incoming_checks = g_slist_append (component->incoming_checks, icheck);
  icheck->from = *from;
  icheck->local_socket = socket;
  icheck->priority = priority;
  icheck->use_candidate = use_candidate;
  icheck->username_len = username_len;
  icheck->username = NULL;
  if (username_len > 0)
    icheck->username = g_memdup (username, username_len);

  nice_address_to_string (from, from_string);
  GST_DEBUG_OBJECT (agent, "%u/%u: Storing pending check from [%s]:%u use_cand=%d priority=%d icheck=%p",
      stream->id, component->id,
      from_string, nice_address_get_port(from), use_candidate, icheck->priority, icheck);

  return 0;
}

/*
 * Adds a new pair, discovered from an incoming STUN response, to
 * the connectivity check list.
 *
 * @return created pair, or NULL on fatal (memory allocation) errors
 */
static CandidateCheckPair *priv_create_peer_reflexive_pair (NiceAgent *agent, guint stream_id, guint component_id, NiceCandidate *local_cand, CandidateCheckPair *parent_pair)
{
  Stream *stream = agent_find_stream (agent, stream_id);
  CandidateCheckPair *pair = priv_alloc_check_pair (agent, stream);

  pair->agent = agent;
  pair->stream_id = stream_id;
  pair->component_id = component_id;;
  pair->local = local_cand;
  pair->remote = parent_pair->remote;
  pair->state = NICE_CHECK_SUCCEEDED;
  g_snprintf (pair->foundation, NICE_CANDIDATE_PAIR_MAX_FOUNDATION, "%s:%s",
              local_cand->foundation, parent_pair->remote->foundation);
  if (agent->controlling_mode == TRUE)
    pair->priority = nice_candidate_pair_priority (pair->local->priority,
                                                   pair->remote->priority);
  else
    pair->priority = nice_candidate_pair_priority (pair->remote->priority,
                                                   pair->local->priority);
  pair->nominated = FALSE;
  pair->controlling = agent->controlling_mode;
  GST_DEBUG_OBJECT (agent, "%u/%u: added a new peer-discovered pair %p(%s).",
      pair->stream_id, pair->component_id,
      pair, pair->foundation);

  return pair;
}

/*
 * Recalculates priorities of all candidate pairs. This
 * is required after a conflict in ICE roles.
 */
static void priv_recalculate_pair_priorities (NiceAgent *agent)
{
  GSList *i, *j;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    priv_print_check_list (agent, stream, stream->conncheck_list, "Check list (before re-priorisation)");
    for (j = stream->conncheck_list; j; j = j->next) {
      CandidateCheckPair *p = j->data;
      p->priority = agent_candidate_pair_priority (agent, p->local, p->remote);
    }
    stream->conncheck_list = g_slist_sort(stream->conncheck_list, (GCompareFunc)conn_check_compare);
    stream->valid_list = g_slist_sort(stream->valid_list, (GCompareFunc)conn_check_compare);
    priv_print_check_list (agent, stream, stream->conncheck_list, "Check list (after re-priorisation)");
    g_assert (priv_conn_check_list_is_ordered (stream->conncheck_list));
  }
}

/*
 * Change the agent role if different from 'control'. Can be
 * initiated both by handling of incoming connectivity checks,
 * and by processing the responses to checks sent by us.
 */
static void priv_check_for_role_conflict (NiceAgent *agent, gboolean control)
{
  /* role conflict, change mode; wait for a new conn. check */
  if (control != agent->controlling_mode) {
    GST_DEBUG_OBJECT (agent, "Role conflict, changing agent role to %d.", control);
    agent->controlling_mode = control;
    /* the pair priorities depend on the roles, so recalculation
     * is needed */
    priv_recalculate_pair_priorities (agent);
  }
  else
    GST_DEBUG_OBJECT (agent, "Role conflict, agent role already changed to %d.", control);
}

/*
 * Tries to find an existing pair on either the checklist of the valid list
 * for the given local and remote candidates. Returns NULL if no pair exists
 */
static CandidateCheckPair* priv_find_check_pair (NiceAgent* agent, Stream* stream, Component* component,
                                                 NiceCandidate* local, NiceCandidate* remote)
{
  GSList *i;

  for (i = stream->conncheck_list; i; i = g_slist_next (i)) {
    CandidateCheckPair* pair = i->data;

    if (pair->local == local &&
        pair->remote == remote) {
      return pair;
    }
  }

  for (i = stream->valid_list; i; i = g_slist_next (i)) {
    CandidateCheckPair* pair = i->data;

    if (pair->local == local &&
        pair->remote == remote) {
      return pair;
    }
  }

  return NULL;
}

/*
 * Checks whether the mapped address in connectivity check response
 * matches any of the known local candidates. If not, apply the
 * mechanism for "Discovering Peer Reflexive Candidates" Section 7.1.3.2.1 RFC 5245
 *
 * Returns the valid pair. May be a pair already on the checklist or a newly created
 * pair
 */
static CandidateCheckPair* priv_process_response_check_for_peer_reflexive(NiceAgent *agent, Stream *stream, Component *component, CandidateCheckPair *p, NiceSocket *sockptr, struct sockaddr *mapped_sockaddr, NiceCandidate *remote_candidate)
{
  CandidateCheckPair *valid_pair = NULL;
  NiceAddress mapped;
  GSList *j;
  NiceCandidate *local_candidate = NULL;

  nice_address_set_from_sockaddr (&mapped, mapped_sockaddr);

  for (j = component->local_candidates; j; j = j->next) {
    NiceCandidate *cand = j->data;

    /*
     * We need to be careful with transports here. 'p' is the pair
     * on which we sent the original connectivity check. We only want to match
     * the mapped address against local candidates that have the same transport
     * as the original local candidate.
     */
    if (nice_address_equal (&mapped, &cand->addr) &&
        cand->transport == p->local->transport) {
      local_candidate = cand;
      break;
    }
  }

  if (local_candidate != NULL) {
    GST_DEBUG_OBJECT (agent, "%u/%u: Mapped address matches existing local candidate %s",
        stream->id, component->id, local_candidate->foundation);
  } else {
    local_candidate = discovery_add_peer_reflexive_candidate (agent,
                                                              stream->id,
                                                              component->id,
                                                              &mapped,
                                                              sockptr,
                                                              local_candidate,
                                                              remote_candidate);
  }

  /*
   * Adding peer reflexive should never fail as we have already checked for duplicate candidates
   */
  g_assert (local_candidate != NULL);

  /*
   * 7.1.3.2.2.  Constructing a Valid Pair
   *
   * "The agent constructs a candidate pair whose local candidate equals
   *  the mapped address of the response, and whose remote candidate equals
   *  the destination address to which the request was sent.  This is
   *  called a valid pair, since it has been validated by a STUN
   *  connectivity check.  The valid pair may equal the pair that generated
   *  the check, may equal a different pair in the check list, or may be a
   *  pair not currently on any check list. If the pair equals the pair
   *  that generated the check or is on a check list currently, it is also
   *  added to the VALID LIST, which is maintained by the agent for each
   *  media stream.  This list is empty at the start of ICE processing, and
   *  fills as checks are performed, resulting in valid candidate pairs."
   *
   * First see if the checklist for this stream contains an existing pair
   * with the same local and remote candidates
   */
  valid_pair = priv_find_check_pair (agent, stream, component, local_candidate, p->remote);

  if (!valid_pair) {
    /*
     * "It will be very common that the pair will not be on any check list.
     *  Recall that the check list has pairs whose local candidates are never
     *  server reflexive; those pairs had their local candidates converted to
     *  the base of the server reflexive candidates, and then pruned if they
     *  were redundant.  When the response to the STUN check arrives, the
     *  mapped address will be reflexive if there is a NAT between the two.
     *  In that case, the valid pair will have a local candidate that doesn't
     *  match any of the pairs in the check list.
     *
     *  If the pair is not on any check list, the agent computes the priority
     *  for the pair based on the priority of each candidate, using the
     *  algorithm in Section 5.7.  The priority of the local candidate
     *  depends on its type.  If it is not peer reflexive, it is equal to the
     *  priority signaled for that candidate in the SDP.  If it is peer
     *  reflexive, it is equal to the PRIORITY attribute the agent placed in
     *  the Binding request that just completed.  The priority of the remote
     *  candidate is taken from the SDP of the peer.  If the candidate does
     *  not appear there, then the check must have been a triggered check to
     *  a new remote candidate.  In that case, the priority is taken as the
     *  value of the PRIORITY attribute in the Binding request that triggered
     *  the check that just completed.  The pair is then added to the VALID
     *  LIST.
     */
    valid_pair = priv_create_peer_reflexive_pair (agent, stream->id, component->id, local_candidate, p);
  } else {
    GST_DEBUG_OBJECT (agent, "%u/%u: valid pair matches an existing pair %s",
        stream->id, component->id, valid_pair->foundation);
  }

  /*
   * Section 7.1.3.2.3 Updating pair states
   */
  priv_add_pair_to_valid_list (agent, stream, component, valid_pair, p);
  priv_set_pair_state (agent, p, NICE_CHECK_SUCCEEDED);
  priv_conn_check_unfreeze_related (agent, stream, p);

  return valid_pair;
}

/*
 * Tries to match STUN reply in 'buf' to an existing STUN connectivity
 * check transaction. If found, the reply is processed. Implements
 * section 7.1.3 "Processing the Response" of RFC 5245
 *
 * @return TRUE if a matching transaction is found
 */
static gboolean priv_map_reply_to_conn_check_request (NiceAgent *agent, Stream *stream, Component *component, NiceSocket *sockptr, const NiceAddress *from, NiceCandidate *remote_candidate, StunMessage *resp)
{
  struct sockaddr_storage sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  GSList *i;
  StunUsageIceReturn res;
  gboolean trans_found = FALSE;
  StunTransactionId discovery_id;
  StunTransactionId response_id;
  stun_message_id (resp, response_id);

  for (i = stream->conncheck_list; i && trans_found != TRUE; i = i->next) {
    CandidateCheckPair *p = i->data;

    if (p->stun_message.buffer) {
      stun_message_id (&p->stun_message, discovery_id);

      if (memcmp (discovery_id, response_id, sizeof(StunTransactionId)) == 0) {
        gchar tmpbuf[INET6_ADDRSTRLEN];

        nice_address_to_string (from, tmpbuf);
        res = stun_usage_ice_conncheck_process (resp,
                                                (struct sockaddr *) &sockaddr, &socklen,
                                                agent_to_ice_compatibility (agent));
        GST_DEBUG_OBJECT (agent, "%u/%u: STUN-CC Response Received from %s for %p(%s) res %d "
            "(controlling=%d).",
            stream->id, component->id, tmpbuf, p, p->foundation, (int)res, agent->controlling_mode);

        if (res == STUN_USAGE_ICE_RETURN_SUCCESS ||
            res == STUN_USAGE_ICE_RETURN_NO_MAPPED_ADDRESS) {
          /* case: found a matching connectivity check request */

          CandidateCheckPair *valid_pair = NULL;

          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;

          /* step: verify that response came from the same IP address we
           *       sent the original request to (see 7.1.2.1. "Failure
           *       Cases") */
          if (nice_address_equal (from, &p->remote->addr) != TRUE) {
            gchar tmpbuf[INET6_ADDRSTRLEN];
            gchar tmpbuf2[INET6_ADDRSTRLEN];

            priv_set_pair_state (agent, p, NICE_CHECK_FAILED);
            GST_DEBUG_OBJECT (agent, "s/c:%u/%u conncheck %p(%s) FAILED"
                " (mismatch of source address).",
                stream->id, component->id, p, p->foundation);
            nice_address_to_string (&p->remote->addr, tmpbuf);
            nice_address_to_string (from, tmpbuf2);
            GST_DEBUG_OBJECT (agent, "%u/%u: '%s:%u' != '%s:%u'",
                stream->id, component->id,
                tmpbuf, nice_address_get_port (&p->remote->addr),
                tmpbuf2, nice_address_get_port (from));

            trans_found = TRUE;
            break;
          }

          if (res == STUN_USAGE_ICE_RETURN_NO_MAPPED_ADDRESS) {
            /*
             * Since there is no mapped address then the valid pair is the same as the pair
             * that generated the check in the first place.
             * As per Section 7.1.3.2.2 (Constructing a valid pair) we add the original
             * pair to the valid list
             * As per Section 7.1.3.2.3 (Updating pair states) we set the state of the original pair
             * to succeeded
             */
            priv_add_pair_to_valid_list (agent, stream, component, p, p);
            priv_set_pair_state (agent, p, NICE_CHECK_SUCCEEDED);
            priv_conn_check_unfreeze_related (agent, stream, p);
            valid_pair = p;
          } else {
            valid_pair = priv_process_response_check_for_peer_reflexive(agent,
                                                                        stream, component, p, sockptr, (struct sockaddr *) &sockaddr,
                                                                        remote_candidate);
          }

          /* Do not step down to CONNECTED if we're already at state READY*/
          if (component->state != NICE_COMPONENT_STATE_READY) {
            /* step: notify the client of a new component state (must be done
             *       before the possible check list state update step */
            agent_signal_component_state_change (agent,
                                                 stream->id, component->id, NICE_COMPONENT_STATE_CONNECTED);
          }

          /*
           * 7.1.3.2.4.  Updating the Nominated Flag
           */
          if (agent->controlling_mode && p->nominated) {
            valid_pair->nominated = TRUE;
          } else {
            /* JBFIXME: TODO
             *
             *  "If the agent is the controlled agent, the response may be the result
             *  of a triggered check that was sent in response to a request that
             *  itself had the USE-CANDIDATE attribute.  This case is described in
             *  Section 7.2.1.5, and may now result in setting the nominated flag for
             *  the pair learned from the original request.
             *
             * For now assume that the triggered check we sent had the use candidate set appropriately
             * so we can just copy it to the new valid pair
             */
            if (p->nominated) {
              valid_pair->nominated = TRUE;
            }
          }

          if (valid_pair->nominated == TRUE) {
            priv_update_selected_pair (agent, component, valid_pair);
          }

          /* step: update pair states (ICE 7.1.2.2.3 "Updating pair
             states" and 8.1.2 "Updating States", ID-19) */
          priv_update_check_list_state_for_ready (agent, stream, component);

          trans_found = TRUE;
        } else if (res == STUN_USAGE_ICE_RETURN_ROLE_CONFLICT) {
          /* case: role conflict error, need to restart with new role */
          GST_INFO_OBJECT (agent, "%u/%u conncheck %p(%s) ROLE CONFLICT, restarting",
              stream->id, component->id, p, p->foundation);
          /* note: our role might already have changed due to an
           * incoming request, but if not, change role now;
           * follows ICE 7.1.2.1 "Failure Cases" (ID-19) */
          priv_check_for_role_conflict (agent, !p->controlling);

          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          priv_set_pair_state (agent, p, NICE_CHECK_WAITING);
          trans_found = TRUE;
        } else {
          /* case: STUN error, the check STUN context was freed */
          GST_INFO_OBJECT (agent, "conncheck %p(%s) FAILED.", p, p->foundation);
          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          trans_found = TRUE;
        }
      }
    }
  }

  return trans_found;
}

/*
 * Tries to match STUN reply in 'buf' to an existing STUN discovery
 * transaction. If found, a reply is sent.
 *
 * @return TRUE if a matching transaction is found
 */
static gboolean priv_map_reply_to_discovery_request (NiceAgent *agent, StunMessage *resp)
{
  struct sockaddr_storage sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  struct sockaddr_storage alternate;
  socklen_t alternatelen = sizeof (sockaddr);
  GSList *i;
  StunUsageBindReturn res;
  gboolean trans_found = FALSE;
  StunTransactionId discovery_id;
  StunTransactionId response_id;
  stun_message_id (resp, response_id);

  for (i = agent->discovery_list; i && trans_found != TRUE; i = i->next) {
    CandidateDiscovery *d = i->data;

    if (d->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
        d->stun_message.buffer) {
      stun_message_id (&d->stun_message, discovery_id);

      if (memcmp (discovery_id, response_id, sizeof(StunTransactionId)) == 0) {
        res = stun_usage_bind_process (resp, (struct sockaddr *) &sockaddr,
                                       &socklen, (struct sockaddr *) &alternate, &alternatelen);

        if (res == STUN_USAGE_BIND_RETURN_ALTERNATE_SERVER) {
          /* handle alternate server */
          NiceAddress niceaddr;
          nice_address_set_from_sockaddr (&niceaddr,
                                          (struct sockaddr *) &alternate);
          d->server = niceaddr;

          d->pending = FALSE;
        } else if (res == STUN_USAGE_BIND_RETURN_SUCCESS) {
          /* case: successful binding discovery, create a new local candidate */
          NiceAddress niceaddr;
          nice_address_set_from_sockaddr (&niceaddr,
                                          (struct sockaddr *) &sockaddr);

          discovery_add_server_reflexive_candidate (
                                                    d->agent,
                                                    d->stream->id,
                                                    d->component->id,
                                                    &niceaddr,
                                                    d->conncheck_nicesock,
                                                    d->transport);

          d->stun_message.buffer = NULL;
          d->stun_message.buffer_len = 0;
          d->done = TRUE;
          trans_found = TRUE;
        } else if (res == STUN_USAGE_BIND_RETURN_ERROR) {
          /* case: STUN error, the check STUN context was freed */
          d->stun_message.buffer = NULL;
          d->stun_message.buffer_len = 0;
          d->done = TRUE;
          trans_found = TRUE;
        }
      }
    }
  }

  return trans_found;
}


static CandidateRefresh *
priv_add_new_turn_refresh (CandidateDiscovery *cdisco, NiceCandidate *relay_cand,
                           guint lifetime)
{
  CandidateRefresh *cand;
  NiceAgent *agent = cdisco->agent;

  cand = g_slice_new0 (CandidateRefresh);
  agent->refresh_list = g_slist_append (agent->refresh_list, cand);

  cand->nicesock = cdisco->nicesock;
  cand->relay_socket = relay_cand->sockptr;
  cand->server = cdisco->server;
  cand->turn = cdisco->turn;
  cand->stream = cdisco->stream;
  cand->component = cdisco->component;
  cand->agent = cdisco->agent;
  memcpy (&cand->stun_agent, &cdisco->stun_agent, sizeof(StunAgent));

  /* Use previous stun response for authentication credentials */
  if (cdisco->stun_resp_msg.buffer != NULL) {
    memcpy(cand->stun_resp_buffer, cdisco->stun_resp_buffer,
           sizeof(cand->stun_resp_buffer));
    memcpy(&cand->stun_resp_msg, &cdisco->stun_resp_msg, sizeof(StunMessage));
    cand->stun_resp_msg.buffer = cand->stun_resp_buffer;
    cand->stun_resp_msg.agent = NULL;
    cand->stun_resp_msg.key = NULL;
  }

  GST_DEBUG_OBJECT (agent, "%u/%u: Adding new refresh candidate %p with timeout %d",
      cand->stream->id, cand->component->id, cand, priv_turn_lifetime_to_refresh_interval(lifetime));

  /* step: also start the refresh timer */
  /* refresh should be sent 1 minute before it expires */
  cand->timer_source =
    agent_timeout_add_with_context (agent, priv_turn_lifetime_to_refresh_interval(lifetime),
                                    priv_turn_allocate_refresh_tick, cand);

  return cand;
}

/*
 * Tries to match STUN reply in 'buf' to an existing STUN discovery
 * transaction. If found, a reply is sent.
 *
 * @return TRUE if a matching transaction is found
 */
static gboolean priv_map_reply_to_relay_request (NiceAgent *agent, StunMessage *resp, const NiceAddress* from)
{
  struct sockaddr_storage sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  struct sockaddr_storage alternate;
  socklen_t alternatelen = sizeof (alternate);
  struct sockaddr_storage relayaddr;
  socklen_t relayaddrlen = sizeof (relayaddr);
  uint32_t lifetime;
  uint32_t bandwidth;
  GSList *i;
  StunUsageTurnReturn res;
  gboolean trans_found = FALSE;
  StunTransactionId discovery_id;
  StunTransactionId response_id;
  struct sockaddr_storage server_address;
  stun_message_id (resp, response_id);

  for (i = agent->discovery_list; i && trans_found != TRUE; i = i->next) {
    CandidateDiscovery *d = i->data;

    if (d->type == NICE_CANDIDATE_TYPE_RELAYED &&
        d->stun_message.buffer) {
      stun_message_id (&d->stun_message, discovery_id);

      if (memcmp (discovery_id, response_id, sizeof(StunTransactionId)) == 0) {
        res = stun_usage_turn_process (resp,
                                       (struct sockaddr *) &relayaddr, &relayaddrlen,
                                       (struct sockaddr *) &sockaddr, &socklen,
                                       (struct sockaddr *) &alternate, &alternatelen,
                                       &bandwidth, &lifetime, agent_to_turn_compatibility (agent));

        nice_address_copy_to_sockaddr(from, (struct sockaddr *)&server_address);
        stun_message_log(resp, FALSE, (struct sockaddr *)&server_address);

        if (res == STUN_USAGE_TURN_RETURN_ALTERNATE_SERVER) {
          /* handle alternate server */
          nice_address_set_from_sockaddr (&d->server,
                                          (struct sockaddr *) &alternate);
          nice_address_set_from_sockaddr (&d->turn->server,
                                          (struct sockaddr *) &alternate);

          d->pending = FALSE;
        } else if (res == STUN_USAGE_TURN_RETURN_RELAY_SUCCESS ||
                   res == STUN_USAGE_TURN_RETURN_MAPPED_SUCCESS) {
          /* case: successful allocate, create a new local candidate */
          NiceAddress niceaddr;
          NiceCandidate *relay_cand;

          /* Server reflexive candidates are only valid for UDP sockets */
          if (res == STUN_USAGE_TURN_RETURN_MAPPED_SUCCESS &&
              !nice_socket_is_reliable (d->nicesock)) {
            /* We also received our mapped address */
            nice_address_set_from_sockaddr (&niceaddr,
                                            (struct sockaddr *) &sockaddr);

            discovery_add_server_reflexive_candidate (
                                                      d->agent,
                                                      d->stream->id,
                                                      d->component->id,
                                                      &niceaddr,
                                                      d->nicesock,
                                                      d->transport);

            if (d->component->enable_tcp_active) {
              /*
               * Also add a tcp active server reflexive candidate with the same mapped address
               */
              GSList *i;

              for (i = d->component->local_candidates; i; i = i->next) {
                NiceCandidate* cand = i->data;

                if (cand->type == NICE_CANDIDATE_TYPE_HOST &&
                    cand->transport == NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE &&
                    nice_address_equal_full (&cand->base_addr, &d->nicesock->addr, FALSE)) {
                  GST_DEBUG_OBJECT (agent, "%u/%u: Adding TCP active srflx candidate %u/%u",
                      d->stream->id, d->component->id, cand->stream_id, cand->component_id);
                  discovery_add_server_reflexive_candidate (
                                                            d->agent,
                                                            d->stream->id,
                                                            d->component->id,
                                                            &niceaddr,
                                                            cand->sockptr,
                                                            NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE);
                }
              }
            }
          }

          nice_address_set_from_sockaddr (&niceaddr,
                                          (struct sockaddr *) &relayaddr);
          relay_cand = discovery_add_relay_candidate (
                                                      d->agent,
                                                      d->stream->id,
                                                      d->component->id,
                                                      &niceaddr,
                                                      d->nicesock,
                                                      d->turn);

          if (relay_cand) {
            priv_add_new_turn_refresh (d, relay_cand, lifetime);
            if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2) {
              /* These data are needed on TURN socket when sending requests,
               * but never reach nice_turn_socket_parse_recv() where it could
               * be read directly, as the socket does not exist when allocate
               * response arrives to _nice_agent_recv(). We must set them right
               * after socket gets created in discovery_add_relay_candidate(),
               * so we are doing it here. */
              nice_turn_socket_set_ms_realm(relay_cand->sockptr, &d->stun_message);
              nice_turn_socket_set_ms_connection_id(relay_cand->sockptr, resp);
            }
          }

          d->stun_message.buffer = NULL;
          d->stun_message.buffer_len = 0;
          d->done = TRUE;
          trans_found = TRUE;
        } else if (res == STUN_USAGE_TURN_RETURN_ERROR) {
          int code = -1;
          uint8_t *sent_realm = NULL;
          uint8_t *recv_realm = NULL;
          uint16_t sent_realm_len = 0;
          uint16_t recv_realm_len = 0;

          sent_realm = (uint8_t *) stun_message_find (&d->stun_message,
                                                      STUN_ATTRIBUTE_REALM, &sent_realm_len);
          recv_realm = (uint8_t *) stun_message_find (resp,
                                                      STUN_ATTRIBUTE_REALM, &recv_realm_len);

          /* check for unauthorized error response */
          if ((agent->compatibility == NICE_COMPATIBILITY_RFC5245 ||
               agent->compatibility == NICE_COMPATIBILITY_OC2007R2) &&
              stun_message_get_class (resp) == STUN_ERROR &&
              stun_message_find_error (resp, &code) ==
              STUN_MESSAGE_RETURN_SUCCESS &&
              recv_realm != NULL && recv_realm_len > 0) {

            if (code == 438 ||
                (code == 401 &&
                 !(recv_realm_len == sent_realm_len &&
                   sent_realm != NULL &&
                   memcmp (sent_realm, recv_realm, sent_realm_len) == 0))) {
              d->stun_resp_msg = *resp;
              memcpy (d->stun_resp_buffer, resp->buffer,
                      stun_message_length (resp));
              d->stun_resp_msg.buffer = d->stun_resp_buffer;
              d->stun_resp_msg.buffer_len = sizeof(d->stun_resp_buffer);
              d->pending = FALSE;
            } else {
              agent_signal_turn_allocation_failure(d->agent,
                                                   d->stream->id,
                                                   d->component->id,
                                                   from,
                                                   resp, "");
              /* case: a real unauthorized error */
              d->stun_message.buffer = NULL;
              d->stun_message.buffer_len = 0;
              d->done = TRUE;
            }
          } else {
            agent_signal_turn_allocation_failure(d->agent,
                                                 d->stream->id,
                                                 d->component->id,
                                                 from,
                                                 resp, "");

            /* case: STUN error, the check STUN context was freed */
            d->stun_message.buffer = NULL;
            d->stun_message.buffer_len = 0;
            d->done = TRUE;
          }
          trans_found = TRUE;
        }
      }
    }
  }

  return trans_found;
}

/*
 * Tries to match STUN reply in 'buf' to an existing STUN discovery
 * transaction. If found, a reply is sent.
 *
 * @return TRUE if a matching transaction is found
 */
static gboolean priv_map_reply_to_relay_refresh (NiceAgent *agent, StunMessage *resp, const NiceAddress* from)
{
  uint32_t lifetime;
  GSList *i;
  StunUsageTurnReturn res;
  gboolean trans_found = FALSE;
  struct sockaddr_storage server_address;
  StunTransactionId refresh_id;
  StunTransactionId response_id;
  stun_message_id (resp, response_id);

  for (i = agent->refresh_list; i && trans_found != TRUE; i = i->next) {
    CandidateRefresh *cand = i->data;

    if (cand->stun_message.buffer) {
      stun_message_id (&cand->stun_message, refresh_id);

      if (memcmp (refresh_id, response_id, sizeof(StunTransactionId)) == 0) {
        res = stun_usage_turn_refresh_process (resp,
                                               &lifetime, agent_to_turn_compatibility (cand->agent));

        nice_address_copy_to_sockaddr(from, (struct sockaddr *)&server_address);
        stun_message_log(resp, FALSE, (struct sockaddr *)&server_address);

        if (res == STUN_USAGE_TURN_RETURN_RELAY_SUCCESS) {
          /* refresh should be sent 1 minute before it expires */
          cand->timer_source =
            agent_timeout_add_with_context (cand->agent, priv_turn_lifetime_to_refresh_interval(lifetime),
                                            priv_turn_allocate_refresh_tick, cand);

          g_source_destroy (cand->tick_source);
          g_source_unref (cand->tick_source);
          cand->tick_source = NULL;
        } else if (res == STUN_USAGE_TURN_RETURN_ERROR) {
          int code = -1;
          uint8_t *sent_realm = NULL;
          uint8_t *recv_realm = NULL;
          uint16_t sent_realm_len = 0;
          uint16_t recv_realm_len = 0;

          sent_realm = (uint8_t *) stun_message_find (&cand->stun_message,
                                                      STUN_ATTRIBUTE_REALM, &sent_realm_len);
          recv_realm = (uint8_t *) stun_message_find (resp,
                                                      STUN_ATTRIBUTE_REALM, &recv_realm_len);

          /* check for unauthorized error response */
          if (cand->agent->turn_compatibility == NICE_COMPATIBILITY_RFC5245 &&
              stun_message_get_class (resp) == STUN_ERROR &&
              stun_message_find_error (resp, &code) ==
              STUN_MESSAGE_RETURN_SUCCESS &&
              recv_realm != NULL && recv_realm_len > 0) {

            if (code == 438 ||
                (code == 401 &&
                 !(recv_realm_len == sent_realm_len &&
                   sent_realm != NULL &&
                   memcmp (sent_realm, recv_realm, sent_realm_len) == 0))) {
              cand->stun_resp_msg = *resp;
              memcpy (cand->stun_resp_buffer, resp->buffer,
                      stun_message_length (resp));
              cand->stun_resp_msg.buffer = cand->stun_resp_buffer;
              cand->stun_resp_msg.buffer_len = sizeof(cand->stun_resp_buffer);
              priv_turn_allocate_refresh_tick_unlocked (cand);
            } else {
              agent_signal_turn_allocation_failure(cand->agent,
                                                   cand->stream->id,
                                                   cand->component->id,
                                                   from,
                                                   resp,
                                                   "");
              /* case: a real unauthorized error */
              refresh_cancel (cand);
            }
          } else {
            agent_signal_turn_allocation_failure(cand->agent,
                                                 cand->stream->id,
                                                 cand->component->id,
                                                 from,
                                                 resp,
                                                 "");
            /* case: STUN error, the check STUN context was freed */
            refresh_cancel (cand);
          }
          trans_found = TRUE;
        }
      }
    }
  }

  return trans_found;
}


static gboolean priv_map_reply_to_keepalive_conncheck (NiceAgent *agent,
                                                       Component *component, StunMessage *resp)
{
  StunTransactionId conncheck_id;
  StunTransactionId response_id;
  stun_message_id (resp, response_id);

  if (component->selected_pair.keepalive.stun_message.buffer) {
    stun_message_id (&component->selected_pair.keepalive.stun_message,
                     conncheck_id);
    if (memcmp (conncheck_id, response_id, sizeof(StunTransactionId)) == 0) {
      GST_DEBUG_OBJECT (agent, "%u/%u: Keepalive for selected pair received.",
          component->selected_pair.local->stream_id, component->id);
      if (component->selected_pair.keepalive.tick_source) {
        g_source_destroy (component->selected_pair.keepalive.tick_source);
        g_source_unref (component->selected_pair.keepalive.tick_source);
        component->selected_pair.keepalive.tick_source = NULL;
      }
      component->selected_pair.keepalive.stun_message.buffer = NULL;
      return TRUE;
    }
  }

  return FALSE;
}


typedef struct {
  NiceAgent *agent;
  Stream *stream;
  Component *component;
  uint8_t *password;
} conncheck_validater_data;

static bool conncheck_stun_validater (StunAgent *agent,
                                      StunMessage *message, uint8_t *username, uint16_t username_len,
                                      uint8_t **password, size_t *password_len, void *user_data)
{
  conncheck_validater_data *data = (conncheck_validater_data*) user_data;
  GSList *i;
  gchar *ufrag = NULL;
  gsize ufrag_len;

  i = data->component->local_candidates;

  for (; i; i = i->next) {
    NiceCandidate *cand = i->data;

    ufrag = NULL;
    if (cand->username)
      ufrag = cand->username;
    else if (data->stream)
      ufrag = data->stream->local_ufrag;
    ufrag_len = ufrag? strlen (ufrag) : 0;

    if (ufrag == NULL)
      continue;

    if (ufrag_len > 0 && username_len >= ufrag_len &&
        memcmp (username, ufrag, ufrag_len) == 0) {
      gchar *pass = NULL;

      if (cand->password)
        pass = cand->password;
      else if(data->stream->local_password[0])
        pass = data->stream->local_password;

      if (pass) {
        *password = (uint8_t *) pass;
        *password_len = strlen (pass);

      }

      return TRUE;
    }
  }

  return FALSE;
}

static StunAgent* priv_find_stunagent_for_message (NiceAgent *agent, Stream *stream,
                                                   Component *component, NiceSocket *socket,
                                                   const NiceAddress *from, gchar *buf, guint len)
{
  GSList *i;
  StunMethod method = stun_get_type ((uint8_t *)buf);
  StunTransactionId msg_id;
  gchar fromstr[INET6_ADDRSTRLEN];

  nice_address_to_string (from, fromstr);

  /*
   * If the incoming message is a response (or an error) then we must have a matching
   * transaction ID in one of our existing stun agents. All requests and indications must
   * come from the remote UA and hence should use the global stun agent
   */
  switch (stun_get_class ((uint8_t *)buf)) {
  case STUN_ERROR:
  case STUN_RESPONSE:
    if (stun_get_transaction_id ((uint8_t *)buf, len, msg_id)) {
      if (stun_agent_find_transaction (&agent->stun_agent, method, msg_id)) {
        GST_DEBUG_OBJECT (agent, "%u/%u: inbound STUN response from [%s]:%u (%u octets) matches global stun agent:",
            stream->id, component->id,
            fromstr, nice_address_get_port (from), len);
        return &agent->stun_agent;
      }

      for (i = agent->discovery_list; i; i = i->next)
      {
        CandidateDiscovery *d = i->data;
        if (stun_agent_find_transaction (&d->stun_agent, method, msg_id)) {
          GST_DEBUG_OBJECT (agent, "%u/%u: inbound STUN response from [%s]:%u (%u octets) matches discovery stun agent:",
              stream->id, component->id,
              fromstr, nice_address_get_port (from), len);
          return &d->stun_agent;
        }
      }

      /* Try and match against the refresh list */
      for (i = agent->refresh_list; i; i = i->next)
      {
        CandidateRefresh *r = i->data;

        if (stun_agent_find_transaction (&r->stun_agent, method, msg_id)) {
          GST_DEBUG_OBJECT (agent, "%u/%u: inbound STUN response from [%s]:%u (%u octets) matches refresh stun agent:",
              stream->id, component->id,
              fromstr, nice_address_get_port (from), len);
          return &r->stun_agent;
        }
      }

      GST_DEBUG_OBJECT (agent, "%u/%u: *** ERROR *** unmatched stun response from [%s]:%u (%u octets):",
          stream->id, component->id,
          fromstr, nice_address_get_port (from), len);
    } else {
      GST_DEBUG_OBJECT (agent, "%u/%u: *** ERROR *** no transaction ID in stun response from [%s]:%u (%u octets):",
          stream->id, component->id,
          fromstr, nice_address_get_port (from), len);
    }
    break;

  case STUN_REQUEST:
  case STUN_INDICATION:
    GST_DEBUG_OBJECT (agent, "%u/%u: inbound STUN request/indication packet from [%s]:%u (%u octets) using global stun agent:",
        stream->id, component->id,
        fromstr, nice_address_get_port (from), len);
    return &agent->stun_agent;
  }

  return NULL;
}

/*
 * Processing an incoming STUN message.
 *
 * @param agent self pointer
 * @param stream stream the packet is related to
 * @param component component the packet is related to
 * @param socket socket from which the packet was received
 * @param from address of the sender
 * @param buf message contents
 * @param buf message length
 *
 * @pre contents of 'buf' is a STUN message
 *
 * @return XXX (what FALSE means exactly?)
 */
gboolean conn_check_handle_inbound_stun (NiceAgent *agent, Stream *stream,
                                         Component *component, NiceSocket *socket, const NiceAddress *from,
                                         gchar *buf, guint len)
{
  struct sockaddr_storage sockaddr;
  uint8_t rbuf[MAX_STUN_DATAGRAM_PAYLOAD];
  ssize_t res;
  size_t rbuf_len = sizeof (rbuf);
  bool control = agent->controlling_mode;
  uint8_t *username;
  uint16_t username_len;
  StunMessage req;
  StunMessage msg;
  StunValidationStatus valid;
  conncheck_validater_data validater_data = {agent, stream, component, NULL};
  GSList *i;
  NiceCandidate *remote_candidate = NULL;
  NiceCandidateTransport remote_transport;

  nice_address_copy_to_sockaddr (from, (struct sockaddr *) &sockaddr);

  /* note: contents of 'buf' already validated, so it is
   *       a valid and fully received STUN message */

  /* note: ICE  7.2. "STUN Server Procedures" (ID-19) */
  /*
   * Find the correct stun agent to use for validation, binding requests always come from the remote
   * peer and should use the global stun agent, all other requests/responses come from the TURN server
   * and should use either a discovery agent or refresh agent for validation.
   */
  StunAgent* stunagent = priv_find_stunagent_for_message (agent, stream, component, socket, from, buf, len);

  if (stunagent == NULL) {
    /* Already logged bu priv_find_stunagent_for_message */
    return FALSE;
  }

  valid = stun_agent_validate (stunagent, &req,
                               (uint8_t *) buf, len, conncheck_stun_validater, &validater_data);

  g_free (validater_data.password);

  if (valid == STUN_VALIDATION_NOT_STUN ||
      valid == STUN_VALIDATION_INCOMPLETE_STUN ||
      valid == STUN_VALIDATION_BAD_REQUEST)
  {
    return FALSE;
  }

  if (valid == STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE) {
    GST_DEBUG_OBJECT (agent, "%u/%u: Unknown mandatory attributes in message.",
        stream->id, component->id);

    rbuf_len = stun_agent_build_unknown_attributes_error (&agent->stun_agent,
                                                          &msg, rbuf, rbuf_len, &req);
    if (rbuf_len != 0)
      nice_socket_send (socket, from, rbuf_len, (const gchar*)rbuf);
    return TRUE;
  }

  if (valid == STUN_VALIDATION_UNAUTHORIZED) {
    GST_DEBUG_OBJECT (agent, "%u/%u: Integrity check failed.",
        stream->id, component->id);

    if (stun_agent_init_error (&agent->stun_agent, &msg, rbuf, rbuf_len,
                               &req, STUN_ERROR_UNAUTHORIZED)) {
      rbuf_len = stun_agent_finish_message (&agent->stun_agent, &msg, NULL, 0);
      if (rbuf_len > 0)
        nice_socket_send (socket, from, rbuf_len, (const gchar*)rbuf);
    }
    return TRUE;
  }
  if (valid == STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST) {
    GST_DEBUG_OBJECT (agent, "%u/%u: Integrity check failed.",
        stream->id, component->id);
    if (stun_agent_init_error (&agent->stun_agent, &msg, rbuf, rbuf_len,
                               &req, STUN_ERROR_BAD_REQUEST)) {
      rbuf_len = stun_agent_finish_message (&agent->stun_agent, &msg, NULL, 0);
      if (rbuf_len > 0)
        nice_socket_send (socket, from, rbuf_len, (const gchar*)rbuf);
    }
    return TRUE;
  }

  username = (uint8_t *) stun_message_find (&req, STUN_ATTRIBUTE_USERNAME,
                                            &username_len);

  /*
   * Try and find a matching remote candidate. Infer the remote
   * candidate transport type based on the local socket type
   */
  switch (socket->type) {
  case NICE_SOCKET_TYPE_TCP_ACTIVE:
    remote_transport = NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
    break;

  case NICE_SOCKET_TYPE_TCP_PASSIVE:
    remote_transport = NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
    break;

  default:
    remote_transport = NICE_CANDIDATE_TRANSPORT_UDP;
  }

  for (i = component->remote_candidates; i; i = i->next) {
    NiceCandidate *cand = i->data;

    if (nice_address_equal (from, &cand->addr) &&
        cand->transport == remote_transport) {
      remote_candidate = cand;
      break;
    }
  }

  if (valid != STUN_VALIDATION_SUCCESS) {
    GST_DEBUG_OBJECT (agent, "%u/%u: STUN message is unsuccessfull %d, ignoring", stream->id, component->id, valid);
    return FALSE;
  }


  if (stun_message_get_class (&req) == STUN_REQUEST) {
    rbuf_len = sizeof (rbuf);
    res = stun_usage_ice_conncheck_create_reply (&agent->stun_agent, &req,
                                                 &msg, rbuf, &rbuf_len, (struct sockaddr *) &sockaddr, sizeof (sockaddr),
                                                 &control, agent->tie_breaker,
                                                 agent_to_ice_compatibility (agent));

    if (res == STUN_USAGE_ICE_RETURN_ROLE_CONFLICT)
      priv_check_for_role_conflict (agent, control);

    if (res == STUN_USAGE_ICE_RETURN_SUCCESS ||
        res == STUN_USAGE_ICE_RETURN_ROLE_CONFLICT) {
      /* case 1: valid incoming request, send a reply/error */
      bool use_candidate = stun_usage_ice_conncheck_use_candidate (&req);
      uint32_t priority = stun_usage_ice_conncheck_priority (&req);

      if (stream->initial_binding_request_received != TRUE)
        agent_signal_initial_binding_request_received (agent, stream);

      if (component->remote_candidates && remote_candidate == NULL) {
        /*
         * 7.2.1.3.  Learning Peer Reflexive Candidates
         */
        GST_DEBUG_OBJECT (agent, "%u/%u: No matching remote candidate for incoming check -> peer-reflexive candidate.",
            stream->id, component->id);
        remote_candidate = discovery_learn_remote_peer_reflexive_candidate (agent, stream, component, priority, from, socket,
                                                                            remote_candidate);
      }

      priv_reply_to_conn_check (agent, stream, component, remote_candidate,
                                from, socket, rbuf_len, rbuf, use_candidate);


      if (component->remote_candidates == NULL) {
        /* case: We've got a valid binding request to a local candidate
         *       but we do not yet know remote credentials nor
         *       candidates. As per sect 7.2 of RFC 5245, we send a reply
         *       immediately but postpone all other processing until
         *       we get information about the remote candidates */

        /* step: send a reply immediately but postpone other processing */
        priv_store_pending_check (agent, stream, component, from, socket,
                                  username, username_len, priority, use_candidate);
      }
    } else {
      GST_DEBUG_OBJECT (agent, "%u/%u: Invalid STUN packet, ignoring... %s",
          stream->id, component->id, strerror(errno));
      return FALSE;
    }
  } else {
    /* case 2: not a new request, might be a reply...  */
    gboolean trans_found = FALSE;

    /* note: ICE sect 7.1.2. "Processing the Response" (ID-19) */

    /* step: let's try to match the response to an existing check context */
    if (trans_found != TRUE)
      trans_found = priv_map_reply_to_conn_check_request (agent, stream,
                                                          component, socket, from, remote_candidate, &req);

    /* step: let's try to match the response to an existing discovery */
    if (trans_found != TRUE)
      trans_found = priv_map_reply_to_discovery_request (agent, &req);

    /* step: let's try to match the response to an existing turn allocate */
    if (trans_found != TRUE)
      trans_found = priv_map_reply_to_relay_request (agent, &req, from);

    /* step: let's try to match the response to an existing turn refresh */
    if (trans_found != TRUE)
      trans_found = priv_map_reply_to_relay_refresh (agent, &req, from);

    /* step: let's try to match the response to an existing keepalive conncheck */
    if (trans_found != TRUE)
      trans_found = priv_map_reply_to_keepalive_conncheck (agent, component,
                                                           &req);

    if (trans_found != TRUE)
      GST_DEBUG_OBJECT (agent, "%u/%u: Unable to match to an existing transaction, "
          "probably a keepalive.",
          stream->id, component->id);
  }

  return TRUE;
}
