/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007-2009 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
 *   Kai Vehmanen, Nokia
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

#ifndef _NICE_DISCOVERY_H
#define _NICE_DISCOVERY_H

/* note: this is a private header to libnice */

#include "stream.h"
#include "agent.h"

typedef struct
{
  NiceAgent *agent;         /**< back pointer to owner */
  NiceCandidateType type;   /**< candidate type STUN or TURN */
  NiceSocket *nicesock;  /**< XXX: should be taken from local cand: existing socket to use */
  NiceAddress server;       /**< STUN/TURN server address */
  GTimeVal next_tick;       /**< next tick timestamp */
  gboolean pending;         /**< is discovery in progress? */
  gboolean done;            /**< is discovery complete? */
  Stream *stream;
  Component *component;
  TurnServer *turn;
  StunAgent stun_agent;
  uint8_t *msn_turn_username;
  uint8_t *msn_turn_password;
  StunTimer timer;
  uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE];
  StunMessage stun_message;
  uint8_t stun_resp_buffer[STUN_MAX_MESSAGE_SIZE];
  StunMessage stun_resp_msg;
  NiceCandidateTransport transport;
  NiceSocket* conncheck_nicesock;
} CandidateDiscovery;

typedef struct
{
  NiceAgent *agent;         /**< back pointer to owner */
  NiceSocket *nicesock;     /**< existing socket to use */
  NiceSocket *relay_socket; /**< relay socket from which we receive */
  NiceAddress server;       /**< STUN/TURN server address */
  Stream *stream;
  Component *component;
  TurnServer *turn;
  StunAgent stun_agent;
  GSource *timer_source;
  GSource *tick_source;
  uint8_t *msn_turn_username;
  uint8_t *msn_turn_password;
  StunTimer timer;
  uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE];
  StunMessage stun_message;
  uint8_t stun_resp_buffer[STUN_MAX_MESSAGE_SIZE];
  StunMessage stun_resp_msg;

  /*
   * Diagnostic / robustness counters used by the TURN refresh code.
   *
   * - allocation_start_us: monotonic timestamp captured when the refresh
   *   object was created (i.e. when the Allocate succeeded). Used purely
   *   for logging "allocation age" so that disconnect-after-N-min patterns
   *   are easy to spot.
   * - refresh_count: how many Refresh requests we have sent on this
   *   allocation (including resends after 438).
   * - consecutive_stale_nonce: how many 438/401-realm-changed responses
   *   we have received in a row without an intervening success. Reset to
   *   zero on any RELAY_SUCCESS response.
   * - last_lifetime_s: lifetime (seconds) granted by the most recent
   *   successful Allocate / Refresh response.
   * - last_refresh_result: human-readable status string describing what
   *   happened to the most recent refresh attempt ("pending", "ok",
   *   "438-retry", "437-mismatch", "timeout", ...). Owned by the cand
   *   and freed on teardown.
   * - last_event_us: monotonic timestamp of the last refresh-related
   *   event (sent / response / timeout). Used by the heartbeat log.
   * - tolerate_one_timeout: when TRUE, the next retransmission timeout
   *   in priv_turn_allocate_refresh_retransmissions_tick will trigger one
   *   extra refresh attempt rather than tearing down the allocation. Set
   *   automatically after every successful refresh so that a single lost
   *   refresh does not kill the allocation.
   * - heartbeat_source: periodic timer that logs this candidate's state
   *   so that "what is libnice doing right now?" can be answered from
   *   the log alone.
   */
  gint64 allocation_start_us;
  guint refresh_count;
  guint consecutive_stale_nonce;
  guint32 last_lifetime_s;
  gchar *last_refresh_result;
  gint64 last_event_us;
  gboolean tolerate_one_timeout;
  GSource *heartbeat_source;
} CandidateRefresh;

/* How many consecutive 438 (Stale Nonce) / 401 (realm changed) responses
 * we will silently retry before declaring the allocation dead. RFC 5389
 * only mandates one retry, but real-world TURN servers (notably coturn
 * with short stale-nonce values) can rotate the nonce again between our
 * retry being sent and reaching them, so be more lenient. */
#define NICE_TURN_MAX_CONSECUTIVE_STALE_NONCE 5

/* Heartbeat interval (milliseconds) — every active CandidateRefresh
 * dumps its current state into the log this often. Set short enough
 * that the log around a failure point shows several heartbeats, but
 * not so short it floods the log of a healthy long-running call. */
#define NICE_TURN_REFRESH_HEARTBEAT_MS 30000

void refresh_free_item (gpointer data, gpointer user_data);
void refresh_free (NiceAgent *agent);
void refresh_prune_stream (NiceAgent *agent, guint stream_id);
void refresh_cancel (CandidateRefresh *refresh);


void discovery_free_item (gpointer data, gpointer user_data);
void discovery_free (NiceAgent *agent);
void discovery_prune_stream (NiceAgent *agent, guint stream_id);
void discovery_schedule (NiceAgent *agent);

NiceCandidate *
discovery_add_local_host_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceCandidateTransport transport);

NiceCandidate*
discovery_add_relay_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket,
  TurnServer *turn);

NiceCandidate* 
discovery_add_server_reflexive_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket,
  NiceCandidateTransport transport);

NiceCandidate* 
discovery_add_peer_reflexive_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket,
  NiceCandidate *local,
  NiceCandidate *remote);

NiceCandidate *
discovery_learn_remote_peer_reflexive_candidate (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  guint32 priority, 
  const NiceAddress *remote_address,
  NiceSocket *udp_socket,
  NiceCandidate *remote);

#endif /*_NICE_CONNCHECK_H */
