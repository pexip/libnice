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

/*
 * @file discovery.c
 * @brief ICE candidate discovery functions
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <glib.h>
#include <gst/gst.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "debug.h"

#include "agent.h"
#include "agent-priv.h"
#include "component.h"
#include "discovery.h"
#include "stun/usages/bind.h"
#include "stun/usages/turn.h"
#include "socket.h"

GST_DEBUG_CATEGORY_EXTERN (niceagent_debug);
#define GST_CAT_DEFAULT niceagent_debug

static inline int priv_timer_expired (GTimeVal *timer, GTimeVal *now)
{
  return (now->tv_sec == timer->tv_sec) ?
    now->tv_usec >= timer->tv_usec :
    now->tv_sec >= timer->tv_sec;
}

/*
 * Frees the CandidateDiscovery structure pointed to
 * by 'user data'. Compatible with g_slist_foreach().
 */
void discovery_free_item (gpointer data, gpointer user_data)
{
  CandidateDiscovery *cand = data;
  g_assert (user_data == NULL);
  g_free (cand->msn_turn_username);
  g_free (cand->msn_turn_password);
  g_slice_free (CandidateDiscovery, cand);
}

/*
 * Frees all discovery related resources for the agent.
 */
void discovery_free (NiceAgent *agent)
{

  g_slist_foreach (agent->discovery_list, discovery_free_item, NULL);
  g_slist_free (agent->discovery_list);
  agent->discovery_list = NULL;
  agent->discovery_unsched_items = 0;

  if (agent->discovery_timer_source != NULL) {
    g_source_destroy (agent->discovery_timer_source);
    g_source_unref (agent->discovery_timer_source);
    agent->discovery_timer_source = NULL;
  }
}

/*
 * Prunes the list of discovery processes for items related
 * to stream 'stream_id'.
 *
 * @return TRUE on success, FALSE on a fatal error
 */
void discovery_prune_stream (NiceAgent *agent, guint stream_id)
{
  GSList *i;

  for (i = agent->discovery_list; i ; ) {
    CandidateDiscovery *cand = i->data;
    GSList *next = i->next;

    if (cand->stream->id == stream_id) {
      agent->discovery_list = g_slist_remove (agent->discovery_list, cand);
      discovery_free_item (cand, NULL);
    }
    i = next;
  }

  if (agent->discovery_list == NULL) {
    /* noone using the timer anymore, clean it up */
    discovery_free (agent);
  }
}


/*
 * Frees the CandidateDiscovery structure pointed to
 * by 'user data'. Compatible with g_slist_foreach().
 */
void refresh_free_item (gpointer data, gpointer user_data)
{
  CandidateRefresh *cand = data;
  NiceAgent *agent = cand->agent;
  uint8_t *username;
  size_t username_len;
  uint8_t *password;
  size_t password_len;
  size_t buffer_len = 0;
  StunUsageTurnCompatibility turn_compat = agent_to_turn_compatibility (agent);

  g_assert (user_data == NULL);

  if (cand->timer_source != NULL) {
    g_source_destroy (cand->timer_source);
    g_source_unref (cand->timer_source);
    cand->timer_source = NULL;
  }
  if (cand->tick_source != NULL) {
    g_source_destroy (cand->tick_source);
    g_source_unref (cand->tick_source);
    cand->tick_source = NULL;
  }

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
      cand->stun_resp_msg.buffer == NULL ? NULL : &cand->stun_resp_msg, 0,
      username, username_len,
      password, password_len,
      agent_to_turn_compatibility (agent));

  if (buffer_len > 0) {
    StunTransactionId id;
    struct sockaddr_storage server_address;

    /* forget the transaction since we don't care about the result and
     * we don't implement retransmissions/timeout */
    stun_message_id (&cand->stun_message, id);
    stun_agent_forget_transaction (&cand->stun_agent, id);

    nice_address_copy_to_sockaddr(&cand->server, (struct sockaddr *)&server_address);
    stun_message_log(&cand->stun_message, TRUE, (struct sockaddr *)&server_address);

    /* send the refresh twice since we won't do retransmissions */
    nice_socket_send (cand->nicesock, &cand->server,
        buffer_len, (gchar *)cand->stun_buffer);
    if (!nice_socket_is_reliable (cand->nicesock)) {
      nice_socket_send (cand->nicesock, &cand->server,
          buffer_len, (gchar *)cand->stun_buffer);
    }

  }

  if (turn_compat == STUN_USAGE_TURN_COMPATIBILITY_MSN ||
      turn_compat == STUN_USAGE_TURN_COMPATIBILITY_OC2007) {
    g_free (username);
    g_free (password);
  }

  g_slice_free (CandidateRefresh, cand);
}

/*
 * Frees all discovery related resources for the agent.
 */
void refresh_free (NiceAgent *agent)
{
  g_slist_foreach (agent->refresh_list, refresh_free_item, NULL);
  g_slist_free (agent->refresh_list);
  agent->refresh_list = NULL;
}

/*
 * Prunes the list of discovery processes for items related
 * to stream 'stream_id'.
 *
 * @return TRUE on success, FALSE on a fatal error
 */
void refresh_prune_stream (NiceAgent *agent, guint stream_id)
{
  GSList *i;

  for (i = agent->refresh_list; i ;) {
    CandidateRefresh *cand = i->data;
    GSList *next = i->next;

    if (cand->stream->id == stream_id) {
      agent->refresh_list = g_slist_remove (agent->refresh_list, cand);
      refresh_free_item (cand, NULL);
    }

    i = next;
  }

}

void refresh_cancel (CandidateRefresh *refresh)
{
  refresh->agent->refresh_list = g_slist_remove (refresh->agent->refresh_list,
      refresh);
  refresh_free_item (refresh, NULL);
}

static void priv_set_candidate_priority (NiceAgent* agent, Component* component, NiceCandidate* candidate)
{
  candidate->priority = agent_candidate_ice_priority (agent, candidate, candidate->type);
}

/*
 * Adds a new local candidate. Implements the candidate pruning
 * defined in ICE spec section 4.1.3 "Eliminating Redundant
 * Candidates" (ID-19).
 */
static gboolean priv_add_local_candidate_pruned (NiceAgent *agent, guint stream_id, Component *component, NiceCandidate *candidate, gboolean pair_with_remotes)
{
  GSList *i;

  for (i = component->local_candidates; i ; i = i->next) {
    NiceCandidate *c = i->data;

    if (c->transport == candidate->transport) {
      /* For TCP active candidates the port number is meaningless so ignore it */
      gboolean compare_ports = (c->transport != NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE || candidate->type != NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);

      if (nice_address_equal_full (&c->base_addr, &candidate->base_addr, compare_ports) &&
          nice_address_equal_full (&c->addr, &candidate->addr, compare_ports)) {
        GST_DEBUG_OBJECT (agent, "%u/%u: Candidate %p redundant, ignoring.", stream_id, component->id, candidate);
        return FALSE;
      }

      /*
       * Special case for server reflexive candidates. Although we should include two UDP server
       * reflexive candidates if they have the same address but different ports doing so upsets
       * some endpoints (notably Lync). As having two server reflexives with the same address is
       * pointless in any real network scenario we'll prune them here
       */
      if (c->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
          candidate->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
          nice_address_equal_full (&c->base_addr, &candidate->base_addr, FALSE) &&
          nice_address_equal_full (&c->addr, &candidate->addr, FALSE)) {
        gchar addrstr[INET6_ADDRSTRLEN];
        nice_address_to_string (&c->addr, addrstr);

        GST_DEBUG_OBJECT (agent, "%u/%u: Pruning duplicate server reflexive candidate for srflx address %s (%s %s)",
            stream_id, component->id, addrstr, candidate->foundation, c->foundation);
        return FALSE;
      }

      if (c->type == NICE_CANDIDATE_TYPE_RELAYED &&
          candidate->type == NICE_CANDIDATE_TYPE_RELAYED &&
          nice_address_equal_full (&c->addr, &candidate->addr, FALSE) &&
          c->turn && candidate->turn && c->turn->type == candidate->turn->type) {

        gchar addrstr[INET6_ADDRSTRLEN];
        nice_address_to_string (&c->addr, addrstr);

        GST_DEBUG_OBJECT (agent, "%u/%u: Pruning duplicate relay reflexive candidate for relay address %s (%s %s) turn-type:%d",
            stream_id, component->id, addrstr, candidate->foundation, c->foundation, c->turn->type);

#if AGENT_EXTENDED_TURN_CANDIDATE_LOGGING
        gchar * candidate_s = nice_candidate_to_string(candidate);
        GST_ERROR("TURN-PRUNE: %s", candidate_s);
        g_free(candidate_s);
#endif
        return FALSE;          
      }
    }
  }

  component->local_candidates = g_slist_append (component->local_candidates,
      candidate);
  if (pair_with_remotes) {
    conn_check_add_for_local_candidate(agent, stream_id, component, candidate);
  }

  return TRUE;
}

static guint priv_highest_remote_foundation (Component *component)
{
  GSList *i;
  guint highest;
  gchar foundation[NICE_CANDIDATE_MAX_FOUNDATION];

  /*
   * We are trying to find an unused foundation from the remote candidates.
   * Starting at 1 was not sensible when we were creating remote candidates
   * before receiving an answer as it would immediately causes a clash with
   * the foundation values supplied by the remote.
   *
   * FIXME: This is only assigning a foundation that is unique to this component.
   * it should really be unique across all remote candidates. Shouldn't really matter
   * as the foundation should be overwritten by the next offer/answer exchange (
   * according to 7.2.1.3 of RFC 5245) but it is confusing in log files.
   */
  for (highest = 100;; highest++) {
    gboolean taken = FALSE;

    g_snprintf (foundation, NICE_CANDIDATE_MAX_FOUNDATION, "%u", highest);
    for (i = component->remote_candidates; i; i = i->next) {
      NiceCandidate *cand = i->data;
      if (strncmp (foundation, cand->foundation,
              NICE_CANDIDATE_MAX_FOUNDATION) == 0) {
        taken = TRUE;
        break;
      }
    }
    if (!taken)
      return highest;
  }

  g_return_val_if_reached (highest);
}

/*
 * Assings a foundation to the candidate.
 *
 * Implements the mechanism described in ICE sect
 * 4.1.1.3 "Computing Foundations" (ID-19).
 */
static void priv_assign_foundation (NiceAgent *agent, NiceCandidate *candidate)
{
  GSList *i, *j, *k;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *component = j->data;
      for (k = component->local_candidates; k; k = k->next) {
        NiceCandidate *n = k->data;
        NiceAddress temp = n->base_addr;

        /* note: candidate must not on the local candidate list */
        g_assert (candidate != n);

        /* note: ports are not to be compared */
        nice_address_set_port (&temp,
                               nice_address_get_port (&candidate->base_addr));

        /*
         * For server reflexive candidates only assign the same foundation if they have
         * the same apparent address. This is OK because we will be pruning one of them
         * later and avoids a race when STUN/TURN results are returned in a different
         * order for different components
         */
        gboolean is_srv_reflx_unique = (candidate->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE && 
                                        !nice_address_equal_full (&candidate->addr, &n->addr, FALSE));
        /*
         * For relay candidates only assign the same foundation if they have
         * the same apparent address and turn_type. This is OK because we will be pruning one of them
         * later and avoids a race when STUN/TURN results are returned in a different
         * order for different components
         */
        gboolean is_relay_unique = (candidate->type == NICE_CANDIDATE_TYPE_RELAYED &&
                                    candidate->turn != NULL && n->turn != NULL &&
                                    (candidate->turn->type != n->turn->type || 
                                    !nice_address_equal_full (&candidate->addr, &n->addr, FALSE)));

        if (candidate->type == n->type &&
            candidate->transport == n->transport &&
            nice_address_equal (&candidate->base_addr, &temp) &&
            is_srv_reflx_unique == FALSE && is_relay_unique == FALSE) {
          candidate->local_foundation = n->local_foundation;
          g_strlcpy (candidate->foundation, n->foundation,
                     NICE_CANDIDATE_MAX_FOUNDATION);
          if (n->username) {
            g_free (candidate->username);
            candidate->username = g_strdup (n->username);
          }
          if (n->password) {
            g_free (candidate->password);
            candidate->password = g_strdup (n->password);
          }
          return;
        }
      }
    }
  }

  candidate->local_foundation = agent->next_candidate_id++;
  g_snprintf (candidate->foundation, NICE_CANDIDATE_MAX_FOUNDATION,
              "%u", candidate->local_foundation);
}

static void priv_assign_remote_foundation (NiceAgent *agent, NiceCandidate *candidate)
{
  GSList *i, *j, *k;
  guint next_remote_id;
  Component *component = NULL;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    for (j = stream->components; j; j = j->next) {
      Component *c = j->data;

      if (c->id == candidate->component_id)
        component = c;

      for (k = c->remote_candidates; k; k = k->next) {
        NiceCandidate *n = k->data;
        NiceAddress temp = n->addr;

        /* note: candidate must not on the remote candidate list */
        g_assert (candidate != n);

        /* note: ports are not to be compared */
        nice_address_set_port (&temp,
                               nice_address_get_port (&candidate->base_addr));

        if (candidate->type == n->type &&
            candidate->transport == n->transport &&
            candidate->stream_id == n->stream_id &&
            nice_address_equal (&candidate->addr, &temp)) {
          /* note: currently only one STUN/TURN server per stream at a
           *       time is supported, so there is no need to check
           *       for candidates that would otherwise share the
           *       foundation, but have different STUN/TURN servers */
          g_strlcpy (candidate->foundation, n->foundation,
                     NICE_CANDIDATE_MAX_FOUNDATION);
          if (n->username) {
            g_free (candidate->username);
            candidate->username = g_strdup (n->username);
          }
          if (n->password) {
            g_free (candidate->password);
            candidate->password = g_strdup (n->password);
          }
          return;
        }
      }
    }
  }

  if (component) {
    next_remote_id = priv_highest_remote_foundation (component);
    g_snprintf (candidate->foundation, NICE_CANDIDATE_MAX_FOUNDATION,
                "%u", next_remote_id);
  }
}


/*
 * Creates a local host candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate *discovery_add_local_host_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceCandidateTransport transport)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  NiceSocket *socket = NULL;
  TcpUserData* userdata = NULL;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = *address;
  candidate->transport = transport;
  priv_assign_foundation (agent, candidate);

  /* note: candidate username and password are left NULL as stream
     level ufrag/password are used */
  switch (transport) {
  case NICE_CANDIDATE_TRANSPORT_UDP:
    socket = nice_udp_bsd_socket_new (address);
    break;

  case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
    userdata = g_new (TcpUserData, 1);
    userdata->agent = agent;
    userdata->stream = stream;
    userdata->component = component;
    socket = nice_tcp_passive_socket_new (component->ctx, address,
        nice_agent_socket_rx_cb, nice_agent_socket_tx_cb,
        (gpointer)userdata, g_free, stream->max_tcp_queue_size);
    break;

  case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
    userdata = g_new (TcpUserData, 1);
    userdata->agent = agent;
    userdata->stream = stream;
    userdata->component = component;
    socket = nice_tcp_active_socket_new (component->ctx, address,
        nice_agent_socket_rx_cb, nice_agent_socket_tx_cb,
        (gpointer)userdata, g_free, stream->max_tcp_queue_size);
    break;
  }

  if (!socket)
    goto errors;

  _priv_set_socket_tos (agent, socket, stream->tos);
  agent_attach_stream_component_socket (agent, stream,
                                        component, socket);

  candidate->sockptr = socket;
  candidate->addr = socket->addr;
  candidate->base_addr = socket->addr;

  priv_set_candidate_priority (agent, component, candidate);
  if (!priv_add_local_candidate_pruned (agent, stream_id, component, candidate, TRUE))
    goto errors;

  component->sockets = g_slist_append (component->sockets, socket);
  return candidate;

errors:
  nice_candidate_free (candidate);
  if (socket) {
    nice_socket_free (socket);
  } else if (userdata) {
    g_free (userdata);
  }
  return NULL;
}

/*
 * Creates a server reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate*
discovery_add_server_reflexive_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket,
  NiceCandidateTransport transport)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  gboolean result = FALSE;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
  candidate->transport = transport;
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;

  /* step: link to the base candidate+socket */
  candidate->sockptr = base_socket;
  candidate->base_addr = base_socket->addr;

  priv_assign_foundation (agent, candidate);

  priv_set_candidate_priority (agent, component, candidate);
  result = priv_add_local_candidate_pruned (agent, stream_id, component, candidate, TRUE);
  if (result) {
    agent_signal_new_candidate (agent, stream, component, candidate);
  }
  else {
    /* error: duplicate candidate */
    nice_candidate_free (candidate);
    candidate = NULL;
  }

  return candidate;
}


/*
 * Creates a server reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate*
discovery_add_relay_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket,
  TurnServer *turn)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  NiceSocket *relay_socket = NULL;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_RELAYED);
  candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->turn = turn;

  /* step: link to the base candidate+socket */
  relay_socket = nice_turn_socket_new (agent->main_context,
      G_OBJECT (agent), address,
      base_socket, &turn->server,
      turn->username, turn->password,
      agent_to_turn_socket_compatibility (agent));
  if (!relay_socket)
    goto errors;

  candidate->sockptr = relay_socket;
  candidate->base_addr = base_socket->addr;

  priv_assign_foundation (agent, candidate);

  priv_set_candidate_priority (agent, component, candidate);
  if (!priv_add_local_candidate_pruned (agent, stream_id, component, candidate, TRUE))
    goto errors;

  component->sockets = g_slist_append (component->sockets, relay_socket);
  agent_signal_new_candidate (agent, stream, component, candidate);

  return candidate;

errors:
  nice_candidate_free (candidate);
  if (relay_socket)
    nice_socket_free (relay_socket);
  return NULL;
}

static NiceCandidateTransport
priv_determine_local_transport(NiceCandidateTransport remote_transport)
{
  switch (remote_transport) {
  case NICE_CANDIDATE_TRANSPORT_UDP: return NICE_CANDIDATE_TRANSPORT_UDP;
  case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE: return NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
  case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE: return NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
  }
  /* Not reached */
  return NICE_CANDIDATE_TRANSPORT_UDP;
}

/*
 * Creates a peer reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate*
discovery_add_peer_reflexive_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address,
  NiceSocket *base_socket,
  NiceCandidate *local,
  NiceCandidate *remote)
{
  NiceCandidate *candidate;
  Component *component;
  Stream *stream;
  gboolean result;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);

  GST_DEBUG_OBJECT (agent, "%u/%u: remote->transport=%s remote->foundation=%s",
      stream_id, component_id, candidate_transport_to_string(remote->transport),
      remote->foundation);

  candidate->transport = priv_determine_local_transport(remote->transport);
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = base_socket->addr;

  priv_assign_foundation (agent, candidate);

  if (local) {
    g_free(candidate->username);
    g_free(candidate->password);

    candidate->username = g_strdup(local->username);
    candidate->password = g_strdup(local->password);
  }

  /* step: link to the base candidate+socket */
  candidate->sockptr = base_socket;
  candidate->base_addr = base_socket->addr;

  priv_set_candidate_priority (agent, component, candidate);
  result = priv_add_local_candidate_pruned (agent, stream_id, component, candidate, FALSE);
  if (result != TRUE) {
    /*
     * error: memory allocation, or duplicate candidate
     */
    nice_candidate_free (candidate);
    candidate = NULL;
  } else {
    GST_DEBUG_OBJECT (agent, "%u/%u: adding new local reflexive candidate, type=%s, transport=%s, foundation=%s",
        candidate->stream_id, candidate->component_id,
        candidate_type_to_string(candidate->type),
        candidate_transport_to_string(candidate->transport),
        candidate->foundation);
  }

  return candidate;
}


/*
 * Adds a new peer reflexive candidate to the list of known
 * remote candidates. The candidate is however not paired with
 * existing local candidates.
 *
 * See ICE sect 7.2.1.3 "Learning Peer Reflexive Candidates" (ID-19).
 *
 * @return pointer to the created candidate, or NULL on error
 */
NiceCandidate *discovery_learn_remote_peer_reflexive_candidate (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  guint32 priority,
  const NiceAddress *remote_address,
  NiceSocket *local_socket,
  NiceCandidate *remote)
{
  NiceCandidate *candidate;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);

  /*
   * Determine remote candidate type from the local socket on which the
   * request was received
   */
  switch (local_socket->type) {
  case NICE_SOCKET_TYPE_TCP_ACTIVE:
    candidate->transport = NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
    break;

  case NICE_SOCKET_TYPE_TCP_PASSIVE:
    candidate->transport = NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
    break;

  default:
    candidate->transport = NICE_CANDIDATE_TRANSPORT_UDP;
  }

  candidate->addr = *remote_address;
  candidate->base_addr = *remote_address;

  candidate->stream_id = stream->id;
  candidate->component_id = component->id;


  priv_assign_remote_foundation (agent, candidate);

  if (remote) {
    g_free (candidate->username);
    g_free (candidate->password);
    GST_DEBUG_OBJECT (agent, "%u/%u: creating username/password for peer-reflexive candidate %s/%s",
        stream->id, component->id,
        remote->username, remote->password);
    candidate->username = g_strdup(remote->username);
    candidate->password = g_strdup(remote->password);
  } else {
    if (component->remote_candidates) {
      NiceCandidate* first_remote = component->remote_candidates->data;
      GST_DEBUG_OBJECT (agent, "%u/%u: no remote when creating peer-reflexive, using first remote candidate username/password %s/%s",
          stream->id, component->id,
          first_remote->username, first_remote->password);
      g_free (candidate->username);
      g_free (candidate->password);
      candidate->username = g_strdup(first_remote->username);
      candidate->password = g_strdup(first_remote->password);
    } else {
      GST_DEBUG_OBJECT (agent, "%u/%u: no remote when creating peer-reflexive",
          stream->id, component->id);
    }
  }

  candidate->sockptr = NULL; /* not stored for remote candidates */
  /* note: candidate username and password are left NULL as stream
     level ufrag/password are used */

  /* if the check didn't contain the PRIORITY attribute, then the priority will
   * be 0, which is invalid... */
  if (priority != 0) {
    candidate->priority = priority;
  } else {
    priv_set_candidate_priority (agent, component, candidate);
  }

  component->remote_candidates = g_slist_append (component->remote_candidates,
      candidate);

  GST_DEBUG_OBJECT (agent, "%u/%u: adding new remote candidate, type=%s, transport=%s, foundation=%s",
      candidate->stream_id, candidate->component_id,
      candidate_type_to_string(candidate->type),
      candidate_transport_to_string(candidate->transport),
      candidate->foundation);
  agent_signal_new_remote_candidate (agent, candidate);

  return candidate;
}

/*
 * Timer callback that handles scheduling new candidate discovery
 * processes (paced by the Ta timer), and handles running of the
 * existing discovery processes.
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static gboolean priv_discovery_tick_unlocked (gpointer pointer)
{
  CandidateDiscovery *cand;
  NiceAgent *agent = pointer;
  GSList *i;
  int not_done = 0; /* note: track whether to continue timer */
  size_t buffer_len = 0;

  {
    static int tick_counter = 0;
    if (tick_counter++ % 50 == 0)
      GST_DEBUG_OBJECT (agent, "discovery tick #%d with list %p (1)", tick_counter, agent->discovery_list);
  }

  for (i = agent->discovery_list; i ; i = i->next) {
    cand = i->data;

    if (cand->pending != TRUE) {
      cand->pending = TRUE;

      if (agent->discovery_unsched_items)
	--agent->discovery_unsched_items;

      {
        gchar tmpbuf[INET6_ADDRSTRLEN];
        nice_address_to_string (&cand->server, tmpbuf);
        GST_DEBUG_OBJECT (agent, "%u/%u: discovery - scheduling cand type %u addr %s.\n",
            cand->stream->id, cand->component->id,
            cand->type, tmpbuf);
      }
      if (nice_address_is_valid (&cand->server) &&
          (cand->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
              cand->type == NICE_CANDIDATE_TYPE_RELAYED)) {

	agent_signal_component_state_change (agent,
					     cand->stream->id,
					     cand->component->id,
					     NICE_COMPONENT_STATE_GATHERING);

        if (cand->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
          buffer_len = stun_usage_bind_create (&cand->stun_agent,
              &cand->stun_message, cand->stun_buffer, sizeof(cand->stun_buffer));
        } else if (cand->type == NICE_CANDIDATE_TYPE_RELAYED) {
          uint8_t *username = (uint8_t *)cand->turn->username;
          size_t username_len = (size_t) strlen (cand->turn->username);
          uint8_t *password = (uint8_t *)cand->turn->password;
          size_t password_len = (size_t) strlen (cand->turn->password);
          StunUsageTurnCompatibility turn_compat =
              agent_to_turn_compatibility (agent);

          if (turn_compat == STUN_USAGE_TURN_COMPATIBILITY_MSN ||
              turn_compat == STUN_USAGE_TURN_COMPATIBILITY_OC2007) {
            username = g_base64_decode ((gchar *)username, &username_len);
            password = g_base64_decode ((gchar *)password, &password_len);
          }

          buffer_len = stun_usage_turn_create (&cand->stun_agent,
              &cand->stun_message,  cand->stun_buffer, sizeof(cand->stun_buffer),
              cand->stun_resp_msg.buffer == NULL ? NULL : &cand->stun_resp_msg,
              STUN_USAGE_TURN_REQUEST_PORT_NORMAL,
              -1, -1,
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

          if (buffer_len > 0) {
            struct sockaddr_storage server_address;
            nice_address_copy_to_sockaddr(&cand->server, (struct sockaddr *)&server_address);
            stun_message_log(&cand->stun_message, TRUE, (struct sockaddr *)&server_address);
          }

        }

        if (buffer_len > 0) {
          if (nice_socket_is_reliable (cand->nicesock)) {
            stun_timer_start_reliable (&cand->timer,
                STUN_TIMER_DEFAULT_RELIABLE_TIMEOUT);
          } else {
            stun_timer_start (&cand->timer, 200,
                STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
          }

          /* send the conncheck */
          nice_socket_send (cand->nicesock, &cand->server,
              buffer_len, (gchar *)cand->stun_buffer);

	  /* case: success, start waiting for the result */
	  g_get_current_time (&cand->next_tick);

	} else {
	  /* case: error in starting discovery, start the next discovery */
	  cand->done = TRUE;
	  cand->stun_message.buffer = NULL;
	  cand->stun_message.buffer_len = 0;
	  continue;
	}
      }
      else
	/* allocate relayed candidates */
	g_assert_not_reached ();

      ++not_done; /* note: new discovery scheduled */
    }

    if (cand->done != TRUE) {
      GTimeVal now;

      g_get_current_time (&now);

      if (cand->stun_message.buffer == NULL) {
	GST_DEBUG_OBJECT (agent, "%u/%u: STUN discovery was cancelled, marking discovery done.",
            cand->stream->id, cand->component->id);
	cand->done = TRUE;
      }
      else if (priv_timer_expired (&cand->next_tick, &now)) {
        switch (stun_timer_refresh (&cand->timer)) {
          case STUN_USAGE_TIMER_RETURN_TIMEOUT:
            {
              /* Time out */
              /* case: error, abort processing */
              StunTransactionId id;

              stun_message_id (&cand->stun_message, id);
              stun_agent_forget_transaction (&cand->stun_agent, id);

              cand->done = TRUE;
              cand->stun_message.buffer = NULL;
              cand->stun_message.buffer_len = 0;
              agent_signal_turn_allocation_failure(cand->agent,
                                                   cand->stream->id,
                                                   cand->component->id,
                                                   &cand->server,
                                                   cand->turn ? &cand->turn->type : NULL,
                                                   NULL,
                                                   "Discovery timed out, aborting.");
              GST_DEBUG_OBJECT (agent, "%u/%u : bind discovery timed out, aborting discovery item.",
                  cand->stream->id, cand->component->id);
              break;
            }
          case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
            {
              /* case: not ready complete, so schedule next timeout */
              unsigned int timeout = stun_timer_remainder (&cand->timer);

              stun_debug ("STUN transaction retransmitted (timeout %dms).\n",
                  timeout);

              /* retransmit */
              nice_socket_send (cand->nicesock, &cand->server,
                  stun_message_length (&cand->stun_message),
                  (gchar *)cand->stun_buffer);

              /* note: convert from milli to microseconds for g_time_val_add() */
              cand->next_tick = now;
              g_time_val_add (&cand->next_tick, timeout * 1000);

              ++not_done; /* note: retry later */
              break;
            }
          case STUN_USAGE_TIMER_RETURN_SUCCESS:
            {
              unsigned int timeout = stun_timer_remainder (&cand->timer);

              cand->next_tick = now;
              g_time_val_add (&cand->next_tick, timeout * 1000);

              ++not_done; /* note: retry later */
              break;
            }
	}

      } else {
	++not_done; /* note: discovery not expired yet */
      }
    }
  }

  if (not_done == 0) {
    GST_DEBUG_OBJECT (agent, "Candidate gathering FINISHED, stopping discovery timer.");

    discovery_free (agent);

    agent_gathering_done (agent);

    /* note: no pending timers, return FALSE to stop timer */
    return FALSE;
  }

  return TRUE;
}

static gboolean priv_discovery_tick (gpointer pointer)
{
  NiceAgent *agent = pointer;
  gboolean ret;

  agent_lock (agent);
  if (g_source_is_destroyed (g_main_current_source ())) {
    GST_DEBUG ("Source was destroyed. "
        "Avoided race condition in priv_discovery_tick");
    agent_unlock (agent);
    return FALSE;
  }

  ret = priv_discovery_tick_unlocked (pointer);
  if (ret == FALSE) {
    if (agent->discovery_timer_source != NULL) {
      g_source_destroy (agent->discovery_timer_source);
      g_source_unref (agent->discovery_timer_source);
      agent->discovery_timer_source = NULL;
    }
  }
  agent_unlock (agent);

  return ret;
}

/*
 * Initiates the candidate discovery process by starting
 * the necessary timers.
 *
 * @pre agent->discovery_list != NULL  // unsched discovery items available
 */
void discovery_schedule (NiceAgent *agent)
{
  g_assert (agent->discovery_list != NULL);

  if (agent->discovery_unsched_items > 0) {

    if (agent->discovery_timer_source == NULL) {
      /* step: run first iteration immediately */
      gboolean res = priv_discovery_tick_unlocked (agent);
      if (res == TRUE) {
        agent->discovery_timer_source = agent_timeout_add_with_context (agent, agent->timer_ta, priv_discovery_tick, agent);
      }
    }
  }
}
