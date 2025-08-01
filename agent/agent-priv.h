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
 *   Dafydd Harries, Collabora Ltd.
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

#ifndef _NICE_AGENT_PRIV_H
#define _NICE_AGENT_PRIV_H

/* note: this is a private header part of agent.h */


#ifdef HAVE_CONFIG_H
# include <config.h>
#else
#define NICEAPI_EXPORT
#endif

#include <glib.h>

#include "agent.h"
#include "socket.h"
#include "candidate.h"
#include "stream.h"
#include "conncheck.h"
#include "component.h"
#include "stun/stunagent.h"
#include "stun/usages/turn.h"
#include "stun/usages/ice.h"

/* XXX: starting from ICE ID-18, Ta SHOULD now be set according
 *      to session bandwidth -> this is not yet implemented in NICE */

#define NICE_AGENT_TIMER_TA_DEFAULT 20      /* timer Ta, msecs (impl. defined) */
#define NICE_AGENT_TIMER_TR_DEFAULT 25000   /* timer Tr, msecs (impl. defined) */
#define NICE_AGENT_TIMER_TR_MIN     15000   /* timer Tr, msecs (ICE ID-19) */
#define NICE_AGENT_MAX_CONNECTIVITY_CHECKS_DEFAULT 80 /* see spec 5.7.3 RFC 5245 and 3.1.4.8.2.1 of MS-ICE2.
                                                         We use the lower of the two suggested limits */
#define NICE_AGENT_REGULAR_NOMINATION_TIMEOUT_DEFAULT 3000

/* An upper limit to size of STUN packets handled (based on Ethernet
 * MTU and estimated typical sizes of ICE STUN packet */
#define MAX_STUN_DATAGRAM_PAYLOAD    1300

#define NICE_COMPONENT_MAX_VALID_CANDIDATES 50 /* maximum number of validates remote candidates to keep, the number is arbitrary but hopefully large enough */

struct _NiceAgent
{
  GObject parent;                 /* gobject pointer */

  gint agent_mutex_count;
  GThread *agent_mutex_th;
  GRecMutex agent_mutex;          /* Mutex used for thread-safe lib */

  GQueue *reliable_transport_events;
  GSource *event_source;

  gboolean full_mode;             /* property: full-mode */
  GTimeVal next_check_tv;         /* property: next conncheck timestamp */
  gchar *stun_server_ip;          /* property: STUN server IP */
  guint stun_server_port;         /* property: STUN server port */
  gchar *proxy_ip;                /* property: Proxy server IP */
  guint proxy_port;               /* property: Proxy server port */
  NiceProxyType proxy_type;       /* property: Proxy type */
  gchar *proxy_username;          /* property: Proxy username */
  gchar *proxy_password;          /* property: Proxy password */
  gboolean controlling_mode;      /* property: controlling-mode */
  guint timer_ta;                 /* property: timer Ta */
  guint max_conn_checks;          /* property: max connectivity checks */
  guint conncheck_timeout;        /* property: initial retransmission interval for connectivity checks */
  guint conncheck_retransmissions; /* property: maximum number of retransmissions for connectivity checks */
  gboolean aggressive_mode;        /* property: use aggressive nomination when controller */
  guint regular_nomination_timeout; /* property: timeout (ms) before regular nomination starts nominating non-optimal media paths */

  GSList *local_addresses;        /* list of NiceAddresses for local
                                     interfaces */
  GSList *streams;                /* list of Stream objects */
  GMainContext *main_context;     /* main context pointer */
  guint next_candidate_id;        /* id of next created candidate */
  guint next_stream_id;           /* id of next created candidate */
  NiceRNG *rng;                   /* random number generator */
  GSList *discovery_list;         /* list of CandidateDiscovery items */
  guint discovery_unsched_items;  /* number of discovery items unscheduled */
  GSource *discovery_timer_source; /* source of discovery timer */
  GSource *conncheck_timer_source; /* source of conncheck timer */
  GSource *keepalive_timer_source; /* source of keepalive timer */
  GSList *refresh_list;         /* list of CandidateRefresh items */
  guint64 tie_breaker;            /* tie breaker (ICE sect 5.2
                                     "Determining Role" ID-19) */
  gboolean override_tie_breaker;
  NiceCompatibility compatibility; /* property: Compatibility mode */
  NiceCompatibility turn_compatibility; /* property: TURN server compatibility mode */
  StunAgent stun_agent;            /* STUN agent */
  gboolean media_after_tick;       /* Received media after keepalive tick */
  gchar *software_attribute;       /* SOFTWARE attribute */
  gboolean reliable;               /* property: reliable */
  /* XXX: add pointer to internal data struct for ABI-safe extensions */
};

gboolean
agent_find_component (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  Stream **stream,
  Component **component);

Stream *agent_find_stream (NiceAgent *agent, guint stream_id);

void agent_gathering_done (NiceAgent *agent);
void agent_signal_gathering_done (NiceAgent *agent);

void agent_lock (NiceAgent *agent);
void agent_unlock (NiceAgent *agent);

void agent_signal_new_selected_pair (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidate *lcandidate,
  NiceCandidate *rcandidate);

void agent_signal_component_state_change (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceComponentState state);

void agent_signal_turn_allocation_failure (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  const NiceAddress* relay_addr,
  const NiceRelayType* relay_type,
  const StunMessage* response,
  const char *reason);

void agent_signal_new_candidate (
  NiceAgent *agent,
  Stream * stream,
  Component * component,
  NiceCandidate *candidate);

void agent_signal_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate);

void agent_signal_initial_binding_request_received (NiceAgent *agent, Stream *stream);

guint64 agent_candidate_pair_priority (NiceAgent *agent, NiceCandidate *local, NiceCandidate *remote);

GSource *agent_timeout_add_with_context (NiceAgent *agent, guint interval, GSourceFunc function, gpointer data);

void agent_attach_stream_component_socket (NiceAgent *agent,
    Stream *stream,
    Component *component,
    NiceSocket *socket);

StunUsageIceCompatibility agent_to_ice_compatibility (NiceAgent *agent);
StunUsageTurnCompatibility agent_to_turn_compatibility (NiceAgent *agent);
NiceTurnSocketCompatibility agent_to_turn_socket_compatibility (NiceAgent *agent);

void _priv_set_socket_tos (NiceAgent *agent, NiceSocket *sock, gint tos);
void nice_agent_socket_rx_cb (NiceSocket* socket, NiceAddress* from, gchar* buf, gint len, gpointer userdata);
void nice_agent_socket_tx_cb (NiceSocket* socket, gchar* buf, gint len, gsize queued, gpointer userdata);

guint32 agent_candidate_ice_priority (NiceAgent* agent, const NiceCandidate *candidate, NiceCandidateType type);

#endif /*_NICE_AGENT_PRIV_H */
