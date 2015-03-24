/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2010 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2010 Nokia Corporation. All rights reserved.
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


#ifdef HAVE_CONFIG_H
# include <config.h>
#else
#define NICEAPI_EXPORT
#endif

#include <glib.h>

#include <string.h>
#include <errno.h>

#ifndef G_OS_WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "debug.h"

#include "socket.h"
#include "stun/usages/turn.h"
#include "candidate.h"
#include "component.h"
#include "conncheck.h"
#include "discovery.h"
#include "agent.h"
#include "agent-priv.h"

#include "stream.h"
#include "interfaces.h"

/* This is the max size of a UDP packet
 * will it work tcp relaying??
 */
#define MAX_BUFFER_SIZE 65536
#define DEFAULT_STUN_PORT  3478
#define DEFAULT_UPNP_TIMEOUT 200

#define MAX_TCP_MTU 1400 /* Use 1400 because of VPNs and we assume IEE 802.3 */

G_DEFINE_TYPE (NiceAgent, nice_agent, G_TYPE_OBJECT);

enum
{
  PROP_COMPATIBILITY = 1,
  PROP_TURN_COMPATIBILITY,
  PROP_MAIN_CONTEXT,
  PROP_STUN_SERVER,
  PROP_STUN_SERVER_PORT,
  PROP_CONTROLLING_MODE,
  PROP_FULL_MODE,
  PROP_STUN_PACING_TIMER,
  PROP_MAX_CONNECTIVITY_CHECKS,
  PROP_PROXY_TYPE,
  PROP_PROXY_IP,
  PROP_PROXY_PORT,
  PROP_PROXY_USERNAME,
  PROP_PROXY_PASSWORD,
  PROP_UPNP,
  PROP_UPNP_TIMEOUT,
  PROP_RELIABLE,
  PROP_MAX_TCP_QUEUE_SIZE,
  PROP_CONNCHECK_TIMEOUT,
  PROP_CONNCHECK_RETRANSMISSIONS,
  PROP_AGGRESSIVE_MODE,
  PROP_REGULAR_NOMINATION_TIMEOUT
};


enum
{
  SIGNAL_COMPONENT_STATE_CHANGED,
  SIGNAL_CANDIDATE_GATHERING_DONE,
  SIGNAL_NEW_SELECTED_PAIR,
  SIGNAL_NEW_CANDIDATE,
  SIGNAL_NEW_REMOTE_CANDIDATE,
  SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED,
  SIGNAL_RELIABLE_TRANSPORT_WRITABLE,
  SIGNAL_RELIABLE_TRANSPORT_OVERFLOW,
  N_SIGNALS,
};

static guint signals[N_SIGNALS];

#if GLIB_CHECK_VERSION(2,31,8)
static GRecMutex agent_mutex;    /* Mutex used for thread-safe lib */
#else
static GStaticRecMutex agent_mutex = G_STATIC_REC_MUTEX_INIT;
#endif

static void priv_free_upnp (NiceAgent *agent);

static void nice_agent_dispose (GObject *object);
static void nice_agent_get_property (GObject *object,
  guint property_id, GValue *value, GParamSpec *pspec);
static void nice_agent_set_property (GObject *object,
  guint property_id, const GValue *value, GParamSpec *pspec);
static gboolean priv_attach_stream_component (NiceAgent *agent,
    Stream *stream, Component *component);
static void priv_detach_stream_component (Stream *stream, Component *component);


#if GLIB_CHECK_VERSION(2,31,8)
void agent_lock (void)
{
  g_rec_mutex_lock (&agent_mutex);
}

void agent_unlock (void)
{
  g_rec_mutex_unlock (&agent_mutex);
}

#else
void agent_lock(void)
{
  g_static_rec_mutex_lock (&agent_mutex);
}

void agent_unlock(void)
{
  g_static_rec_mutex_unlock (&agent_mutex);
}

#endif

/*
 * ICE 4.1.2.1. "Recommended Formula" (ID-19):
 * returns number between 1 and 0x7effffff 
 */
static guint32
priv_agent_candidate_ice_priority_full (
  // must be ∈ (0, 126) (max 2^7 - 2)
  guint type_preference,
  // must be ∈ (0, 65535) (max 2^16 - 1)
  guint local_preference,
  // must be ∈ (0, 255) (max 2 ^ 8 - 1)
  guint component_id)
{
  return (
      0x1000000 * type_preference +
      0x100 * local_preference +
      (0x100 - component_id));
}

static guint 
priv_agent_candidate_type_preference (NiceAgent* agent, NiceCandidateType type, NiceCandidateTransport transport)
{
  switch (agent->compatibility) {
  case NICE_COMPATIBILITY_OC2007R2:
    if (transport == NICE_CANDIDATE_TRANSPORT_UDP) {
      switch(type) {
      case NICE_CANDIDATE_TYPE_HOST: return NICE_CANDIDATE_OC2007R2_TYPE_PREF_HOST; 
      case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return NICE_CANDIDATE_OC2007R2_TYPE_PREF_SERVER_REFLEXIVE; 
      case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE: return NICE_CANDIDATE_OC2007R2_TYPE_PREF_PEER_REFLEXIVE;
      case NICE_CANDIDATE_TYPE_RELAYED:return NICE_CANDIDATE_OC2007R2_TYPE_PREF_RELAYED;
      }
    } else {
      switch(type) {
      case NICE_CANDIDATE_TYPE_HOST: return NICE_CANDIDATE_OC2007R2_TYPE_PREF_HOST_TCP; 
      case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return NICE_CANDIDATE_OC2007R2_TYPE_PREF_SERVER_REFLEXIVE_TCP; 
      case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE: return NICE_CANDIDATE_OC2007R2_TYPE_PREF_PEER_REFLEXIVE_TCP;
      case NICE_CANDIDATE_TYPE_RELAYED:return NICE_CANDIDATE_OC2007R2_TYPE_PREF_RELAYED_TCP;
      }
    }
    break;
    
  default:
    if (transport == NICE_CANDIDATE_TRANSPORT_UDP) {
      switch(type) {
      case NICE_CANDIDATE_TYPE_HOST: return NICE_CANDIDATE_TYPE_PREF_HOST; 
      case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE; 
      case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE: return NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE;
      case NICE_CANDIDATE_TYPE_RELAYED:return NICE_CANDIDATE_TYPE_PREF_RELAYED;
      }
    } else {
      switch(type) {
      case NICE_CANDIDATE_TYPE_HOST: return NICE_CANDIDATE_TYPE_PREF_HOST_TCP; 
      case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE_TCP; 
      case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE: return NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE_TCP;
      case NICE_CANDIDATE_TYPE_RELAYED:return NICE_CANDIDATE_TYPE_PREF_RELAYED_TCP;
      }
    }
  }

  /* Not reached */
  return NICE_CANDIDATE_TYPE_PREF_RELAYED;
}

guint32
agent_candidate_ice_priority (NiceAgent *agent, const NiceCandidate *candidate, NiceCandidateType type)
{
  guint8 type_preference = 0;
  guint other_preference = 0;
  guint direction_preference = 0;
  guint local_preference = 0;
  
  if (nice_address_is_ipv6(&candidate->base_addr)) {
    other_preference = (candidate->local_foundation << 1);
  } else {
    other_preference = (candidate->local_foundation << 1) | 1;;
  }

  type_preference = priv_agent_candidate_type_preference (agent, type, candidate->transport);
  
  switch (candidate->transport) {
  case NICE_CANDIDATE_TRANSPORT_UDP:
    direction_preference = 7; /* Always most preferred */
    break;

  case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
    if (candidate->type == NICE_CANDIDATE_TYPE_HOST ||
        candidate->type == NICE_CANDIDATE_TYPE_RELAYED) {
      direction_preference = 6;
    } else {
      direction_preference = 4;
    }
    break;

  case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
    if (candidate->type == NICE_CANDIDATE_TYPE_HOST ||
        candidate->type == NICE_CANDIDATE_TYPE_RELAYED) {
      direction_preference = 4;
    } else {
      direction_preference = 2;
    }
    break;

  }
  local_preference = (2 << 13) * direction_preference + other_preference;

  /* return _candidate_ice_priority (type_preference, 1, candidate->component_id); */
  return priv_agent_candidate_ice_priority_full (type_preference, local_preference, candidate->component_id);
}

StunUsageIceCompatibility
agent_to_ice_compatibility (NiceAgent *agent)
{
  return agent->compatibility == NICE_COMPATIBILITY_OC2007R2 ?
      STUN_USAGE_ICE_COMPATIBILITY_WLM2009 :
      STUN_USAGE_ICE_COMPATIBILITY_RFC5245;
}


StunUsageTurnCompatibility
agent_to_turn_compatibility (NiceAgent *agent)
{
  return agent->turn_compatibility == NICE_COMPATIBILITY_OC2007R2 ?
      STUN_USAGE_TURN_COMPATIBILITY_OC2007 :
      STUN_USAGE_TURN_COMPATIBILITY_RFC5766;
}

NiceTurnSocketCompatibility
agent_to_turn_socket_compatibility (NiceAgent *agent)
{
  return agent->turn_compatibility == NICE_COMPATIBILITY_OC2007R2 ?
      NICE_TURN_SOCKET_COMPATIBILITY_OC2007 :
      NICE_TURN_SOCKET_COMPATIBILITY_RFC5766;
}

Stream *agent_find_stream (NiceAgent *agent, guint stream_id)
{
  GSList *i;

  for (i = agent->streams; i; i = i->next)
    {
      Stream *s = i->data;

      if (s->id == stream_id)
        return s;
    }

  return NULL;
}


gboolean
agent_find_component (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  Stream **stream,
  Component **component)
{
  Stream *s;
  Component *c;

  s = agent_find_stream (agent, stream_id);

  if (s == NULL)
    return FALSE;

  c = stream_find_component_by_id (s, component_id);

  if (c == NULL)
    return FALSE;

  if (stream)
    *stream = s;

  if (component)
    *component = c;

  return TRUE;
}


static void
nice_agent_class_init (NiceAgentClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = nice_agent_get_property;
  gobject_class->set_property = nice_agent_set_property;
  gobject_class->dispose = nice_agent_dispose;

  /* install properties */
  /**
   * NiceAgent:main-context:
   *
   * A GLib main context is needed for all timeouts used by libnice.
   * This is a property being set by the nice_agent_new() call.
   */
  g_object_class_install_property (gobject_class, PROP_MAIN_CONTEXT,
      g_param_spec_pointer (
         "main-context",
         "The GMainContext to use for timeouts",
         "The GMainContext to use for timeouts",
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  /**
   * NiceAgent:compatibility:
   *
   * The Nice agent can work in various compatibility modes depending on
   * what the application/peer needs.
   * <para> See also: #NiceCompatibility</para>
   */
  g_object_class_install_property (gobject_class, PROP_COMPATIBILITY,
      g_param_spec_uint (
         "compatibility",
         "ICE specification compatibility",
         "The compatibility mode for the agent",
         NICE_COMPATIBILITY_RFC5245, NICE_COMPATIBILITY_LAST,
         NICE_COMPATIBILITY_RFC5245,
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class, PROP_TURN_COMPATIBILITY,
      g_param_spec_uint (
         "turn-compatibility",
         "TURN specification compatibility",
         "The compatibility mode for the agent when commmunicating with the TURN server",
         NICE_COMPATIBILITY_RFC5245, NICE_COMPATIBILITY_LAST,
         NICE_COMPATIBILITY_RFC5245,
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class, PROP_STUN_SERVER,
      g_param_spec_string (
        "stun-server",
        "STUN server IP address",
        "The IP address (not the hostname) of the STUN server to use",
        NULL,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_STUN_SERVER_PORT,
      g_param_spec_uint (
        "stun-server-port",
        "STUN server port",
        "Port of the STUN server used to gather server-reflexive candidates",
        1, 65536,
	1, /* not a construct property, ignored */
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_CONTROLLING_MODE,
      g_param_spec_boolean (
        "controlling-mode",
        "ICE controlling mode",
        "Whether the agent is in controlling mode",
	FALSE, /* not a construct property, ignored */
        G_PARAM_READWRITE));

   g_object_class_install_property (gobject_class, PROP_FULL_MODE,
      g_param_spec_boolean (
        "full-mode",
        "ICE full mode",
        "Whether agent runs in ICE full mode",
	TRUE, /* use full mode by default */
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class, PROP_STUN_PACING_TIMER,
      g_param_spec_uint (
        "stun-pacing-timer",
        "STUN pacing timer",
        "Timer 'Ta' (msecs) used in the IETF ICE specification for pacing "
        "candidate gathering and sending of connectivity checks",
        1, 0xffffffff,
	NICE_AGENT_TIMER_TA_DEFAULT,
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  /* note: according to spec recommendation in sect 5.7.3 (ID-19) */
  g_object_class_install_property (gobject_class, PROP_MAX_CONNECTIVITY_CHECKS,
      g_param_spec_uint (
        "max-connectivity-checks",
        "Maximum number of connectivity checks",
        "Upper limit for the total number of connectivity checks performed",
        1, 0xffffffff,
        NICE_AGENT_MAX_CONNECTIVITY_CHECKS_DEFAULT,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_MAX_TCP_QUEUE_SIZE,
      g_param_spec_uint (
        "max-tcp-queue-size",
        "Maximum number of packets that will be queued on a TCP connection",
        "Maximum number of packets that will be queued on a TCP connection. 0 -> unlimited",
        0, 0xffffffff,
        NICE_AGENT_MAX_TCP_QUEUE_SIZE_DEFAULT,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-ip:
   *
   * The proxy server IP used to bypass a proxy firewall
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_IP,
      g_param_spec_string (
        "proxy-ip",
        "Proxy server IP",
        "The proxy server IP used to bypass a proxy firewall",
        NULL,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-port:
   *
   * The proxy server port used to bypass a proxy firewall
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_PORT,
      g_param_spec_uint (
        "proxy-port",
        "Proxy server port",
        "The Proxy server port used to bypass a proxy firewall",
        1, 65536,
	1,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-type:
   *
   * The type of proxy set in the proxy-ip property
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_TYPE,
      g_param_spec_uint (
         "proxy-type",
         "Type of proxy to use",
         "The type of proxy set in the proxy-ip property",
         NICE_PROXY_TYPE_NONE, NICE_PROXY_TYPE_LAST,
         NICE_PROXY_TYPE_NONE,
         G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-username:
   *
   * The username used to authenticate with the proxy
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_USERNAME,
      g_param_spec_string (
        "proxy-username",
        "Proxy server username",
        "The username used to authenticate with the proxy",
        NULL,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:proxy-password:
   *
   * The password used to authenticate with the proxy
   *
   * Since: 0.0.4
   */
  g_object_class_install_property (gobject_class, PROP_PROXY_PASSWORD,
      g_param_spec_string (
        "proxy-password",
        "Proxy server password",
        "The password used to authenticate with the proxy",
        NULL,
        G_PARAM_READWRITE));

  /**
   * NiceAgent:upnp:
   *
   * Whether the agent should use UPnP to open a port in the router and
   * get the external IP
   *
   * Since: 0.0.7
   */
   g_object_class_install_property (gobject_class, PROP_UPNP,
      g_param_spec_boolean (
        "upnp",
#ifdef HAVE_GUPNP
        "Use UPnP",
        "Whether the agent should use UPnP to open a port in the router and "
        "get the external IP",
#else
        "Use UPnP (disabled in build)",
        "Does nothing because libnice was not built with UPnP support",
#endif
	TRUE, /* enable UPnP by default */
        G_PARAM_READWRITE| G_PARAM_CONSTRUCT));

  /**
   * NiceAgent:upnp-timeout:
   *
   * The maximum amount of time to wait for UPnP discovery to finish before
   * signaling the #NiceAgent::candidate-gathering-done signal
   *
   * Since: 0.0.7
   */
  g_object_class_install_property (gobject_class, PROP_UPNP_TIMEOUT,
      g_param_spec_uint (
        "upnp-timeout",
#ifdef HAVE_GUPNP
        "Timeout for UPnP discovery",
        "The maximum amount of time to wait for UPnP discovery to finish before "
        "signaling the candidate-gathering-done signal",
#else
        "Timeout for UPnP discovery (disabled in build)",
        "Does nothing because libnice was not built with UPnP support",
#endif
        100, 60000,
	DEFAULT_UPNP_TIMEOUT,
        G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

  g_object_class_install_property (gobject_class, PROP_CONNCHECK_TIMEOUT,
      g_param_spec_uint (
        "connectivity-check-timeout",
        "Initial timeout for connectivity check (ms)",
        "Initial timeout for connectivity checks (ms). Each subsequent retransmission will double the timeout",
        1, 0xffffffff,
        STUN_TIMER_DEFAULT_TIMEOUT,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_CONNCHECK_RETRANSMISSIONS,
      g_param_spec_uint (
        "connectivity-check-retransmissions",
        "Maximum restransmissions for a connectivity check",
        "Maximum restransmissions for a connectivity check",
        1, 0xffffffff,
        STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_AGGRESSIVE_MODE,
      g_param_spec_boolean (
        "aggressive-mode",
        "Use aggressive nomination when controller",
        "Use aggressive nomination when controller",
        TRUE,
        G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_REGULAR_NOMINATION_TIMEOUT,
      g_param_spec_uint (
        "regular-nomination-timeout",
        "Timeout (in ms) before regular nomination will select non-optimal media path",
        "Timeout (in ms) before regular nomination will select non-optimal media path",
        1, 0xffffffff,
        NICE_AGENT_REGULAR_NOMINATION_TIMEOUT_DEFAULT,  /* Not construct time so ignored */
        G_PARAM_READWRITE));

  /* install signals */

  /**
   * NiceAgent::component-state-changed
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @state: The #NiceComponentState of the component
   *
   * This signal is fired whenever a component's state changes
   */
  signals[SIGNAL_COMPONENT_STATE_CHANGED] =
      g_signal_new (
          "component-state-changed",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_generic,
          G_TYPE_NONE,
          3,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT,
          G_TYPE_INVALID);

  /**
   * NiceAgent::candidate-gathering-done:
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   *
   * This signal is fired whenever a stream has finished gathering its
   * candidates after a call to nice_agent_gather_candidates()
   */
  signals[SIGNAL_CANDIDATE_GATHERING_DONE] =
      g_signal_new (
          "candidate-gathering-done",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_generic,
          G_TYPE_NONE,
          1,
          G_TYPE_UINT, G_TYPE_INVALID);

  /**
   * NiceAgent::new-selected-pair
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @lfoundation: The local foundation of the selected candidate pair
   * @rfoundation: The remote foundation of the selected candidate pair
   *
   * This signal is fired once a candidate pair is selected for data transfer for
   * a stream's component
   */
  signals[SIGNAL_NEW_SELECTED_PAIR] =
      g_signal_new (
          "new-selected-pair",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_generic,
          G_TYPE_NONE,
          4,
          G_TYPE_UINT, G_TYPE_UINT, NICE_TYPE_CANDIDATE, NICE_TYPE_CANDIDATE);

  /**
   * NiceAgent::new-candidate
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @foundation: The foundation of the new candidate
   *
   * This signal is fired when the agent discovers a new candidate
   * <para> See also: #NiceAgent::candidate-gathering-done </para>
   */
  signals[SIGNAL_NEW_CANDIDATE] =
      g_signal_new (
          "new-candidate",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_generic,
          G_TYPE_NONE,
          3,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_STRING,
          G_TYPE_INVALID);

  /**
   * NiceAgent::new-remote-candidate
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   * @foundation: The foundation of the new candidate
   *
   * This signal is fired when the agent discovers a new remote candidate.
   * This can happen with peer reflexive candidates.
   */
  signals[SIGNAL_NEW_REMOTE_CANDIDATE] =
      g_signal_new (
          "new-remote-candidate",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_generic,
          G_TYPE_NONE,
          3,
          G_TYPE_UINT, G_TYPE_UINT, G_TYPE_STRING,
          G_TYPE_INVALID);

  /**
   * NiceAgent::initial-binding-request-received
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   *
   * This signal is fired when we received our first binding request from
   * the peer.
   */
  signals[SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED] =
      g_signal_new (
          "initial-binding-request-received",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_generic,
          G_TYPE_NONE,
          1,
          G_TYPE_UINT,
          G_TYPE_INVALID);

  /**
   * NiceAgent::reliable-transport-writable
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   *
   * This signal is fired on the reliable #NiceAgent when the underlying reliable
   * transport becomes writable.
   * This signal is only emitted when the nice_agent_send() function returns less
   * bytes than requested to send (or -1) and once when the connection
   * is established.
   *
   * Since: 0.0.11
   */
  signals[SIGNAL_RELIABLE_TRANSPORT_WRITABLE] =
      g_signal_new (
          "reliable-transport-writable",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_generic,
          G_TYPE_NONE,
          2,
          G_TYPE_UINT, G_TYPE_UINT,
          G_TYPE_INVALID);

  /**
   * NiceAgent::reliable-transport-overflow
   * @agent: The #NiceAgent object
   * @stream_id: The ID of the stream
   * @component_id: The ID of the component
   *
   * This signal is fired on the reliable #NiceAgent when the underlying reliable
   * transport buffer is full.
   *
   * Since: PEXIP specific
   */
  signals[SIGNAL_RELIABLE_TRANSPORT_OVERFLOW] =
      g_signal_new (
          "reliable-transport-overflow",
          G_OBJECT_CLASS_TYPE (klass),
          G_SIGNAL_RUN_LAST,
          0,
          NULL,
          NULL,
          g_cclosure_marshal_generic,
          G_TYPE_NONE,
          2,
          G_TYPE_UINT, G_TYPE_UINT,
          G_TYPE_INVALID);


  /* Init debug options depending on env variables */
  nice_debug_init ();
}

static void
priv_generate_tie_breaker (NiceAgent *agent)
{
  nice_rng_generate_bytes (agent->rng, 8, (gchar*)&agent->tie_breaker);
}

static void
nice_agent_init (NiceAgent *agent)
{
  agent->next_candidate_id = 1;
  agent->next_stream_id = 1;

  /* set defaults; not construct params, so set here */
  agent->stun_server_port = DEFAULT_STUN_PORT;
  agent->controlling_mode = TRUE;
  agent->max_conn_checks = NICE_AGENT_MAX_CONNECTIVITY_CHECKS_DEFAULT;
  agent->max_tcp_queue_size = NICE_AGENT_MAX_TCP_QUEUE_SIZE_DEFAULT;
  agent->conncheck_timeout = STUN_TIMER_DEFAULT_TIMEOUT;
  agent->conncheck_retransmissions = STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS;
  agent->aggressive_mode = TRUE;
  agent->regular_nomination_timeout = NICE_AGENT_REGULAR_NOMINATION_TIMEOUT_DEFAULT;

  agent->discovery_list = NULL;
  agent->discovery_unsched_items = 0;
  agent->discovery_timer_source = NULL;
  agent->conncheck_timer_source = NULL;
  agent->keepalive_timer_source = NULL;
  agent->refresh_list = NULL;
  agent->media_after_tick = FALSE;
  agent->software_attribute = NULL;

  agent->compatibility = NICE_COMPATIBILITY_RFC5245;

  stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC5389,
      STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
      STUN_AGENT_USAGE_USE_FINGERPRINT);

  agent->rng = nice_rng_new ();
  priv_generate_tie_breaker (agent);

  g_mutex_init (&agent->mutex);
}


NICEAPI_EXPORT NiceAgent *
nice_agent_new (GMainContext *ctx, NiceCompatibility compat, NiceCompatibility turn_compat)
{
  NiceAgent *agent = g_object_new (NICE_TYPE_AGENT,
      "compatibility", compat,
      "turn-compatibility", turn_compat,
      "main-context", ctx,
      NULL);

  return agent;
}


static void
nice_agent_get_property (
  GObject *object,
  guint property_id,
  GValue *value,
  GParamSpec *pspec)
{
  NiceAgent *agent = NICE_AGENT (object);

  agent_lock();

  switch (property_id)
    {
    case PROP_MAIN_CONTEXT:
      g_value_set_pointer (value, agent->main_context);
      break;

    case PROP_COMPATIBILITY:
      g_value_set_uint (value, agent->compatibility);
      break;

    case PROP_TURN_COMPATIBILITY:
      g_value_set_uint (value, agent->turn_compatibility);
      break;

    case PROP_STUN_SERVER:
      g_value_set_string (value, agent->stun_server_ip);
      break;

    case PROP_STUN_SERVER_PORT:
      g_value_set_uint (value, agent->stun_server_port);
      break;

    case PROP_CONTROLLING_MODE:
      g_value_set_boolean (value, agent->controlling_mode);
      break;

    case PROP_FULL_MODE:
      g_value_set_boolean (value, agent->full_mode);
      break;

    case PROP_STUN_PACING_TIMER:
      g_value_set_uint (value, agent->timer_ta);
      break;

    case PROP_CONNCHECK_TIMEOUT:
      g_value_set_uint (value, agent->conncheck_timeout);
      break;

    case PROP_CONNCHECK_RETRANSMISSIONS:
      g_value_set_uint (value, agent->conncheck_retransmissions);
      break;
      
    case PROP_AGGRESSIVE_MODE:
      g_value_set_boolean (value, agent->aggressive_mode);
      break;

    case PROP_REGULAR_NOMINATION_TIMEOUT:
      g_value_set_uint (value, agent->regular_nomination_timeout);
      break;

    case PROP_MAX_CONNECTIVITY_CHECKS:
      g_value_set_uint (value, agent->max_conn_checks);
      /* XXX: should we prune the list of already existing checks? */
      break;

    case PROP_MAX_TCP_QUEUE_SIZE:
      g_value_set_uint (value, agent->max_tcp_queue_size);
      break;

    case PROP_PROXY_IP:
      g_value_set_string (value, agent->proxy_ip);
      break;

    case PROP_PROXY_PORT:
      g_value_set_uint (value, agent->proxy_port);
      break;

    case PROP_PROXY_TYPE:
      g_value_set_uint (value, agent->proxy_type);
      break;

    case PROP_PROXY_USERNAME:
      g_value_set_string (value, agent->proxy_username);
      break;

    case PROP_PROXY_PASSWORD:
      g_value_set_string (value, agent->proxy_password);
      break;

    case PROP_UPNP:
#ifdef HAVE_GUPNP
      g_value_set_boolean (value, agent->upnp_enabled);
#else
      g_value_set_boolean (value, FALSE);
#endif
      break;

    case PROP_UPNP_TIMEOUT:
#ifdef HAVE_GUPNP
      g_value_set_uint (value, agent->upnp_timeout);
#else
      g_value_set_uint (value, DEFAULT_UPNP_TIMEOUT);
#endif
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }

  agent_unlock();
}


static void
nice_agent_set_property (
  GObject *object,
  guint property_id,
  const GValue *value,
  GParamSpec *pspec)
{
  NiceAgent *agent = NICE_AGENT (object);

  agent_lock();

  switch (property_id)
    {
    case PROP_MAIN_CONTEXT:
      agent->main_context = g_value_get_pointer (value);
      if (agent->main_context != NULL)
        g_main_context_ref (agent->main_context);
      break;

    case PROP_COMPATIBILITY:
      agent->compatibility = g_value_get_uint (value);
      if (agent->compatibility == NICE_COMPATIBILITY_OC2007R2) {
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_WLM2009,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_USE_FINGERPRINT |
            STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
      } else {
        agent->compatibility = NICE_COMPATIBILITY_RFC5245;
        stun_agent_init (&agent->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
            STUN_COMPATIBILITY_RFC5389,
            STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
            STUN_AGENT_USAGE_USE_FINGERPRINT);
      }
      stun_agent_set_software (&agent->stun_agent, agent->software_attribute);
      break;

    case PROP_TURN_COMPATIBILITY:
      agent->turn_compatibility = g_value_get_uint (value);
      break;

    case PROP_STUN_SERVER:
      g_free (agent->stun_server_ip);
      agent->stun_server_ip = g_value_dup_string (value);
      break;

    case PROP_STUN_SERVER_PORT:
      agent->stun_server_port = g_value_get_uint (value);
      break;

    case PROP_CONTROLLING_MODE:
      agent->controlling_mode = g_value_get_boolean (value);
      break;

    case PROP_FULL_MODE:
      agent->full_mode = g_value_get_boolean (value);
      break;

    case PROP_STUN_PACING_TIMER:
      agent->timer_ta = g_value_get_uint (value);
      break;

    case PROP_AGGRESSIVE_MODE:
      agent->aggressive_mode = g_value_get_boolean (value);
      break;

    case PROP_REGULAR_NOMINATION_TIMEOUT:
      agent->regular_nomination_timeout = g_value_get_uint (value);
      break;

    case PROP_MAX_CONNECTIVITY_CHECKS:
      agent->max_conn_checks = g_value_get_uint (value);
      break;

    case PROP_CONNCHECK_TIMEOUT:
      agent->conncheck_timeout = g_value_get_uint (value);
      break;

    case PROP_CONNCHECK_RETRANSMISSIONS:
      agent->conncheck_retransmissions = g_value_get_uint (value);
      break;

    case PROP_MAX_TCP_QUEUE_SIZE:
      agent->max_tcp_queue_size = g_value_get_uint (value);
      break;

    case PROP_PROXY_IP:
      g_free (agent->proxy_ip);
      agent->proxy_ip = g_value_dup_string (value);
      break;

    case PROP_PROXY_PORT:
      agent->proxy_port = g_value_get_uint (value);
      break;

    case PROP_PROXY_TYPE:
      agent->proxy_type = g_value_get_uint (value);
      break;

    case PROP_PROXY_USERNAME:
      g_free (agent->proxy_username);
      agent->proxy_username = g_value_dup_string (value);
      break;

    case PROP_PROXY_PASSWORD:
      g_free (agent->proxy_password);
      agent->proxy_password = g_value_dup_string (value);
      break;

    case PROP_UPNP_TIMEOUT:
#ifdef HAVE_GUPNP
      agent->upnp_timeout = g_value_get_uint (value);
#endif
      break;

    case PROP_UPNP:
#ifdef HAVE_GUPNP
      agent->upnp_enabled = g_value_get_boolean (value);
#endif
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }

  agent_unlock();

}


void agent_gathering_done (NiceAgent *agent)
{
  GSList *i, *j, *k, *l, *m;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    if (stream->gathering) {
      for (j = stream->components; j; j = j->next) {
        Component *component = j->data;
        
        for (k = component->local_candidates; k; k = k->next) {
          NiceCandidate *local_candidate = k->data;
          gchar tmpbuf[INET6_ADDRSTRLEN];
          gchar tmpbuf2[INET6_ADDRSTRLEN];
          nice_address_to_string (&local_candidate->addr, tmpbuf);
          nice_address_to_string (&local_candidate->base_addr, tmpbuf2);
          nice_debug ("Agent %p %u/%u: gathered local candidate : foundation:%s %s %s [%s]:%u [%s]:%u",
                      agent, local_candidate->stream_id, local_candidate->component_id,
                      local_candidate->foundation, 
                      candidate_type_to_string (local_candidate->type),
                      candidate_transport_to_string (local_candidate->transport),
                      tmpbuf, nice_address_get_port (&local_candidate->addr),
                      tmpbuf2, nice_address_get_port (&local_candidate->base_addr));
          
          for (l = component->remote_candidates; l; l = l->next) {
            NiceCandidate *remote_candidate = l->data;
            
            for (m = stream->conncheck_list; m; m = m->next) {
              CandidateCheckPair *p = m->data;
              
              if (p->local == local_candidate && p->remote == remote_candidate)
                break;
            }
            if (m == NULL) {
              conn_check_add_for_candidate_pair (agent, stream->id, component, local_candidate, remote_candidate);
            }
          }
        }
      }
    }
  }

#ifdef HAVE_GUPNP
  if (agent->discovery_timer_source == NULL &&
      agent->upnp_timer_source == NULL) {
    agent_signal_gathering_done (agent);
  }
#else
  if (agent->discovery_timer_source == NULL)
    agent_signal_gathering_done (agent);
#endif
}

void agent_signal_gathering_done (NiceAgent *agent)
{
  GSList *i;

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    if (stream->gathering) {
      stream->gathering = FALSE;
      g_signal_emit (agent, signals[SIGNAL_CANDIDATE_GATHERING_DONE], 0, stream->id);
    }
  }
}

void agent_signal_initial_binding_request_received (NiceAgent *agent, Stream *stream)
{
  if (stream->initial_binding_request_received != TRUE) {
    stream->initial_binding_request_received = TRUE;
    g_signal_emit (agent, signals[SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED], 0, stream->id);
  }
}

void agent_signal_new_selected_pair (NiceAgent *agent, guint stream_id, guint component_id,
    NiceCandidate *lcandidate, NiceCandidate *rcandidate)
{
  Component *component;
  Stream *stream;

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    return;

  if (lcandidate->type == NICE_CANDIDATE_TYPE_RELAYED) {
    nice_turn_socket_set_peer (lcandidate->sockptr, &rcandidate->addr);
  }

  nice_debug("Agent %p %u/%u: signalling new-selected-pair (%s:%s) local-candidate-type=%s remote-candidate-type=%s local-transport=%s remote-transport=%s", agent, stream_id, component_id,
             lcandidate->foundation, rcandidate->foundation,
             candidate_type_to_string(lcandidate->type), 
             candidate_type_to_string(rcandidate->type),
             candidate_transport_to_string(lcandidate->transport), 
             candidate_transport_to_string(rcandidate->transport));

  g_signal_emit (agent, signals[SIGNAL_NEW_SELECTED_PAIR], 0,
      stream_id, component_id, lcandidate, rcandidate);
}

void agent_signal_new_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  g_signal_emit (agent, signals[SIGNAL_NEW_CANDIDATE], 0,
		 candidate->stream_id,
		 candidate->component_id,
		 candidate->foundation);
}

void agent_signal_new_remote_candidate (NiceAgent *agent, NiceCandidate *candidate)
{
  g_signal_emit (agent, signals[SIGNAL_NEW_REMOTE_CANDIDATE], 0, 
		 candidate->stream_id, 
		 candidate->component_id, 
		 candidate->foundation);
}

void agent_signal_component_state_change (NiceAgent *agent, guint stream_id, guint component_id, NiceComponentState state)
{
  Component *component;
  Stream *stream;

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component))
    return;

  if (component->state != state && state < NICE_COMPONENT_STATE_LAST) {
    nice_debug ("Agent %p %u/%u: signalling STATE-CHANGE %s -> %s.", agent,
                stream_id, component_id, component_state_to_string(component->state), component_state_to_string(state));

    component->state = state;

    g_signal_emit (agent, signals[SIGNAL_COMPONENT_STATE_CHANGED], 0,
		   stream_id, component_id, state);
  }
}

void agent_signal_turn_allocation_failure (NiceAgent* agent, guint stream_id, guint component_id, const NiceAddress* relay_addr, const StunMessage* response, const char* reason)
{
  char* msgstr = NULL;
  char addrstr[NICE_ADDRESS_STRING_LEN];
  memset(addrstr, 0, sizeof(addrstr));

  if (response)
    msgstr = stun_message_to_string(response);

  if (relay_addr)
    nice_address_to_string(relay_addr, addrstr);

  g_log (G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "TURN ALLOCATION FAILED for stream=%u component=%u server=%s response=%s reason=%s", 
         stream_id, component_id, addrstr, msgstr ? msgstr : "none", reason ? reason : "none");

  if (msgstr) g_free(msgstr);
}

guint64
agent_candidate_pair_priority (NiceAgent *agent, NiceCandidate *local, NiceCandidate *remote)
{
  if (agent->controlling_mode)
    return nice_candidate_pair_priority (local->priority, remote->priority);
  else
    return nice_candidate_pair_priority (remote->priority, local->priority);
}

static void
priv_add_new_candidate_discovery_stun (NiceAgent *agent,
    NiceSocket *socket, NiceAddress server,
    Stream *stream, guint component_id,
    NiceCandidateTransport transport,
    NiceSocket *conncheck_nicesock)
{
  CandidateDiscovery *cdisco;

  /* Don't try to connect to an IPv6 server from an IPv4 local interface or vice-versa */
  if (nice_address_get_family (&server) != nice_address_get_family (&socket->addr)) 
      return;

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);

  cdisco->type = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
  cdisco->transport = transport;
  cdisco->nicesock = socket;
  cdisco->conncheck_nicesock = conncheck_nicesock;
  cdisco->server = server;
  cdisco->stream = stream;
  cdisco->component = stream_find_component_by_id (stream, component_id);
  cdisco->agent = agent;
  stun_agent_init (&cdisco->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
                   STUN_COMPATIBILITY_RFC5389,
                   (agent->turn_compatibility == NICE_COMPATIBILITY_OC2007R2 ?
                    STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES : 0));

  nice_debug ("Agent %p : Adding new srv-rflx candidate discovery %p compatibility = %d\n",
              agent, cdisco, agent->turn_compatibility);

  agent->discovery_list = g_slist_append (agent->discovery_list, cdisco);
  ++agent->discovery_unsched_items;
}

static void
priv_add_new_candidate_discovery_turn (NiceAgent *agent,
    NiceSocket *socket, TurnServer *turn,
    Stream *stream, guint component_id)
{
  CandidateDiscovery *cdisco;
  Component *component = stream_find_component_by_id (stream, component_id);

  /* Don't try to connect to an IPv6 server from an IPv4 local interface or vice-versa */
  if (nice_address_get_family (&turn->server) != nice_address_get_family (&socket->addr)) 
      return;

  /* note: no need to check for redundant candidates, as this is
   *       done later on in the process */

  cdisco = g_slice_new0 (CandidateDiscovery);
  cdisco->type = NICE_CANDIDATE_TYPE_RELAYED;
  cdisco->transport = NICE_CANDIDATE_TRANSPORT_UDP;

  if (turn->type ==  NICE_RELAY_TYPE_TURN_UDP) {
    cdisco->nicesock = socket;
  } else {
    NiceAddress proxy_server;
    socket = NULL;

    if (agent->proxy_type != NICE_PROXY_TYPE_NONE &&
        agent->proxy_ip != NULL &&
        nice_address_set_from_string (&proxy_server, agent->proxy_ip)) {
      nice_address_set_port (&proxy_server, agent->proxy_port);
      socket = nice_tcp_bsd_socket_new (agent->main_context, &proxy_server);

      if (socket) {
        _priv_set_socket_tos (agent, socket, stream->tos);
        if (agent->proxy_type == NICE_PROXY_TYPE_SOCKS5) {
          socket = nice_socks5_socket_new (socket, &turn->server,
              agent->proxy_username, agent->proxy_password);
        } else if (agent->proxy_type == NICE_PROXY_TYPE_HTTP){
          socket = nice_http_socket_new (socket, &turn->server,
              agent->proxy_username, agent->proxy_password);
        } else {
          nice_socket_free (socket);
          socket = NULL;
        }
      }

    }
    if (socket == NULL) {
      socket = nice_tcp_bsd_socket_new (agent->main_context, &turn->server);

      if (socket)
        _priv_set_socket_tos (agent, socket, stream->tos);
    }

    /* The TURN server may be invalid or not listening */
    if (socket == NULL)
      return;

    cdisco->nicesock = nice_tcp_turn_socket_new (socket,
        agent_to_turn_socket_compatibility (agent));

    agent_attach_stream_component_socket (agent, stream,
        component, cdisco->nicesock);
    component->sockets = g_slist_append (component->sockets, cdisco->nicesock);
  }

  cdisco->turn = turn;
  cdisco->server = turn->server;

  cdisco->stream = stream;
  cdisco->component = stream_find_component_by_id (stream, component_id);
  cdisco->agent = agent;

  
  stun_agent_init (&cdisco->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
      STUN_COMPATIBILITY_RFC5389,
      STUN_AGENT_USAGE_ADD_SOFTWARE |
      STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS |
      STUN_AGENT_USAGE_NO_INDICATION_AUTH);
  stun_agent_set_software (&cdisco->stun_agent, agent->software_attribute);

  nice_debug ("Agent %p : Adding new relay-rflx candidate discovery %p\n",
      agent, cdisco);
  agent->discovery_list = g_slist_append (agent->discovery_list, cdisco);
  ++agent->discovery_unsched_items;
}

NICEAPI_EXPORT guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components)
{
  Stream *stream;
  guint ret = 0;

  agent_lock();
  stream = stream_new (n_components);

  agent->streams = g_slist_append (agent->streams, stream);
  stream->id = agent->next_stream_id++;
  nice_debug ("Agent %p : allocating stream id %u (%p)", agent, stream->id, stream);

  stream_initialize_credentials (stream, agent->rng);

  ret = stream->id;

  agent_unlock();
  return ret;
}


NICEAPI_EXPORT gboolean
nice_agent_set_relay_info(NiceAgent *agent,
    guint stream_id, guint component_id,
    const gchar *server_ip, guint server_port,
    const gchar *username, const gchar *password,
    NiceRelayType type)
{

  Component *component = NULL;

  g_return_val_if_fail (server_ip, FALSE);
  g_return_val_if_fail (server_port, FALSE);
  g_return_val_if_fail (username, FALSE);
  g_return_val_if_fail (password, FALSE);
  g_return_val_if_fail (type <= NICE_RELAY_TYPE_TURN_TLS, FALSE);

  agent_lock();

  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    TurnServer *turn = g_slice_new0 (TurnServer);
    nice_address_init (&turn->server);

    if (nice_address_set_from_string (&turn->server, server_ip)) {
      nice_address_set_port (&turn->server, server_port);
    } else {
      g_slice_free (TurnServer, turn);
      agent_unlock();
      return FALSE;
    }


    turn->username = g_strdup (username);
    turn->password = g_strdup (password);
    turn->type = type;

    nice_debug ("Agent %p: added relay server [%s]:%d of type %d", agent,
        server_ip, server_port, type);

    component->turn_servers = g_list_append (component->turn_servers, turn);
  }

  agent_unlock();
  return TRUE;
}

NICEAPI_EXPORT gboolean
nice_agent_gather_candidates (
  NiceAgent *agent,
  guint stream_id)
{
  guint n;
  GSList *i;
  Stream *stream;
  GSList *local_addresses = NULL;
  gboolean ret = TRUE;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    agent_unlock();
    return FALSE;
  }

  nice_debug ("Agent %p : In %s mode, starting candidate gathering.", agent,
      agent->full_mode ? "ICE-FULL" : "ICE-LITE");

  /* if no local addresses added, generate them ourselves */
  if (agent->local_addresses == NULL) {
    GList *addresses = nice_interfaces_get_local_ips (FALSE);
    GList *item;

    for (item = addresses; item; item = g_list_next (item)) {
      NiceAddress *addr = nice_address_new ();

      if (nice_address_set_from_string (addr, item->data)) {
        local_addresses = g_slist_append (local_addresses, addr);
      } else {
        nice_address_free (addr);
      }
    }

    g_list_foreach (addresses, (GFunc) g_free, NULL);
    g_list_free (addresses);
  } else {
    for (i = agent->local_addresses; i; i = i->next) {
      NiceAddress *addr = i->data;
      NiceAddress *dup = nice_address_dup (addr);

      local_addresses = g_slist_append (local_addresses, dup);
    }
  }

  /* generate a local host candidate for each local address */
  for (i = local_addresses; i; i = i->next) {
    NiceAddress *addr = i->data;
    NiceCandidate *udp_host_candidate;
    NiceCandidate *tcp_active_host_candidate;
    NiceCandidate *tcp_passive_host_candidate;

#ifdef HAVE_GUPNP
    gchar local_ip[NICE_ADDRESS_STRING_LEN];
    nice_address_to_string (addr, local_ip);
#endif

    for (n = 0; n < stream->n_components; n++) {
      Component *component = stream_find_component_by_id (stream, n + 1);
      guint current_port;

      if (component == NULL)
        continue;

      current_port = component->min_port;

      udp_host_candidate = NULL;
      if (component->enable_udp) {
        while (udp_host_candidate == NULL) {
          nice_debug ("Agent %p %u/%u: Trying to create host candidate on port %d", 
                      agent, stream->id, n + 1,
                      current_port);
          nice_address_set_port (addr, current_port);
          udp_host_candidate = discovery_add_local_host_candidate (agent, stream->id,
                                                                   n + 1, addr, NICE_CANDIDATE_TRANSPORT_UDP);
          if (current_port > 0)
            current_port++;
          if (current_port == 0 || current_port > component->max_port)
            break;
        }
        nice_address_set_port (addr, 0);

        if (!udp_host_candidate) {
          gchar ip[NICE_ADDRESS_STRING_LEN];
          nice_address_to_string (addr, ip);
          nice_debug ("Agent %p: Unable to add local host candidate %s for s%d:%d"
              ". Invalid interface?", agent, ip, stream->id, component->id);
          ret = FALSE;
          goto error;
        }

#ifdef HAVE_GUPNP
        if (agent->upnp_enabled) {
          NiceAddress *addr = nice_address_dup (&udp_host_candidate->base_addr);
          nice_debug ("Agent %p: Adding UPnP port %s:%d", agent, local_ip,
              nice_address_get_port (&udp_host_candidate->base_addr));
          gupnp_simple_igd_add_port (GUPNP_SIMPLE_IGD (agent->upnp), "UDP",
              0, local_ip, nice_address_get_port (&udp_host_candidate->base_addr),
              0, PACKAGE_STRING);
          agent->upnp_mapping = g_slist_prepend (agent->upnp_mapping, addr);
        }
#endif

        if (agent->full_mode &&
            agent->stun_server_ip) {
          NiceAddress stun_server;
          if (nice_address_set_from_string (&stun_server, agent->stun_server_ip)) {
            nice_address_set_port (&stun_server, agent->stun_server_port);

            priv_add_new_candidate_discovery_stun (agent,
                udp_host_candidate->sockptr,
                stun_server,
                stream,
                n + 1,
                NICE_CANDIDATE_TRANSPORT_UDP,
                udp_host_candidate->sockptr);
          }
        }

        if (agent->full_mode && component) {
          GList *item;

          for (item = component->turn_servers; item; item = item->next) {
            TurnServer *turn = item->data;

            priv_add_new_candidate_discovery_turn (agent,
                udp_host_candidate->sockptr,
                turn,
                stream,
                n + 1);
          }
        }
      }

      tcp_passive_host_candidate = NULL;
      if (component->enable_tcp_passive) {
        current_port = component->min_port;

        while (tcp_passive_host_candidate == NULL) {
          nice_debug ("Agent %p: Trying to create TCP-PASSIVE host candidate on port %d", agent, current_port);
          nice_address_set_port (addr, current_port);
          tcp_passive_host_candidate = discovery_add_local_host_candidate (agent, stream->id,
                                                               n + 1, addr, NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE);
          if (current_port > 0)
            current_port++;
          if (current_port == 0 || current_port > component->max_port)
            break;
        }
        nice_address_set_port (addr, 0);

        if (!tcp_passive_host_candidate) {
          gchar ip[NICE_ADDRESS_STRING_LEN];
          nice_address_to_string (addr, ip);
          nice_debug ("Agent %p: Unable to add local TCP-PASSIVE host candidate %s for s%d:%d"
              ". Invalid interface?", agent, ip, stream->id, component->id);
          ret = FALSE;
          goto error;
        }
      }
      
      tcp_active_host_candidate = NULL;
      if (component->enable_tcp_active) {
        current_port = component->min_port;

        while (tcp_active_host_candidate == NULL) {
          nice_debug ("Agent %p: Trying to create TCP-ACTIVE host candidate on port %d", agent, current_port);
          nice_address_set_port (addr, current_port);
          tcp_active_host_candidate = discovery_add_local_host_candidate (agent, stream->id,
                                                               n + 1, addr, NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE);
          if (current_port > 0)
            current_port++;
          if (current_port == 0 || current_port > component->max_port)
            break;
        }

        if (!tcp_active_host_candidate) {
          gchar ip[NICE_ADDRESS_STRING_LEN];
          nice_address_to_string (addr, ip);
          nice_debug ("Agent %p: Unable to add local TCP-ACTIVE host candidate %s for s%d:%d"
              ". Invalid interface?", agent, ip, stream->id, component->id);
          ret = FALSE;
          goto error;
        }

        if (agent->full_mode &&
            agent->stun_server_ip) {
          /*
           * RDP Traversal
           * Use UDP stun to discover our server reflexive address and then advertise
           * a server reflexive TCP active candidate that should be able to connect
           * to the remote relay TCP passive candidate
           */
          NiceAddress stun_server;
          if (nice_address_set_from_string (&stun_server, agent->stun_server_ip)) {
            NiceSocket* sockptr;
            char local_address_string[NICE_ADDRESS_STRING_LEN];
            char stun_address_string[NICE_ADDRESS_STRING_LEN];

            nice_address_set_port (&stun_server, agent->stun_server_port);

            if (udp_host_candidate) {
              sockptr = udp_host_candidate->sockptr;
            } else {
              /*
               * UDP not enabled for this stream, create a local UDP socket
               * for talking to the STUN server
               */
              sockptr = nice_udp_bsd_socket_new (addr);
              agent_attach_stream_component_socket (agent, stream, component, sockptr);

              component->sockets = g_slist_append (component->sockets, sockptr);

              nice_address_to_string (addr, local_address_string);
              nice_address_to_string (&stun_server, stun_address_string);

              nice_debug ("Created local UDP socket for STUN request s/c %d/%d, local-address=%s:%d, stun-address=%s:%d result=%p\n",
                          stream->id, component->id, local_address_string, nice_address_get_port(addr),
                          stun_address_string, nice_address_get_port(&stun_server), sockptr);
            }

            priv_add_new_candidate_discovery_stun (agent,
                sockptr,
                stun_server,
                stream,
                n + 1,
                NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE,
                tcp_active_host_candidate->sockptr);
          }
        }

        nice_address_set_port (addr, 0);

      }
    }
  }

  stream->gathering = TRUE;


  /* Only signal the new candidates after we're sure that the gathering was
   * succesfful. But before sending gathering-done */
  for (n = 0; n < stream->n_components; n++) {
    Component *component = stream_find_component_by_id (stream, n + 1);
    for (i = component->local_candidates; i; i = i->next) {
      NiceCandidate *candidate = i->data;
      agent_signal_new_candidate (agent, candidate);
    }
  }

  /* note: no async discoveries pending, signal that we are ready */
  if (agent->discovery_unsched_items == 0 &&
#ifdef HAVE_GUPNP
      g_slist_length (agent->upnp_mapping) == 0) {
#else
    TRUE) {
#endif
    agent_gathering_done (agent);
  } else if (agent->discovery_unsched_items) {
    discovery_schedule (agent);
  }
  
 error:
  for (i = local_addresses; i; i = i->next)
    nice_address_free (i->data);
  g_slist_free (local_addresses);

  if (ret == FALSE) {
    priv_free_upnp (agent);
    for (n = 0; n < stream->n_components; n++) {
      Component *component = stream_find_component_by_id (stream, n + 1);

      priv_detach_stream_component (stream, component);

      for (i = component->local_candidates; i; i = i->next) {
        NiceCandidate *candidate = i->data;
        nice_candidate_free (candidate);
      }
      for (i = component->sockets; i; i = i->next) {
        NiceSocket *udpsocket = i->data;
        nice_socket_free (udpsocket);
      }
      g_slist_free (component->local_candidates);
      component->local_candidates = NULL;
      g_slist_free (component->sockets);
      component->sockets = NULL;
    }
    discovery_prune_stream (agent, stream_id);
  }

  agent_unlock();

  return ret;
}

static void priv_free_upnp (NiceAgent *agent)
{
#ifdef HAVE_GUPNP
  GSList *i;

  if (agent->upnp) {
    g_object_unref (agent->upnp);
    agent->upnp = NULL;
  }

  for (i = agent->upnp_mapping; i; i = i->next) {
    NiceAddress *a = i->data;
    nice_address_free (a);
  }
  g_slist_free (agent->upnp_mapping);
  agent->upnp_mapping = NULL;

  if (agent->upnp_timer_source != NULL) {
    g_source_destroy (agent->upnp_timer_source);
    g_source_unref (agent->upnp_timer_source);
    agent->upnp_timer_source = NULL;
  }
#endif
}

static void priv_remove_keepalive_timer (NiceAgent *agent)
{
  if (agent->keepalive_timer_source != NULL) {
    g_source_destroy (agent->keepalive_timer_source);
    g_source_unref (agent->keepalive_timer_source);
    agent->keepalive_timer_source = NULL;
  }
}

NICEAPI_EXPORT void
nice_agent_remove_stream (
  NiceAgent *agent,
  guint stream_id)
{
  /* note that streams/candidates can be in use by other threads */

  Stream *stream;

  agent_lock();
  stream = agent_find_stream (agent, stream_id);

  if (!stream) {
    goto done;
  }

  /* note: remove items with matching stream_ids from both lists */
  conn_check_prune_stream (agent, stream);
  discovery_prune_stream (agent, stream_id);
  refresh_prune_stream (agent, stream_id);

  /* remove the stream itself */
  agent->streams = g_slist_remove (agent->streams, stream);
  stream_free (stream);

  if (!agent->streams)
    priv_remove_keepalive_timer (agent);

 done:
  agent_unlock();
}

NICEAPI_EXPORT void
nice_agent_set_port_range (NiceAgent *agent, guint stream_id, guint component_id,
    guint min_port, guint max_port)
{
  Component *component;

  agent_lock();

  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    component->min_port = min_port;
    component->max_port = max_port;
  }

  agent_unlock();
}

NICEAPI_EXPORT void
nice_agent_set_transport (
    NiceAgent *agent,
    guint stream_id,
    guint component_id,
    NiceCandidateTransport transport)
{
  Component *component;

  agent_lock();

  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    switch (transport) {
    case NICE_CANDIDATE_TRANSPORT_UDP:
      component->enable_udp = TRUE;
      break;

    case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
      component->enable_tcp_active = TRUE;
      break;

    case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
      component->enable_tcp_passive = TRUE;
      break;

    }
  }

  agent_unlock();
}

NICEAPI_EXPORT gboolean
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr)
{
  NiceAddress *dup;
  gboolean found = FALSE;
  GSList *item;

  agent_lock();

  dup = nice_address_dup (addr);
  nice_address_set_port (dup, 0);

  for (item = agent->local_addresses; item; item = g_slist_next (item)) {
    NiceAddress *address = item->data;

    if (nice_address_equal (dup, address)) {
      found = TRUE;
      break;
    }
  }

  if (!found) {
    agent->local_addresses = g_slist_append (agent->local_addresses, dup);
  }
  else {
    nice_address_free(dup);
  }

  agent_unlock();
  return TRUE;
}

static gboolean priv_add_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  const NiceAddress *addr,
  const NiceAddress *base_addr,
  NiceCandidateTransport transport,
  guint32 priority,
  const gchar *username,
  const gchar *password,
  const gchar *foundation)
{
  Component *component;
  NiceCandidate *candidate;

  if (!agent_find_component (agent, stream_id, component_id, NULL, &component))
    return FALSE;
  
  /* step: check whether the candidate already exists */
  candidate = component_find_remote_candidate(component, addr, transport);
  if (candidate) {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (addr, tmpbuf);
    nice_debug ("Agent %p : Not updating existing remote candidate with addr [%s]:%u"
                " for s%d/c%d. U/P '%s'/'%s' prio: %u type:%d transport:%d", agent, tmpbuf,
                nice_address_get_port (addr), stream_id, component_id,
                username, password, priority, type, transport);
  }
  else {
    /* case 2: add a new candidate */
    
    candidate = nice_candidate_new (type);
    component->remote_candidates = g_slist_append (component->remote_candidates,
                                                   candidate);
    
    candidate->stream_id = stream_id;
    candidate->component_id = component_id;
    
    candidate->type = type;
    if (addr)
      candidate->addr = *addr;
    
    {
      gchar tmpbuf[INET6_ADDRSTRLEN] = {0};
      if(addr)
        nice_address_to_string (addr, tmpbuf);
      nice_debug ("Agent %p %u/%u: Adding remote candidate with foundation %s addr [%s]:%u"
                  " U/P '%s'/'%s' prio: %u type:%s transport:%s", 
                  agent, stream_id, component_id,
                  foundation, tmpbuf,
                  addr? nice_address_get_port (addr) : 0,
                  username, password, priority, candidate_type_to_string(type), candidate_transport_to_string(transport));
    }
    
    if (base_addr)
      candidate->base_addr = *base_addr;
    
    candidate->transport = transport;
    candidate->priority = priority;
    candidate->username = g_strdup (username);
    candidate->password = g_strdup (password);
    
    if (foundation)
      g_strlcpy (candidate->foundation, foundation,
          NICE_CANDIDATE_MAX_FOUNDATION);
    
    /*
     * Don't pair up remote peer reflexive candidates (RFC 5245 Section 7.2.1.3)
     */
    if (type != NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
      conn_check_add_for_remote_candidate (agent, stream_id, component, candidate);
    }
  }
  
  return TRUE;  
}

NICEAPI_EXPORT gboolean
nice_agent_set_remote_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar *ufrag, const gchar *pwd)
{
  Stream *stream;
  gboolean ret = FALSE;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  /* note: oddly enough, ufrag and pwd can be empty strings */
  if (stream && ufrag && pwd) {

    g_strlcpy (stream->remote_ufrag, ufrag, NICE_STREAM_MAX_UFRAG);
    g_strlcpy (stream->remote_password, pwd, NICE_STREAM_MAX_PWD);

    ret = TRUE;
    goto done;
  }

 done:
  agent_unlock();
  return ret;
}


NICEAPI_EXPORT gboolean
nice_agent_get_local_credentials (
  NiceAgent *agent,
  guint stream_id,
  gchar **ufrag, gchar **pwd)
{
  Stream *stream;
  gboolean ret = TRUE;

  agent_lock();

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    goto done;
  }

  if (!ufrag || !pwd) {
    goto done;
  }

  *ufrag = g_strdup (stream->local_ufrag);
  *pwd = g_strdup (stream->local_password);
  ret = TRUE;

 done:

  agent_unlock();
  return ret;
}

NICEAPI_EXPORT int
nice_agent_set_remote_candidates (NiceAgent *agent, guint stream_id, guint component_id, const GSList *candidates)
{
  const GSList *i;
  int added = 0;
  Stream *stream;
  Component *component;

  agent_lock();

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component)) {
    g_warning ("Could not find component %u in stream %u", component_id,
        stream_id);
    added = -1;
    goto done;
  }


 for (i = candidates; i && added >= 0; i = i->next) {
   NiceCandidate *d = (NiceCandidate*) i->data;

   if (nice_address_is_valid (&d->addr) == TRUE) {
     gboolean res =
         priv_add_remote_candidate (agent,
             stream_id,
             component_id,
             d->type,
             &d->addr,
             &d->base_addr,
             d->transport,
             d->priority,
             d->username,
             d->password,
             d->foundation);
     if (res)
       ++added;
   }
 }

 nice_debug("Agent %p %u/%u: added all remote candidates, checking for any pending inbound checks", 
            agent, stream_id, component_id);
 conn_check_remote_candidates_set(agent, stream_id, component_id);

 if (added > 0) {
   gboolean res = conn_check_schedule_next (agent);
   if (res != TRUE)
     nice_debug ("Agent %p %u/%u: Warning: unable to schedule any conn checks!", 
                 agent, stream_id, component_id);
 }

done:
 agent_unlock();
 return added;
}

static gboolean _nice_should_have_padding(NiceCompatibility compatibility)
{
  if (compatibility == NICE_COMPATIBILITY_OC2007R2) {
    return FALSE;
  } else {
    return TRUE;
  }
}

static gint
_nice_agent_recv (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceSocket *socket,
  guint buf_len,
  gchar *buf,
  NiceAddress *from)
{
  gint len;
  GList *item;
  gboolean has_padding = _nice_should_have_padding(agent->compatibility);
  NiceAddress stun_server;
  gboolean found_server = FALSE;

  len = nice_socket_recv (socket, from,  buf_len, buf);

  if (len <= 0)
    return len;

#ifndef NDEBUG
  if (len > 0) {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (from, tmpbuf);
    nice_debug ("Agent %p   : Packet received on local %s socket %u from [%s]:%u (%u octets).", agent,
                socket_type_to_string(socket->type), socket->fileno ? g_socket_get_fd (socket->fileno) : 0, 
                tmpbuf, nice_address_get_port (from), len);
  }
#endif


  if ((guint)len > buf_len)
    {
      /* buffer is not big enough to accept this packet */
      /* XXX: test this case */
      return 0;
    }

  /*
   * If the packet comes from a relayed candidate then let the turn socket
   * have first crack at it
   */
  for (item = component->turn_servers; item; item = g_list_next (item)) {
    TurnServer *turn = item->data;

    if (nice_address_equal (from, &turn->server)) {
      GSList * i = NULL;

#ifndef NDEBUG
      nice_debug ("Agent %p    : Packet received from TURN server candidate", agent);
#endif
      for (i = component->local_candidates; i; i = i->next) {
        NiceCandidate *cand = i->data;
        if (cand->type == NICE_CANDIDATE_TYPE_RELAYED &&
            cand->stream_id == stream->id &&
            cand->component_id == component->id) {
          len = nice_turn_socket_parse_recv (cand->sockptr, &socket,
                                             from, len, buf, from, buf, len);
        }
      }
      break;
    }
  }

  /*
   * Now that the packet has been decapsulated from any data indication figure out the correct
   * padding based on compatibility mode
   */
  if (agent->stun_server_ip && nice_address_set_from_string (&stun_server, agent->stun_server_ip)) {
    nice_address_set_port (&stun_server, agent->stun_server_port);
    if (nice_address_equal (from, &stun_server)) {
      has_padding = _nice_should_have_padding(agent->turn_compatibility);
#ifndef NDEBUG
      nice_debug ("Agent %p    : Packet received from STUN server, has_padding=%d",
                  agent, has_padding);
#endif
      found_server = TRUE;
    }
  }

  if (!found_server) {
    for (item = component->turn_servers; item; item = g_list_next (item)) {
      TurnServer *turn = item->data;

      if (nice_address_equal (from, &turn->server)) {
        has_padding = _nice_should_have_padding(agent->turn_compatibility);
#ifndef NDEBUG
        nice_debug ("Agent %p    : Packet received from TURN server, has_padding=%d",
                    agent, has_padding);
#endif
      }
    } 
  }

  agent->media_after_tick = TRUE;
  
  if (len > 0) {
    if (stun_message_validate_buffer_length ((uint8_t *) buf, (size_t) len, has_padding) != len) {
      /* If the retval is no 0, its not a valid stun packet, probably data */
      return len;
    }
    
    if (conn_check_handle_inbound_stun (agent, stream, component, socket,
                                        from, buf, len))
      /* handled STUN message*/
      return 0;
  }
  
  /* unhandled STUN, pass to client */
  return len;
}


NICEAPI_EXPORT gint
nice_agent_send (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  const gchar *buf)
{
  Stream *stream;
  Component *component;
  gint ret = -1;

  agent_lock();

  if (agent_find_component (agent, stream_id, component_id, &stream, &component) &&
      component->selected_pair.local != NULL) {
    NiceSocket *sock = component->selected_pair.local->sockptr;
    NiceAddress *addr= &component->selected_pair.remote->addr;

#ifndef NDEBUG
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (&component->selected_pair.remote->addr, tmpbuf);

    nice_debug ("Agent %p %u/%u: sending %d bytes to [%s]:%d", agent, stream_id, component_id,
        len, tmpbuf,
        nice_address_get_port (&component->selected_pair.remote->addr));
#endif
    ret = nice_socket_send (sock, addr, len, buf);
  }

  agent_unlock();
  return ret;
}


NICEAPI_EXPORT GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id)
{
  Component *component;
  GSList *ret = NULL, *item = NULL;

  agent_lock();

  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    for (item = component->local_candidates; item; item = item->next)
      ret = g_slist_append (ret, nice_candidate_copy (item->data));
  }

  agent_unlock();
  return ret;
}


NICEAPI_EXPORT GSList *
nice_agent_get_remote_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id)
{
  Component *component;
  GSList *ret = NULL, *item = NULL;

  agent_lock();
  if (agent_find_component (agent, stream_id, component_id, NULL, &component)) {
    for (item = component->remote_candidates; item; item = item->next)
      ret = g_slist_append (ret, nice_candidate_copy (item->data));
  }

  agent_unlock();
  return ret;
}


gboolean
nice_agent_restart (
  NiceAgent *agent)
{
  GSList *i;
  gboolean res = TRUE;

  agent_lock();

  /* step: clean up all connectivity checks */
  conn_check_prune_all_streams (agent);

  /* step: regenerate tie-breaker value */
  priv_generate_tie_breaker (agent);

  for (i = agent->streams; i && res; i = i->next) {
    Stream *stream = i->data;

    /* step: reset local credentials for the stream and 
     * clean up the list of remote candidates */
    res = stream_restart (stream, agent->rng);
  }

  agent_unlock();
  return res;
}


static void
nice_agent_dispose (GObject *object)
{
  GSList *i;
  NiceAgent *agent = NICE_AGENT (object);

  /* step: free resources for the binding discovery timers */
  discovery_free (agent);
  g_assert (agent->discovery_list == NULL);
  refresh_free (agent);
  g_assert (agent->refresh_list == NULL);

  /* step: free resources for the connectivity check timers */
  conn_check_prune_all_streams (agent);

  priv_remove_keepalive_timer (agent);

  for (i = agent->local_addresses; i; i = i->next)
    {
      NiceAddress *a = i->data;

      nice_address_free (a);
    }

  g_slist_free (agent->local_addresses);
  agent->local_addresses = NULL;

  for (i = agent->streams; i; i = i->next)
    {
      Stream *s = i->data;

      stream_free (s);
    }

  g_slist_free (agent->streams);
  agent->streams = NULL;

  g_free (agent->stun_server_ip);
  agent->stun_server_ip = NULL;

  g_free (agent->proxy_ip);
  agent->proxy_ip = NULL;
  g_free (agent->proxy_username);
  agent->proxy_username = NULL;
  g_free (agent->proxy_password);
  agent->proxy_password = NULL;

  nice_rng_free (agent->rng);
  agent->rng = NULL;

  priv_free_upnp (agent);

  g_free (agent->software_attribute);
  agent->software_attribute = NULL;

  if (agent->main_context != NULL)
    g_main_context_unref (agent->main_context);
  agent->main_context = NULL;

  g_mutex_clear (&agent->mutex);

  if (G_OBJECT_CLASS (nice_agent_parent_class)->dispose)
    G_OBJECT_CLASS (nice_agent_parent_class)->dispose (object);
}


typedef struct _IOCtx IOCtx;

struct _IOCtx
{
  GSource *source;
  NiceAgent *agent;
  Stream *stream;
  Component *component;
  NiceSocket *socket;
};


static IOCtx *
io_ctx_new (
  NiceAgent *agent,
  Stream *stream,
  Component *component,
  NiceSocket *socket,
  GSource *source)
{
  IOCtx *ctx;

  ctx = g_slice_new0 (IOCtx);
  ctx->agent = agent;
  ctx->stream = stream;
  ctx->component = component;
  ctx->socket = socket;
  ctx->source = source;
  return ctx;
}


static void
io_ctx_free (IOCtx *ctx)
{
  g_slice_free (IOCtx, ctx);
}

/*
 * Callback from non gsocket based NiceSockets when data received.
 */
void
nice_agent_socket_rx_cb (NiceSocket* socket, NiceAddress* from,
    gchar* buf, gint len, gpointer userdata)
{
  TcpUserData *ctx = (TcpUserData *)userdata;
  NiceAgent *agent = ctx->agent;
  Stream *stream = ctx->stream;
  Component *component = ctx->component;
  gboolean has_padding = _nice_should_have_padding(agent->compatibility);
  GList *item;
  gboolean is_stun = TRUE;
  NiceAddress stun_server;

  if (len <= 0) {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (from, tmpbuf);

    g_log (G_LOG_DOMAIN, G_LOG_LEVEL_INFO, "Agent %p : Received invalid packet on local socket %u from [%s]:%u (%d octets).", agent,
                socket->fileno ? g_socket_get_fd (socket->fileno) : 0, tmpbuf, nice_address_get_port (from), len);
    return;
  } 

#ifndef NDEBUG
  if (len > 0) {
    gchar tmpbuf[INET6_ADDRSTRLEN];
    nice_address_to_string (from, tmpbuf);
    nice_debug ("Agent %p    : Packet received on local %s socket %u from [%s]:%u (%u octets).", agent,
                socket_type_to_string(socket->type), socket->fileno ? g_socket_get_fd (socket->fileno) : 0, 
                tmpbuf, nice_address_get_port (from), len);
  }
#endif

  agent_lock();

  if (agent->stun_server_ip && nice_address_set_from_string (&stun_server, agent->stun_server_ip)) {
    nice_address_set_port (&stun_server, agent->stun_server_port);
    if (nice_address_equal (from, &stun_server)) {
      has_padding = _nice_should_have_padding(agent->turn_compatibility);
    }
  } else {
    for (item = component->turn_servers; item; item = g_list_next (item)) {
      TurnServer *turn = item->data;
      if (nice_address_equal (from, &turn->server)) {
        GSList * i = NULL;
        has_padding = _nice_should_have_padding(agent->turn_compatibility);

#ifndef NDEBUG
        nice_debug ("Agent %p    : Packet received from TURN server candidate.",
                    agent);
#endif
        for (i = component->local_candidates; i; i = i->next) {
          NiceCandidate *cand = i->data;
          if (cand->type == NICE_CANDIDATE_TYPE_RELAYED &&
              cand->stream_id == stream->id &&
              cand->component_id == component->id) {
            len = nice_turn_socket_parse_recv (cand->sockptr, &socket,
                                               from, len, buf, from, buf, len);
          }
        }
        break;
      }
    }
  }

  agent->media_after_tick = TRUE;

  if (stun_message_validate_buffer_length ((uint8_t *) buf, (size_t) len, has_padding) != len) {
    is_stun = FALSE;
  } 

  if (!is_stun || !conn_check_handle_inbound_stun (agent, stream, component, socket,
                                                   from, buf, len)) {
    /* unhandled STUN, pass to client */
    if (component->g_source_io_cb) {
      gpointer cdata = component->data;
      gint sid = stream->id;
      gint cid = component->id;
      NiceAgentRecvFunc callback = component->g_source_io_cb;
      agent_unlock();
      callback (agent, sid, cid, len, buf, cdata, from, &socket->addr);
    } else {
      agent_unlock();
    }    
  } else {
    agent_unlock();
  }
}

void
nice_agent_socket_tx_cb (NiceSocket* socket, gchar* buf, gint len, gsize queued,
    gpointer userdata)
{
  TcpUserData *ctx = (TcpUserData *)userdata;
  NiceAgent *agent = ctx->agent;
  Stream *stream = ctx->stream;
  Component *component = ctx->component;

  g_mutex_lock (&agent->mutex);
  if (agent->writable && queued > 0) {
    agent->writable = FALSE;
    g_signal_emit (agent, signals[SIGNAL_RELIABLE_TRANSPORT_OVERFLOW],
        0, stream->id, component->id);
  } else if (!agent->writable && queued == 0) {
    agent->writable = TRUE;
    g_signal_emit (agent, signals[SIGNAL_RELIABLE_TRANSPORT_WRITABLE],
        0, stream->id, component->id);
  }
  g_mutex_unlock (&agent->mutex);
}

static gboolean
nice_agent_g_source_cb (
  GSocket *gsocket,
  GIOCondition condition,
  gpointer data)
{
  IOCtx *ctx = data;
  NiceAgent *agent = ctx->agent;
  Stream *stream = ctx->stream;
  Component *component = ctx->component;
  NiceAddress from;
  gchar buf[MAX_BUFFER_SIZE];
  gint len;

  agent_lock();

  if (g_source_is_destroyed (g_main_current_source ())) {
    agent_unlock ();
    return FALSE;
  }

  len = _nice_agent_recv (agent, stream, component, ctx->socket,
			  MAX_BUFFER_SIZE, buf, &from);

  if (len > 0 && component->g_source_io_cb) {
    gpointer data = component->data;
    gint sid = stream->id;
    gint cid = component->id;
    NiceAgentRecvFunc callback = component->g_source_io_cb;
    /* Unlock the agent before calling the callback */
    agent_unlock();
    callback (agent, sid, cid, len, buf, data, &from, &ctx->socket->addr);
    goto done;
  } else if (len < 0) {
    GSource *source = ctx->source;

    nice_debug ("Agent %p: _nice_agent_recv returned %d, errno (%d) : %s",
        agent, len, errno, g_strerror (errno));
    component->gsources = g_slist_remove (component->gsources, source);
    g_source_destroy (source);
    g_source_unref (source);
    /* We don't close the socket because it would be way too complicated to
     * take care of every path where the socket might still be used.. */
    nice_debug ("Agent %p: unable to recv from socket %p. Detaching", agent,
        ctx->socket);

  }

  agent_unlock();

 done:

  return TRUE;
}

/*
 * Attaches one socket handle to the main loop event context
 */

void
agent_attach_stream_component_socket (NiceAgent *agent,
    Stream *stream,
    Component *component,
    NiceSocket *socket)
{
  GSource *source;
  IOCtx *ctx;

  nice_socket_attach (socket, component->ctx);

  if (!component->ctx)
    return;

  if (socket->fileno) {
    /* note: without G_IO_ERR the glib mainloop goes into
     *       busyloop if errors are encountered */
    source = g_socket_create_source(socket->fileno, G_IO_IN | G_IO_ERR, NULL);
    
    ctx = io_ctx_new (agent, stream, component, socket, source);
    g_source_set_callback (source, (GSourceFunc) nice_agent_g_source_cb,
                           ctx, (GDestroyNotify) io_ctx_free);
    nice_debug ("Agent %p %u/%u: Attach source %p ctx %p", agent, stream->id, component->id, source, component->ctx);
    g_source_attach (source, component->ctx);
    component->gsources = g_slist_append (component->gsources, source);
  } else {
    nice_debug ("Agent %p %u/%u: Source has no fileno", agent, stream->id, component->id);
  }
}


/*
 * Attaches socket handles of 'stream' to the main eventloop
 * context.
 *
 */
static gboolean
priv_attach_stream_component (NiceAgent *agent,
    Stream *stream,
    Component *component)
{
  GSList *i;

  for (i = component->sockets; i; i = i->next)
    agent_attach_stream_component_socket (agent, stream, component, i->data);

  return TRUE;
}

/*
 * Detaches socket handles of 'stream' from the main eventloop
 * context.
 *
 */
static void priv_detach_stream_component (Stream *stream, Component *component)
{
  GSList *i;

  for (i = component->gsources; i; i = i->next) {
    GSource *source = i->data;
    nice_debug ("Detach source %p (stream %u).", source, stream->id);
    g_source_destroy (source);
    g_source_unref (source);
  }

  g_slist_free (component->gsources);
  component->gsources = NULL;
}

NICEAPI_EXPORT gboolean
nice_agent_attach_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  GMainContext *ctx,
  NiceAgentRecvFunc func,
  gpointer data)
{
  Component *component = NULL;
  Stream *stream = NULL;
  gboolean ret = FALSE;

  agent_lock();

  /* attach candidates */

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    g_warning ("Could not find component %u in stream %u", component_id,
        stream_id);
    goto done;
  }

  if (component->g_source_io_cb)
    priv_detach_stream_component (stream, component);

  ret = TRUE;

  component->g_source_io_cb = NULL;
  component->data = NULL;
  if (component->ctx)
    g_main_context_unref (component->ctx);
  component->ctx = NULL;

  if (func) {
    component->g_source_io_cb = func;
    component->data = data;
    component->ctx = ctx;
    if (ctx)
      g_main_context_ref (ctx);

    priv_attach_stream_component (agent, stream, component);
  }

 done:
  agent_unlock();
  return ret;
}

NICEAPI_EXPORT gboolean
nice_agent_set_selected_pair (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  const gchar *lfoundation,
  const gchar *rfoundation)
{
  Component *component;
  Stream *stream;
  gboolean ret = FALSE;
  NiceCandidate *local = NULL;
  NiceCandidate *remote = NULL;
  guint64 priority = 0;

  agent_lock();

  /* step: check that params specify an existing pair */
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }
  
  /*
   * JBFIXME: It is possible for multiple remote peer reflexive candidates to have the same 
   * foundation so there is no guarantee that this API will set the correct 
   * pair of candidates
   */
  if (!component_find_pair (component, agent, lfoundation, rfoundation, &local, &remote, &priority)){
    goto done;
  }

  /* step: stop connectivity checks (note: for the whole stream) */
  conn_check_prune_stream (agent, stream);

  /* step: change component state */
  agent_signal_component_state_change (agent, stream_id, component_id, NICE_COMPONENT_STATE_READY);

  /* step: set the selected pair */
  component_update_selected_pair (component, local, remote, priority);
  agent_signal_new_selected_pair (agent, stream_id, component_id, local, remote);

  ret = TRUE;

 done:
  agent_unlock();
  return ret;
}


GSource* agent_timeout_add_with_context (NiceAgent *agent, guint interval,
    GSourceFunc function, gpointer data)
{
  GSource *source;

  g_return_val_if_fail (function != NULL, NULL);

  source = g_timeout_source_new (interval);

  g_source_set_callback (source, function, data, NULL);
  g_source_attach (source, agent->main_context);

  return source;
}


NICEAPI_EXPORT gboolean
nice_agent_set_selected_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidate *candidate)
{
  Component *component;
  Stream *stream;
  NiceCandidate *lcandidate = NULL;
  gboolean ret = FALSE;

  agent_lock();

  /* step: check if the component exists*/
  if (!agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    goto done;
  }

  /* step: stop connectivity checks (note: for the whole stream) */
  conn_check_prune_stream (agent, stream);

  /* step: set the selected pair */
  lcandidate = component_set_selected_remote_candidate (agent, component,
      candidate);
  if (!lcandidate)
    goto done;

  /* step: change component state */
  agent_signal_component_state_change (agent, stream_id, component_id, NICE_COMPONENT_STATE_READY);

  agent_signal_new_selected_pair (agent, stream_id, component_id, lcandidate, candidate);

  ret = TRUE;

 done:
  agent_unlock();
  return ret;
}

void
_priv_set_socket_tos (NiceAgent *agent, NiceSocket *sock, gint tos)
{
  if (sock->fileno && 
      setsockopt (g_socket_get_fd (sock->fileno), IPPROTO_IP,
                  IP_TOS, (const char *) &tos, sizeof (tos)) < 0) {
    nice_debug ("Agent %p: Could not set socket ToS", agent,
                g_strerror (errno));
  }

#ifdef IPV6_TCLASS
  if (sock->fileno && 
      setsockopt (g_socket_get_fd (sock->fileno), IPPROTO_IPV6,
                  IPV6_TCLASS, (const char *) &tos, sizeof (tos)) < 0) {
    nice_debug ("Agent %p: Could not set IPV6 socket ToS", agent,
                g_strerror (errno));
  }
#endif
}


void nice_agent_set_stream_tos (NiceAgent *agent,
  guint stream_id, gint tos)
{

  GSList *i, *j, *k;

  agent_lock();

  for (i = agent->streams; i; i = i->next) {
    Stream *stream = i->data;
    if (stream->id == stream_id) {
      stream->tos = tos;
      for (j = stream->components; j; j = j->next) {
        Component *component = j->data;

        for (k = component->local_candidates; k; k = k->next) {
          NiceCandidate *local_candidate = k->data;
          _priv_set_socket_tos (agent, local_candidate->sockptr, tos);
        }
      }
    }
  }

  agent_unlock();
}

void nice_agent_set_software (NiceAgent *agent, const gchar *software)
{
  agent_lock();

  g_free (agent->software_attribute);
  if (software)
    agent->software_attribute = g_strdup_printf ("%s/%s",
        software, PACKAGE_STRING);

  stun_agent_set_software (&agent->stun_agent, agent->software_attribute);

  agent_unlock ();
}

NICEAPI_EXPORT gint
nice_agent_get_tx_queue_size (
  NiceAgent *agent,
  guint stream_id,
  guint component_id)
{
  Stream *stream;
  Component *component;
  gint ret = 0;

  agent_lock();

  if (!agent_find_component (agent, stream_id, component_id,
          &stream, &component)) {
    goto done;
  }

  if (component->selected_pair.local != NULL) {
    NiceSocket *sock = component->selected_pair.local->sockptr;

    ret = nice_socket_get_tx_queue_size (sock);
  }

 done:
  agent_unlock();
  return ret;
}
