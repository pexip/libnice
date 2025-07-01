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

/*
 * @file candidate.c
 * @brief ICE candidate functions
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#else
#define NICEAPI_EXPORT
#endif

#include <string.h>

#include "agent.h"
#include "component.h"

GType
nice_candidate_get_type (void)
{
  static GType candidate_type = 0;
  if (candidate_type == 0)
  {
    candidate_type = g_boxed_type_register_static (
        "NiceCandidate",
        (GBoxedCopyFunc)nice_candidate_copy,
        (GBoxedFreeFunc)nice_candidate_free);
  }

  return candidate_type;
}


/* (ICE 4.1.1 "Gathering Candidates") ""Every candidate is a transport
 * address. It also has a type and a base. Three types are defined and
 * gathered by this specification - host candidates, server reflexive
 * candidates, and relayed candidates."" (ID-19) */

NICEAPI_EXPORT NiceCandidate *
nice_candidate_new (NiceCandidateType type)
{
  NiceCandidate *candidate;

  candidate = g_slice_new0 (NiceCandidate);
  candidate->type = type;
  return candidate;
}


NICEAPI_EXPORT void
nice_candidate_free (NiceCandidate *candidate)
{
  /* better way of checking if socket is allocated? */

  if (candidate->username)
    g_free (candidate->username);

  if (candidate->password)
    g_free (candidate->password);

  g_slice_free (NiceCandidate, candidate);
}


/*
 * Calculates the pair priority as specified in ICE
 * sect 5.7.2. "Computing Pair Priority and Ordering Pairs" (ID-19).
 */
guint64
nice_candidate_pair_priority (guint32 o_prio, guint32 a_prio)
{
  guint32 max = o_prio > a_prio ? o_prio : a_prio;
  guint32 min = o_prio < a_prio ? o_prio : a_prio;

  return ((guint64)1 << 32) * min + 2 * max + (o_prio > a_prio ? 1 : 0);
}

/*
 * Copies a candidate
 */
NICEAPI_EXPORT NiceCandidate *
nice_candidate_copy (const NiceCandidate *candidate)
{
  NiceCandidate *copy = nice_candidate_new (candidate->type);

  memcpy (copy, candidate, sizeof(NiceCandidate));

  copy->username = g_strdup (copy->username);
  copy->password = g_strdup (copy->password);

  return copy;
}

NICEAPI_EXPORT void
nice_candidate_set_ctype (NiceCandidate *candidate, NiceCandidateType type)
{
  candidate->type = type;
}

NICEAPI_EXPORT NiceCandidateType
nice_candidate_get_ctype (const NiceCandidate *candidate)
{
  return candidate->type;
}

NICEAPI_EXPORT void
nice_candidate_set_transport (NiceCandidate *candidate, NiceCandidateTransport transport)
{
  candidate->transport = transport;
}

NICEAPI_EXPORT NiceCandidateTransport
nice_candidate_get_transport (const NiceCandidate *candidate)
{
  return candidate->transport;
}

static gboolean
_set_addr (NiceAddress *dst_addr, const gchar *addr, guint port)
{
  NiceAddress new_addr;
  nice_address_init (&new_addr);
  if (!nice_address_set_from_string (&new_addr, addr))
    return FALSE;
  nice_address_set_port (&new_addr, port);
  *dst_addr = new_addr;
  return TRUE;
}

static void
_get_addr (const NiceAddress *addr, gchar **dst_addr, guint *dst_port)
{
  gchar *addr_str = g_new0 (gchar, INET6_ADDRSTRLEN);
  nice_address_to_string (addr, addr_str);
  *dst_port = nice_address_get_port (addr);
  *dst_addr = addr_str;
}

NICEAPI_EXPORT gboolean
nice_candidate_set_addr (NiceCandidate *candidate, const gchar *addr, guint port)
{
  return _set_addr (&candidate->addr, addr, port);
}

NICEAPI_EXPORT void
nice_candidate_get_addr (const NiceCandidate *candidate, gchar **dst_addr, guint *dst_port)
{
  _get_addr (&candidate->addr, dst_addr, dst_port);
}

NICEAPI_EXPORT gboolean
nice_candidate_set_base_addr (NiceCandidate *candidate, const gchar *addr, guint port)
{
  return _set_addr (&candidate->base_addr, addr, port);
}

NICEAPI_EXPORT void
nice_candidate_get_base_addr (const NiceCandidate *candidate, gchar **dst_addr, guint *dst_port)
{
  _get_addr (&candidate->base_addr, dst_addr, dst_port);
}

NICEAPI_EXPORT void
nice_candidate_set_priority (NiceCandidate *candidate, guint32 priority)
{
  candidate->priority = priority;
}

NICEAPI_EXPORT guint32
nice_candidate_get_priority (const NiceCandidate *candidate)
{
  return candidate->priority;
}

NICEAPI_EXPORT void
nice_candidate_set_stream_id (NiceCandidate *candidate, guint stream_id)
{
  candidate->stream_id = stream_id;
}

NICEAPI_EXPORT guint
nice_candidate_get_stream_id (const NiceCandidate *candidate)
{
  return candidate->stream_id;
}

NICEAPI_EXPORT void
nice_candidate_set_component_id (NiceCandidate *candidate, guint component_id)
{
  candidate->component_id = component_id;
}

NICEAPI_EXPORT guint
nice_candidate_get_component_id (const NiceCandidate *candidate)
{
  return candidate->component_id;
}

NICEAPI_EXPORT void
nice_candidate_set_foundation (NiceCandidate *candidate, const gchar *foundation)
{
  g_assert_cmpint (g_utf8_strlen(foundation, -1), <, NICE_CANDIDATE_MAX_FOUNDATION);
  g_strlcpy (candidate->foundation, foundation, NICE_CANDIDATE_MAX_FOUNDATION);
}

NICEAPI_EXPORT const gchar *
nice_candidate_get_foundation (const NiceCandidate *candidate)
{
  return candidate->foundation;
}

NICEAPI_EXPORT void
nice_candidate_set_username (NiceCandidate *candidate, gchar *username)
{
  if (candidate->username)
    g_free (candidate->username);
  candidate->username = username;
}

NICEAPI_EXPORT const gchar *
nice_candidate_get_username (const NiceCandidate *candidate)
{
  return candidate->username;
}

NICEAPI_EXPORT void
nice_candidate_set_password (NiceCandidate *candidate, gchar *password)
{
  if (candidate->password)
    g_free (candidate->password);
  candidate->password = password;
}

NICEAPI_EXPORT const gchar *
nice_candidate_get_password (const NiceCandidate *candidate)
{
  return candidate->password;
}

const char *candidate_type_to_string(NiceCandidateType type)
{
  switch (type) {
  case NICE_CANDIDATE_TYPE_HOST: return "host";
  case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return "srflx";
  case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE: return "prflx";
  case NICE_CANDIDATE_TYPE_RELAYED: return "relay";
  }
  return "(invalid)";
}

const char *candidate_transport_to_string(NiceCandidateTransport transport)
{
  switch (transport) {
  case NICE_CANDIDATE_TRANSPORT_UDP: return "udp";
  case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE: return "tcp-act";
  case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE: return "tcp-pass";
  }
  return "(invalid)";
}

NICEAPI_EXPORT gboolean
nice_candidate_equal_target (const NiceCandidate *candidate1,
    const NiceCandidate *candidate2)
{
  g_return_val_if_fail (candidate1 != NULL, FALSE);
  g_return_val_if_fail (candidate2 != NULL, FALSE);

  return (candidate1->transport == candidate2->transport &&
      nice_address_equal (&candidate1->addr, &candidate2->addr));
}

static const gchar *
_candidate_relay_type_to_string(NiceRelayType relay_type)
{
  switch (relay_type) {
  case NICE_RELAY_TYPE_TURN_UDP: return "udp";
  case NICE_RELAY_TYPE_TURN_TCP: return "tcp";
  case NICE_RELAY_TYPE_TURN_TLS: return "tls";
  }
  return "(invalid)";
}

gchar *
nice_candidate_to_string(const NiceCandidate * candidate)
{
  if (candidate == NULL)
    return NULL;

  gchar buf[1024];
  GString * s = g_string_new("candidate");
  g_string_append_printf(s, " foundation:%s", candidate->foundation);
  if (candidate->priority)
    g_string_append_printf(s, " priority:%u", candidate->priority);
  g_string_append_printf(s, " transport:%s", candidate_transport_to_string(candidate->transport));
  g_string_append_printf(s, " type:%s", candidate_type_to_string(candidate->type));

  if (candidate->type == NICE_CANDIDATE_TYPE_RELAYED){
    g_string_append_printf(s, " relay_type:%s", _candidate_relay_type_to_string(candidate->turn->type));
    nice_address_to_string(&candidate->turn->server, buf);
    g_string_append_printf(s, " relay_addr:'%s:%d'", buf, nice_address_get_port(&candidate->turn->server));
  }

  nice_address_to_string(&candidate->addr, buf);
  g_string_append_printf(s, " addr:'%s:%d'", buf, nice_address_get_port(&candidate->addr));
  nice_address_to_string(&candidate->base_addr, buf);
  g_string_append_printf(s, " base_addr:'%s:%d'", buf, nice_address_get_port(&candidate->base_addr));

  return g_string_free(s, FALSE);
}
