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

NICEAPI_EXPORT gboolean
nice_candidate_set_addr (NiceCandidate *candidate, const gchar *addr, guint port)
{
  return _set_addr (&candidate->addr, addr, port);
}

NICEAPI_EXPORT gboolean
nice_candidate_set_base_addr (NiceCandidate *candidate, const gchar *addr, guint port)
{
  return _set_addr (&candidate->base_addr, addr, port);
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
