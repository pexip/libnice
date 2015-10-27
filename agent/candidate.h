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

#ifndef _CANDIDATE_H
#define _CANDIDATE_H


/**
 * SECTION:candidate
 * @short_description: ICE candidate representation
 * @see_also: #NiceAddress
 * @stability: Stable
 *
 * A representation of an ICE candidate. Make sure you read the ICE drafts[1] to
 * understand correctly the concept of ICE candidates.
 *
 * [1] http://tools.ietf.org/wg/mmusic/draft-ietf-mmusic-ice/
 */


G_BEGIN_DECLS

#define NICE_TYPE_CANDIDATE \
  (nice_candidate_get_type ())

/*
 * As per RFC 6544 section 4.2 adjust type preference so that UDP
 * is always preferred to any TCP candidate
 */
#define NICE_CANDIDATE_TYPE_PREF_HOST                 120
#define NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE       110
#define NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE     100
#define NICE_CANDIDATE_TYPE_PREF_RELAYED               60

#define NICE_CANDIDATE_TYPE_PREF_HOST_TCP              50
#define NICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE_TCP    40
#define NICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE_TCP  30
#define NICE_CANDIDATE_TYPE_PREF_RELAYED_TCP            0

#define NICE_CANDIDATE_OC2007R2_TYPE_PREF_HOST                 120
#define NICE_CANDIDATE_OC2007R2_TYPE_PREF_PEER_REFLEXIVE       100
#define NICE_CANDIDATE_OC2007R2_TYPE_PREF_SERVER_REFLEXIVE      60
#define NICE_CANDIDATE_OC2007R2_TYPE_PREF_RELAYED              110

/*
 * These are set deliberately low so that they are out ranked by the
 * priority that lync assigns to it's UDP relay candidates. The result
 * of this is that Lync -> MCU calls should prefer relayed-UDP paths to
 * non-relayed TCP paths
 *
 * We assign TCP active candidates a higher priority in our SDP but that
 * priority will never actually be used since the local type for a
 * TCP active candidate will always be peer reflexive (since we connect
 * from an ephemeral port). Therefore we assign higher priority to peer
 * reflexive than to host to make ICE converge quicker when using TCP.
 */
#define NICE_CANDIDATE_OC2007R2_TYPE_PREF_HOST_TCP               8
#define NICE_CANDIDATE_OC2007R2_TYPE_PREF_PEER_REFLEXIVE_TCP     9
#define NICE_CANDIDATE_OC2007R2_TYPE_PREF_SERVER_REFLEXIVE_TCP   7
#define NICE_CANDIDATE_OC2007R2_TYPE_PREF_RELAYED_TCP            0

/* Max foundation size '1*32ice-char' plus terminating NULL, ICE ID-19  */
/**
 * NICE_CANDIDATE_MAX_FOUNDATION:
 *
 * The maximum size a candidate foundation can have.
 */
#define NICE_CANDIDATE_MAX_FOUNDATION                32+1


/**
 * NiceCandidateType:
 * @NICE_CANDIDATE_TYPE_HOST: A host candidate
 * @NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: A server reflexive candidate
 * @NICE_CANDIDATE_TYPE_PEER_REFLEXIVE: A peer reflexive candidate
 * @NICE_CANDIDATE_TYPE_RELAYED: A relay candidate
 *
 * An enum represneting the type of a candidate
 */
typedef enum
{
  NICE_CANDIDATE_TYPE_HOST,
  NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
  NICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
  NICE_CANDIDATE_TYPE_RELAYED,
} NiceCandidateType;

/**
 * NiceCandidateTransport:
 * @NICE_CANDIDATE_TRANSPORT_UDP: UDP transport
 * @NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE: TCP Active transport
 * @NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE: TCP Passive transport
 * @NICE_CANDIDATE_TRANSPORT_TCP_SO: TCP Simultaneous-Open transport
 *
 * An enum representing the type of transport to use
 */
typedef enum
{
  NICE_CANDIDATE_TRANSPORT_UDP = 1,
  NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE = 2,
  NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE = 4
} NiceCandidateTransport;

/**
 * NiceRelayType:
 * @NICE_RELAY_TYPE_TURN_UDP: A TURN relay using UDP
 * @NICE_RELAY_TYPE_TURN_TCP: A TURN relay using TCP
 * @NICE_RELAY_TYPE_TURN_TLS: A TURN relay using TLS over TCP
 *
 * An enum representing the type of relay to use
 */
typedef enum {
  NICE_RELAY_TYPE_TURN_UDP,
  NICE_RELAY_TYPE_TURN_TCP,
  NICE_RELAY_TYPE_TURN_TLS
} NiceRelayType;


typedef struct _NiceCandidate NiceCandidate;

typedef struct _TurnServer TurnServer;

/**
 * TurnServer:
 * @server: The #NiceAddress of the TURN server
 * @username: The TURN username
 * @password: The TURN password
 * @type: The #NiceRelayType of the server
 *
 * A structure to store the TURN relay settings
 */
struct _TurnServer
{
  NiceAddress server;
  gchar *username;
  gchar *password;
  NiceRelayType type;
};

/**
 * NiceCandidate:
 * @type: The type of candidate
 * @transport: The transport being used for the candidate
 * @addr: The #NiceAddress of the candidate
 * @base_addr: The #NiceAddress of the base address used by the candidate
 * @priority: The priority of the candidate <emphasis> see note </emphasis>
 * @stream_id: The ID of the stream to which belongs the candidate
 * @component_id: The ID of the component to which belongs the candidate
 * @foundation: The foundation of the candidate
 * @username: The candidate-specific username to use (overrides the one set
 * by nice_agent_set_local_credentials() or nice_agent_set_remote_credentials())
 * @password: The candidate-specific password to use (overrides the one set
 * by nice_agent_set_local_credentials() or nice_agent_set_remote_credentials())
 * @turn: The #TurnServer settings if the candidate is
 * of type %NICE_CANDIDATE_TYPE_RELAYED
 * @sockptr: The underlying socket
 *
 * A structure to represent an ICE candidate
 <note>
   <para>
   The @priority is an integer as specified in the ICE draft 19. If you are
   using the MSN or the GOOGLE compatibility mode (which are based on ICE
   draft 6, which uses a floating point qvalue as priority), then the @priority
   value will represent the qvalue multiplied by 1000.
   </para>
 </note>
 */
struct _NiceCandidate
{
  NiceCandidateType type;
  NiceCandidateTransport transport;
  NiceAddress addr;
  NiceAddress base_addr;
  guint32 priority;
  guint stream_id;
  guint component_id;
  gchar foundation[NICE_CANDIDATE_MAX_FOUNDATION];
  gchar *username;        /* pointer to a NULL-terminated username string */
  gchar *password;        /* pointer to a NULL-terminated password string */
  TurnServer *turn;
  gpointer sockptr;
  guint local_foundation;
};

/**
 * nice_candidate_new:
 * @type: The #NiceCandidateType of the candidate to create
 *
 * Creates a new candidate. Must be freed with nice_candidate_free()
 *
 * Returns: A new #NiceCandidate
 */
NiceCandidate *
nice_candidate_new (NiceCandidateType type);

/**
 * nice_candidate_free:
 * @candidate: The candidate to free
 *
 * Frees a #NiceCandidate
 */
void
nice_candidate_free (NiceCandidate *candidate);

/**
 * nice_candidate_copy:
 * @candidate: The candidate to copy
 *
 * Makes a copy of a #NiceCandidate
 *
 * Returns: A new #NiceCandidate, a copy of @candidate
 */
NiceCandidate *
nice_candidate_copy (const NiceCandidate *candidate);

/**
 * nice_candidate_set_addr:
 * @candidate: The candidate to modify
 * @addr: The address to set
 * @port: The port to set
 *
 * Sets addr of @candidate
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
gboolean
nice_candidate_set_addr (NiceCandidate *candidate, const gchar *addr, guint port);

/**
 * nice_candidate_set_base_addr:
 * @candidate: The candidate to modify
 * @addr: The address to set
 * @port: The port to set
 *
 * Sets base_addr of @candidate
 *
 * Returns: %TRUE on success, %FALSE on failure
 */
gboolean
nice_candidate_set_base_addr (NiceCandidate *candidate, const gchar *addr, guint port);

guint64
nice_candidate_pair_priority (guint32 o_prio, guint32 a_prio);

const char *candidate_type_to_string(NiceCandidateType type);
const char *candidate_transport_to_string(NiceCandidateTransport transport);

G_END_DECLS

#endif /* _CANDIDATE_H */

