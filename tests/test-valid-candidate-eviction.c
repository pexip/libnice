/*
 * This file is part of the Nice GLib ICE library.
 *
 * Regression test for eviction of the nominated pair's remote candidate from
 * Component::valid_candidates.
 *
 * nice_component_verify_remote_candidate() accepts a packet only if its source
 * address appears in Component::valid_candidates. That list is capped at
 * NICE_COMPONENT_MAX_VALID_CANDIDATES and trimmed from the tail by
 * nice_component_add_valid_candidate().
 *
 * A candidate is moved to the head of the list only when a packet from it is
 * verified, so the nominated pair's remote stays wherever it was inserted until
 * the first media packet arrives. If enough other candidates are validated in
 * that window the nominated remote reaches the tail and is evicted, and every
 * subsequent packet from the peer is dropped as an unknown source for the rest
 * of the call - silently, since the drop returns 0 with no error and no counter.
 *
 * That window is easy to hit when a peer opens one transport per stream and
 * probes them all: each distinct source port becomes a peer-reflexive candidate.
 * With 8 audio + 8 video streams a single component was observed accumulating 51
 * candidates against the cap of 50, i.e. it failed by one.
 *
 * (C) 2026 Pexip AS.
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <glib.h>

#include "agent-priv.h"
#include "component.h"

#define TEST_PEER_ADDR      "192.0.2.1"
#define TEST_NOMINATED_PORT 40004
#define TEST_PRFLX_BASE_PORT 40100

static NiceCandidate *
make_candidate (guint port, NiceCandidateType type)
{
  NiceCandidate *candidate = nice_candidate_new (type);

  candidate->stream_id = 1;
  candidate->component_id = NICE_COMPONENT_TYPE_RTP;
  g_assert_true (nice_address_set_from_string (&candidate->addr,
          TEST_PEER_ADDR));
  nice_address_set_port (&candidate->addr, port);

  return candidate;
}

/* Validates candidates the peer never sends media from, as connectivity checks
 * from one transport per stream do. The agent is only used for logging, so NULL
 * is fine here. */
static void
flood_with_peer_reflexive (Component *component, guint count)
{
  guint i;

  for (i = 0; i < count; i++) {
    NiceCandidate *prflx = make_candidate (TEST_PRFLX_BASE_PORT + i,
        NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);

    nice_component_add_valid_candidate (NULL, component, prflx);
    nice_candidate_free (prflx);
  }
}

static void
test_nominated_remote_survives_flood (void)
{
  Component *component = component_new (NICE_COMPONENT_TYPE_RTP);
  NiceCandidate *remote = make_candidate (TEST_NOMINATED_PORT,
      NICE_CANDIDATE_TYPE_HOST);

  /* Nominate the pair, as component_update_selected_pair() does. */
  component->selected_pair.remote = remote;
  nice_component_add_valid_candidate (NULL, component, remote);

  g_assert_true (nice_component_verify_remote_candidate (component,
          &remote->addr, NULL));

  /* No media has arrived yet, so the nominated remote is never promoted and
   * ages towards the tail as the flood is prepended. */
  flood_with_peer_reflexive (component, NICE_COMPONENT_MAX_VALID_CANDIDATES * 2);

  /* Before the fix the nominated remote had been trimmed off the tail and this
   * failed, dropping every media packet for the remainder of the call. */
  g_assert_true (nice_component_verify_remote_candidate (component,
          &remote->addr, NULL));

  component->selected_pair.remote = NULL;
  nice_candidate_free (remote);
  component_free (component);
}

/* The fix must not turn the cap into an unbounded list. */
static void
test_list_is_still_bounded (void)
{
  Component *component = component_new (NICE_COMPONENT_TYPE_RTP);
  NiceCandidate *remote = make_candidate (TEST_NOMINATED_PORT,
      NICE_CANDIDATE_TYPE_HOST);

  component->selected_pair.remote = remote;
  nice_component_add_valid_candidate (NULL, component, remote);

  flood_with_peer_reflexive (component, NICE_COMPONENT_MAX_VALID_CANDIDATES * 4);

  g_assert_cmpuint (g_list_length (component->valid_candidates), <=,
      NICE_COMPONENT_MAX_VALID_CANDIDATES + 1);

  component->selected_pair.remote = NULL;
  nice_candidate_free (remote);
  component_free (component);
}

/* Without a nominated pair the original tail-trimming behaviour is unchanged. */
static void
test_trims_when_no_pair_nominated (void)
{
  Component *component = component_new (NICE_COMPONENT_TYPE_RTP);
  NiceCandidate *oldest = make_candidate (TEST_NOMINATED_PORT,
      NICE_CANDIDATE_TYPE_HOST);

  nice_component_add_valid_candidate (NULL, component, oldest);
  flood_with_peer_reflexive (component, NICE_COMPONENT_MAX_VALID_CANDIDATES * 2);

  g_assert_false (nice_component_verify_remote_candidate (component,
          &oldest->addr, NULL));

  nice_candidate_free (oldest);
  component_free (component);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/valid-candidate/nominated-remote-survives-flood",
      test_nominated_remote_survives_flood);
  g_test_add_func ("/valid-candidate/list-is-still-bounded",
      test_list_is_still_bounded);
  g_test_add_func ("/valid-candidate/trims-when-no-pair-nominated",
      test_trims_when_no_pair_nominated);

  return g_test_run ();
}
