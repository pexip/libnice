/*
 * This file is part of the Nice GLib ICE library.
 *
 * Unit test for the TURN refresh-interval calculation in
 * agent/conncheck.c::priv_turn_lifetime_to_refresh_interval().
 *
 * Background:
 *   Given a TURN allocation lifetime L (seconds, as returned by the
 *   server in an Allocate or Refresh response), libnice schedules the
 *   next Refresh to be sent priv_turn_lifetime_to_refresh_interval(L)
 *   milliseconds later. Historically this returned `(L - 30) * 1000`,
 *   despite a comment in the same file claiming "1 minute before
 *   expiry". On lossy paths 30 s is not enough to absorb a STUN
 *   retransmission cycle (default timer is 600 ms doubling, 3
 *   retransmissions ≈ 9 s) and a possible 438 round trip. There was
 *   also no guard against integer underflow if L < 30.
 *
 *   The formula was rewritten to:
 *     - if L <= 20: refresh in 1 s (degenerate input)
 *     - else: refresh after min(L/2, L - 10) seconds, never < 5 s
 *
 *   This file enforces the *invariants* the new formula must satisfy:
 *     I1. result is strictly less than L (never refresh exactly at
 *         expiry or after).
 *     I2. result + 10 s margin never exceeds L (always at least 10 s
 *         of safety margin to retry before the server times us out)
 *         for non-degenerate inputs.
 *     I3. result is at most L/2 for non-degenerate inputs (refresh in
 *         the first half of the lifetime, so a single failure plus
 *         retry still has time to complete).
 *     I4. result is never zero / never underflows.
 *     I5. for the canonical lifetime of 600 s (RFC 5766 §6.1
 *         recommended) the result is between 5000 ms and 300000 ms.
 *
 *   These properties are tested against a copy of the production
 *   formula. If the production formula changes in conncheck.c, this
 *   copy MUST be kept in sync — the comment at the top of the helper
 *   below makes that requirement explicit.
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
#include <stdint.h>
#include <stdlib.h>

/*
 * EXACT MIRROR of agent/conncheck.c::priv_turn_lifetime_to_refresh_interval.
 *
 * If you change one, you MUST change the other. The point of this
 * mirror is so that the invariants below can be enforced as plain
 * unit-tested properties without exposing the static function.
 */
static uint32_t
mirror_lifetime_to_refresh_interval (uint32_t lifetime)
{
  uint32_t interval_s;

  if (lifetime <= 20)
    return 1000;

  interval_s = lifetime / 2;
  if (interval_s + 10 > lifetime)
    interval_s = lifetime - 10;
  if (interval_s < 5)
    interval_s = 5;

  return interval_s * 1000;
}

static void
check_invariants_for (uint32_t lifetime)
{
  uint32_t result_ms = mirror_lifetime_to_refresh_interval (lifetime);
  uint32_t result_s = result_ms / 1000;

  /* I4: never zero / never underflows. */
  g_assert_cmpuint (result_ms, >, 0);

  /* Degenerate-input branch is exempt from I1..I3. */
  if (lifetime <= 20) {
    g_assert_cmpuint (result_ms, ==, 1000);
    return;
  }

  /* I1: result must be strictly less than the lifetime. */
  g_assert_cmpuint (result_s, <, lifetime);

  /* I2: at least 10 s of safety margin. */
  g_assert_cmpuint (result_s + 10, <=, lifetime);

  /* I3: refresh in the first half of the lifetime. */
  g_assert_cmpuint (result_s * 2, <=, lifetime);
}

int
main (void)
{
  /* I5: canonical RFC 5766 lifetime sanity. */
  uint32_t r600 = mirror_lifetime_to_refresh_interval (600);
  g_assert_cmpuint (r600, >=, 5000);
  g_assert_cmpuint (r600, <=, 300000);

  /* Spot-checks vs. the old (buggy) formula. */
  /* Old: (600 - 30) * 1000 = 570000. New must be much smaller. */
  g_assert_cmpuint (r600, <, 570000);

  /* Boundary: lifetime == 0 must not underflow uint32_t arithmetic. */
  g_assert_cmpuint (mirror_lifetime_to_refresh_interval (0), >, 0);

  /* Boundary: lifetime == 1, 2, 5, 10, 20, 21 — the degenerate-vs-
   * normal switchover. The previous formula would have returned
   * (1 - 30) * 1000 = a huge number due to underflow. */
  check_invariants_for (0);
  check_invariants_for (1);
  check_invariants_for (5);
  check_invariants_for (10);
  check_invariants_for (20);
  check_invariants_for (21);
  check_invariants_for (30);
  check_invariants_for (60);
  check_invariants_for (120);
  check_invariants_for (300);
  check_invariants_for (600);
  check_invariants_for (3600);
  check_invariants_for (UINT32_MAX);

  return EXIT_SUCCESS;
}
