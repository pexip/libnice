/*
 * This file is part of the Nice GLib ICE library.
 *
 * Unit test for the test-only TURN refresh-timeout env-var knobs declared
 * in socket/turn.c:
 *
 *   NICE_TURN_BINDING_TIMEOUT
 *   NICE_TURN_PERMISSION_TIMEOUT
 *   NICE_TURN_EXPIRE_TIMEOUT
 *
 * These knobs let an integration test shorten the ChannelBind /
 * CreatePermission refresh schedule (default 240/240/60 s) so the
 * refresh code paths can be exercised in seconds rather than the ~10 min
 * required to observe a real refresh cycle. Because they are the basis
 * for any such integration test, this file pins down their *parsing*
 * contract: which strings override the default, which fall through to
 * the default, and which are clamped.
 *
 * The parser is `static` in socket/turn.c, so this file mirrors it
 * verbatim. If you change one, you MUST change the other.
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
#include <stdlib.h>

/* Names MUST match socket/turn.c. */
#define ENV_NICE_TURN_BINDING_TIMEOUT     "NICE_TURN_BINDING_TIMEOUT"
#define ENV_NICE_TURN_PERMISSION_TIMEOUT  "NICE_TURN_PERMISSION_TIMEOUT"
#define ENV_NICE_TURN_EXPIRE_TIMEOUT      "NICE_TURN_EXPIRE_TIMEOUT"

/*
 * EXACT MIRROR of socket/turn.c::priv_env_timeout_secs.
 * If you change one, you MUST change the other.
 */
static guint
mirror_env_timeout_secs (const gchar *name, guint default_secs)
{
  const gchar *v = g_getenv (name);
  gchar *end = NULL;
  guint64 parsed;

  if (v == NULL || *v == '\0')
    return default_secs;

  parsed = g_ascii_strtoull (v, &end, 10);
  if (end == v || *end != '\0' || parsed == 0 || parsed > G_MAXUINT)
    return default_secs;

  return (guint) parsed;
}

/* Helper: set the env var to `val` (or unset if NULL), then check that
 * the parser returns `expect`. */
static void
expect (const gchar *name, const gchar *val, guint default_secs, guint expect)
{
  if (val == NULL)
    g_unsetenv (name);
  else
    g_setenv (name, val, TRUE);

  g_assert_cmpuint (mirror_env_timeout_secs (name, default_secs), ==, expect);
}

int
main (void)
{
  /* Defaults: unset / empty / non-numeric / leading-non-digit / trailing
   * garbage / zero / overflow all fall back to the supplied default. */
  expect (ENV_NICE_TURN_BINDING_TIMEOUT,    NULL,           240, 240);
  expect (ENV_NICE_TURN_BINDING_TIMEOUT,    "",             240, 240);
  expect (ENV_NICE_TURN_BINDING_TIMEOUT,    "abc",          240, 240);
  expect (ENV_NICE_TURN_BINDING_TIMEOUT,    "12abc",        240, 240);
  expect (ENV_NICE_TURN_BINDING_TIMEOUT,    "0",            240, 240);
  expect (ENV_NICE_TURN_BINDING_TIMEOUT,    "99999999999",  240, 240);

  /* Positive integer values override. */
  expect (ENV_NICE_TURN_BINDING_TIMEOUT,    "1",            240, 1);
  expect (ENV_NICE_TURN_PERMISSION_TIMEOUT, "2",            240, 2);
  expect (ENV_NICE_TURN_EXPIRE_TIMEOUT,     "3",            60,  3);

  /* Each knob is read by name, so the three are independent. */
  g_setenv (ENV_NICE_TURN_BINDING_TIMEOUT,    "11", TRUE);
  g_setenv (ENV_NICE_TURN_PERMISSION_TIMEOUT, "22", TRUE);
  g_setenv (ENV_NICE_TURN_EXPIRE_TIMEOUT,     "33", TRUE);
  g_assert_cmpuint (
      mirror_env_timeout_secs (ENV_NICE_TURN_BINDING_TIMEOUT, 240),
      ==, 11);
  g_assert_cmpuint (
      mirror_env_timeout_secs (ENV_NICE_TURN_PERMISSION_TIMEOUT, 240),
      ==, 22);
  g_assert_cmpuint (
      mirror_env_timeout_secs (ENV_NICE_TURN_EXPIRE_TIMEOUT, 60),
      ==, 33);

  /* Boundary: G_MAXUINT itself is accepted; G_MAXUINT + 1 is not.
   * Build the strings dynamically to stay portable across 32/64-bit
   * `guint`. */
  {
    gchar *max_str = g_strdup_printf ("%u", G_MAXUINT);
    gchar *over_str = g_strdup_printf ("%" G_GUINT64_FORMAT,
        (guint64) G_MAXUINT + 1);
    expect (ENV_NICE_TURN_BINDING_TIMEOUT, max_str,  240, G_MAXUINT);
    expect (ENV_NICE_TURN_BINDING_TIMEOUT, over_str, 240, 240);
    g_free (max_str);
    g_free (over_str);
  }

  /* Cleanup so we don't leak overrides into anything that runs after. */
  g_unsetenv (ENV_NICE_TURN_BINDING_TIMEOUT);
  g_unsetenv (ENV_NICE_TURN_PERMISSION_TIMEOUT);
  g_unsetenv (ENV_NICE_TURN_EXPIRE_TIMEOUT);

  return EXIT_SUCCESS;
}
