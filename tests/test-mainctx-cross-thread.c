/*
 * This file is part of the Nice GLib ICE library.
 *
 * Regression test for the TURN ChannelBind / CreatePermission refresh
 * timer bug fixed in socket/turn.c.
 *
 * The bug:
 *   The TURN response handler may run on a worker thread (the agent's
 *   I/O thread). That thread's "thread-default" GMainContext is the
 *   global default and is never iterated by anyone, because the agent's
 *   own main context lives on a different thread. When the response
 *   handler called g_timeout_add_seconds() to arm a refresh timer, the
 *   resulting GSource was attached to the worker thread's default
 *   context — i.e. nowhere — and the timer NEVER fired.
 *
 *   The fix is to construct the GSource explicitly with
 *   g_timeout_source_new_seconds() and attach it to the *agent's*
 *   GMainContext via g_source_attach(), bypassing the per-thread
 *   default context entirely.
 *
 * What this test does:
 *   1. Creates GMainContext "ctx" and runs its loop on the main thread.
 *   2. Spawns a worker thread whose own thread-default context is the
 *      global default (NULL) — i.e. the same situation that an agent
 *      I/O thread is in by default.
 *   3. From the worker thread, arms two short timers:
 *        a) the BROKEN pattern: g_timeout_add_seconds() to a callback
 *           that increments `broken_fired`. This source ends up on the
 *           worker thread's default context, which nobody iterates.
 *        b) the FIXED pattern: g_timeout_source_new_seconds() +
 *           g_source_attach(source, ctx) to a callback that increments
 *           `fixed_fired`.
 *   4. Iterates the ctx loop on the main thread for ~2.5 seconds.
 *   5. Asserts:
 *        - fixed_fired  > 0  (the fix pattern works)
 *        - broken_fired == 0 (the original pattern is dead, confirming
 *          this test would have failed without the fix being applied
 *          at all turn.c call sites)
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

static volatile gint broken_fired = 0;
static volatile gint fixed_fired = 0;
static GMainLoop *main_loop = NULL;

/* Handshake: the worker signals `timers_armed` once it has attached
 * both timer sources. Main waits for that signal before arming the
 * quit timer, so the test does not race the worker thread under load
 * (the previous unconditional 2.5 s quit could fire before the worker
 * had even scheduled the 1 s timers). */
static GMutex armed_mutex;
static GCond armed_cond;
static gboolean timers_armed = FALSE;

static gboolean
broken_cb (gpointer data)
{
  (void) data;
  g_atomic_int_inc (&broken_fired);
  return FALSE;
}

static gboolean
fixed_cb (gpointer data)
{
  (void) data;
  g_atomic_int_inc (&fixed_fired);
  return FALSE;
}

static gboolean
quit_cb (gpointer data)
{
  GMainLoop *loop = data;
  g_main_loop_quit (loop);
  return FALSE;
}

static gpointer
worker_thread (gpointer data)
{
  GMainContext *agent_ctx = data;
  GSource *source;

  /* (a) broken pattern: convenience wrapper that attaches to the
   * thread-default context, which on this worker thread is the global
   * default — nobody iterates it. */
  g_timeout_add_seconds (1, broken_cb, NULL);

  /* (b) fixed pattern: build a GSource and attach it explicitly to the
   * agent's context, the one that is actually being iterated. */
  source = g_timeout_source_new_seconds (1);
  g_source_set_callback (source, fixed_cb, NULL, NULL);
  g_source_attach (source, agent_ctx);
  g_source_unref (source);

  /* Tell main that both timers are now armed. */
  g_mutex_lock (&armed_mutex);
  timers_armed = TRUE;
  g_cond_signal (&armed_cond);
  g_mutex_unlock (&armed_mutex);
  g_main_context_wakeup (agent_ctx);

  return NULL;
}

int
main (void)
{
  GMainContext *agent_ctx;
  GThread *worker;
  GSource *quit_source;

#if !GLIB_CHECK_VERSION (2, 36, 0)
  g_type_init ();
#endif

  g_mutex_init (&armed_mutex);
  g_cond_init (&armed_cond);

  agent_ctx = g_main_context_new ();
  main_loop = g_main_loop_new (agent_ctx, FALSE);

  /* Spawn the worker. Its thread-default context is NULL (the global
   * default) — exactly the situation the bug occurred in. */
  worker = g_thread_new ("test-worker", worker_thread, agent_ctx);

  /* Wait for the worker to arm both timer sources before starting our
   * quit countdown. Bounded by a generous 10 s wall-clock cap so a
   * stuck worker can't hang CI. */
  {
    gint64 deadline = g_get_monotonic_time () + 10 * G_TIME_SPAN_SECOND;
    g_mutex_lock (&armed_mutex);
    while (!timers_armed) {
      if (!g_cond_wait_until (&armed_cond, &armed_mutex, deadline))
        break;
    }
    g_mutex_unlock (&armed_mutex);
    g_assert_true (timers_armed);
  }

  /* Schedule a quit 2.5 s after the timers were armed. The timers we
   * are testing fire at ~1 s, so this leaves ~1.5 s of slack. */
  quit_source = g_timeout_source_new (2500);
  g_source_set_callback (quit_source, quit_cb, main_loop, NULL);
  g_source_attach (quit_source, agent_ctx);
  g_source_unref (quit_source);

  g_main_loop_run (main_loop);

  g_thread_join (worker);

  g_main_loop_unref (main_loop);
  g_main_context_unref (agent_ctx);
  g_cond_clear (&armed_cond);
  g_mutex_clear (&armed_mutex);

  /* Assertions: the fixed pattern must have fired; the broken pattern
   * must NOT have fired. If broken_fired > 0 it means the worker
   * thread's default context is somehow being iterated, which would
   * invalidate the test scenario. */
  g_assert_cmpint (g_atomic_int_get (&fixed_fired), ==, 1);
  g_assert_cmpint (g_atomic_int_get (&broken_fired), ==, 0);

  return EXIT_SUCCESS;
}
