/*
 * main_loop_thread.c - Source for interface discovery code
 *
 * Copyright (C) 2020 Pexip
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "main_loop_thread.h"

static gpointer nice_main_loop_thread_run(gpointer thread_data);

NiceMainLoopThread *
nice_main_loop_thread_new (NiceAgent *agent)
{
  NiceMainLoopThread *thread;

  thread = g_slice_new0 (NiceMainLoopThread);
  thread->context= g_main_context_new ();
  thread->loop = g_main_loop_new (thread->context, FALSE);
  thread->agent = g_object_ref(agent);
  thread->thread = g_thread_new ("NiceMLSocketDisp", nice_main_loop_thread_run, thread);

  return thread;
}

void
nice_main_loop_thread_socket_set (NiceMainLoopThread * thread, NiceSocket *socket)
{
	g_assert (thread->socket == NULL);
	thread->socket = socket;
}

static gboolean
nice_main_loop_thread_stop_main_loop (gpointer data)
{
  NiceMainLoopThread *thread = (NiceMainLoopThread*) data;
  g_main_loop_quit (thread->loop);

  return FALSE;
}

static void
nice_main_loop_thread_stop(NiceMainLoopThread * thread)
{
  GSource *idle = g_idle_source_new ();
  g_assert (idle != NULL);
  g_source_set_priority (idle, G_PRIORITY_HIGH);
  g_source_set_callback (idle, nice_main_loop_thread_stop_main_loop, thread, NULL);
  g_assert (g_source_attach (idle, thread->context) > 0);

  g_thread_join (thread->thread);

  g_source_destroy (idle);
  g_source_unref (idle);
}

void
nice_main_loop_thread_free (NiceMainLoopThread * thread)
{
  // TODO: Stop thread & more cleanup
  nice_main_loop_thread_stop(thread);
  g_main_context_unref(thread->context);
  g_main_loop_unref(thread->loop);
  g_object_unref(thread->agent);
  g_free (thread);
}

static gpointer nice_main_loop_thread_run(gpointer thread_data)
{
  NiceMainLoopThread *thread = (NiceMainLoopThread*) thread_data;
  g_main_loop_run (thread->loop);
  return NULL;
}

