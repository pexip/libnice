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
#endif

#include <string.h>

#include "stream.h"
#include "conncheck.h"
#include "agent-priv.h"

/*
 * @file stream.c
 * @brief ICE stream functionality
 */
Stream *
stream_new (NiceAgent * agent, guint n_components)
{
  Stream *stream;
  guint n;
  Component *component;

  stream = g_slice_new0 (Stream);
  for (n = 0; n < n_components; n++) {
    component = component_new (n + 1, agent->main_context, agent->async);
    stream->components = g_slist_append (stream->components, component);
  }

  stream->n_components = n_components;
  stream->initial_binding_request_received = FALSE;
  stream->max_tcp_queue_size = NICE_STREAM_DEF_MAX_TCP_QUEUE;
  stream->trickle_ice = FALSE;
  return stream;
}

void
stream_free (Stream *stream)
{
  GSList *i;

  for (i = stream->local_addresses; i; i = i->next)
  {
    NiceAddress *a = i->data;
    nice_address_free (a);
  }
  g_slist_free (stream->local_addresses);
  stream->local_addresses = NULL;

  for (i = stream->components; i; i = i->next) {
    Component *component = i->data;
    component_free (component);
    i->data = NULL;
  }
  g_slist_free (stream->components);
  g_slice_free (Stream, stream);
}

Component *
stream_find_component_by_id (const Stream *stream, guint id)
{
  GSList *i;

  for (i = stream->components; i; i = i->next) {
    Component *component = i->data;
    if (component && component->id == id)
      return component;
  }

  return NULL;
}

/*
 * Returns true if all components of the stream are either
 * 'CONNECTED' or 'READY' (connected plus nominated).
 */
gboolean
stream_all_components_ready (const Stream *stream)
{
  GSList *i;

  for (i = stream->components; i; i = i->next) {
    Component *component = i->data;
    if (component &&
        !(component->state == NICE_COMPONENT_STATE_CONNECTED ||
          component->state == NICE_COMPONENT_STATE_READY))
      return FALSE;
  }

  return TRUE;
}


/*
 * Initialized the local crendentials for the stream.
 */
void stream_initialize_credentials (Stream *stream, NiceRNG *rng)
{
  /* note: generate ufrag/pwd for the stream (see ICE 15.4.
   *       '"ice-ufrag" and "ice-pwd" Attributes', ID-19) */
  nice_rng_generate_bytes_print (rng, NICE_STREAM_DEF_UFRAG - 1, stream->local_ufrag);
  nice_rng_generate_bytes_print (rng, NICE_STREAM_DEF_PWD - 1, stream->local_password);
}

/*
 * Resets the stream state to that of a ICE restarted
 * session.
 */
void
stream_restart (NiceAgent *agent,
    Stream *stream, NiceRNG *rng)
{
  GSList *i;

  /* step: clean up all connectivity checks */
  conn_check_prune_stream (agent, stream);

  stream->initial_binding_request_received = FALSE;

  stream_initialize_credentials (stream, rng);

  for (i = stream->components; i; i = i->next) {
    Component *component = i->data;

    component_restart (component);
  }
}
