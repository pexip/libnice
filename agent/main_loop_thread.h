/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2020 Pexip
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

#ifndef _NICE_MAIN_LOOP_THREAD_H
#define _NICE_MAIN_LOOP_THREAD_H
/* note: this is a private header to libnice */

#include <glib.h>
#include "agent.h"
#include "socket.h"

typedef struct _NiceMainLoopThread NiceMainLoopThread;

struct _NiceMainLoopThread
{
  NiceAgent *agent;         /* back pointer to owner */
  GMainContext *context;
  GMainLoop *loop;
  NiceSocket *socket;
  GThread *thread;
};

NiceMainLoopThread *
nice_main_loop_thread_new (NiceAgent *agent);

void
nice_main_loop_thread_socket_set (NiceMainLoopThread * thread, NiceSocket *socket);

void
nice_main_loop_thread_free (NiceMainLoopThread * thread);


#endif /*_NICE_MAIN_LOOP_THREAD_H */
