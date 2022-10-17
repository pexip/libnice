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

#ifndef _UDP_BSD_H
#define _UDP_BSD_H

#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
#define _GNU_SOURCE
#include <sys/socket.h>
#endif

#include "socket.h"
#include "agent.h"

G_BEGIN_DECLS

#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
#define NICE_UDP_SOCKET_MSG_RECEIVE_TIMES 1
#define NICE_UDP_SOCKET_MMSG_LEN 32
#else
#define NICE_UDP_SOCKET_MSG_RECEIVE_TIMES 32
#define NICE_UDP_SOCKET_MMSG_LEN 1
#endif
#define NICE_UDP_SOCKET_BUFFER_ALLOC_SIZE 1500
#define NICE_UDP_SOCKET_MMSG_TOTAL (NICE_UDP_SOCKET_MSG_RECEIVE_TIMES * NICE_UDP_SOCKET_MMSG_LEN)

NiceSocket *
nice_udp_bsd_socket_new (NiceAddress *addr);

void nice_udp_socket_interface_set(NiceSocket *udp_socket, MemlistInterface **interface);
void nice_udp_socket_buffers_and_interface_unref(NiceSocket *udp_socket);
gint nice_udp_socket_recvmmsg(NiceSocket *sock);
NiceMemoryBufferRef *nice_udp_socket_packet_retrieve(NiceSocket *udp_socket,
  guint packet_index, NiceAddress *from);
void nice_udp_socket_recvmmsg_structures_fill_new_buffers(NiceSocket *udp_socket,
  guint iter_start, guint iter_end);

G_END_DECLS

#endif /* _UDP_BSD_H */

