/*
 * Lightweight abstraction over GStreamers buffer lists / buffer pools to allow
 * allocating buffers for use with recvmmsg.
 * This file is part of the Nice GLib ICE library.
 *
 *
 * (C) 2022 Pexip AS
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
 *   Frederik Vestre, Pexip AS
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

#ifndef _NICE_MEMLIST_H
#define _NICE_MEMLIST_H

#include <glib.h>

typedef struct _MemlistInterface MemlistInterface;
typedef void NiceMemoryBufferRef;
/* Libnice expects the buffers received trough the interface to be accessable until they are either
   returned though nice_return_memory_buffer or by passing them as a result of a read operation.
   All buffers will be returned when the corresponding agent is destroyed */
typedef NiceMemoryBufferRef* (*nice_memory_buffer_get)(MemlistInterface *interface, gsize size);
/* Return a memory buffer to the provider */
typedef void (*nice_memory_buffer_return)(MemlistInterface *interface, NiceMemoryBufferRef* buffer);
/* Get a pointer to the contents (i.e. bytes) of the memory buffer */
typedef char* (*nice_memory_buffer_contents)(MemlistInterface *interface, NiceMemoryBufferRef* buffer);
/* Get the size of the memory buffer */
typedef gsize (*nice_memory_buffer_size)(MemlistInterface *interface, NiceMemoryBufferRef* buffer);
typedef gsize (*nice_memory_memlist_unref)(MemlistInterface *interface);

struct _MemlistInterface {
     nice_memory_buffer_get buffer_get;
     nice_memory_buffer_return buffer_return;
     nice_memory_buffer_contents buffer_contents;
     nice_memory_buffer_size buffer_size;
     nice_memory_memlist_unref unref;
};
#endif /* _NICE_MEMLIST_H */

