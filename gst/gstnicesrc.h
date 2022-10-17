/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
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

#ifndef _GSTNICESRC_H
#define _GSTNICESRC_H

#include <gst/gst.h>
#include <gst/base/gstpushsrc.h>

#include <nice/nice.h>

G_BEGIN_DECLS
#define GST_NICE_SRC_MEM_BUFFERS_PREALLOCATED 32

#define GST_TYPE_NICE_SRC \
  (gst_nice_src_get_type())
#define GST_NICE_SRC(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_NICE_SRC,GstNiceSrc))
#define GST_NICE_SRC_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_NICE_SRC,GstNiceSrcClass))
#define GST_IS_NICE_SRC(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_NICE_SRC))
#define GST_IS_NICE_SRC_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_NICE_SRC))
#define GST_NICE_SRC_CAST(obj) \
  ((GstNiceSrc *)(obj))
#define GST_NICE_SRC_GET_CLASS(obj) \
      (G_TYPE_INSTANCE_GET_CLASS ((obj), GST_TYPE_NICE_SRC, GstNiceSrcClass))

typedef struct _GstNiceSrc GstNiceSrc;

typedef struct _GstNiceSrcMemoryBufferRef GstNiceSrcMemoryBufferRef;

struct _GstNiceSrcMemoryBufferRef{
  GstBuffer *buffer;
  GstMapInfo buf_map;
};

struct _GstNiceMemlistInterface{
  /* This must be first in struct for upcasts to work */
  const MemlistInterface *function_interface;
  /* When embedded in GstNiceSrc this will be a self referencing pointer,
    that is not refcounted */
  GstNiceSrc *gst_src;
  /* Pointers to  GstNiceSrcMemoryBufferRefs that have been returned that are 
     waiting to be given out again. It is assumed that the buffer and mapping 
     refed to by the reference is in an unintitialised state */
  GArray *temp_refs;
  /* Buffer variables needed for allocating and releasing buffers trough a pool */
  GstAllocator *allocator;
  GstAllocationParams params;
  GstBufferPool *pool;

};

struct _GstNiceSrc
{
  GstBaseSrc parent;
  GstPad *srcpad;
  NiceAgent *agent;
  guint stream_id;
  guint component_id;
  GMainContext *mainctx;
  GMainLoop *mainloop;
  GQueue *outbufs;
  gboolean unlocked;
  GSource *idle_source;
  GstCaps *caps;
  GHashTable *socket_addresses;
#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
  struct _GstNiceMemlistInterface mem_list_interface;
  gboolean mem_list_interface_set;
#endif
};

typedef struct _GstNiceSrcClass GstNiceSrcClass;

struct _GstNiceSrcClass
{
  GstBaseSrcClass parent_class;
};

GType gst_nice_src_get_type (void);

G_END_DECLS

#endif // _GSTNICESRC_H

