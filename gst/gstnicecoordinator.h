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

#ifndef _GSTNICECOORDINATOR_H
#define _GSTNICECOORDINATOR_H

#include <gst/gst.h>
#include <gst/base/gstpushsrc.h>

#include <nice/nice.h>

G_BEGIN_DECLS
#define GST_NICE_MAX_BUFFER_SIZE 65536
#define GST_NICE_MAX_BUFFER_ALIGN 32

#define GST_TYPE_NICE_COORDINATOR \
  (gst_nice_coordinator_get_type())
#define GST_NICE_COORDINATOR(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_NICE_COORDINATOR,GstNiceCoordinator))
#define GST_NICE_COORDINATOR_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_NICE_COORDINATOR,GstNiceCoordinatorClass))
#define GST_IS_NICE_COORDINATOR(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_NICE_COORDINATOR))
#define GST_IS_NICE_COORDINATOR_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_NICE_COORDINATOR))
#define GST_NICE_COORDINATOR_CAST(obj) \
  ((GstNiceCoordinator *)(obj))

typedef struct _GstNiceCoordinator GstNiceCoordinator;

gboolean gst_nice_coordinator_negotiate_caps(GstNiceCoordinator *coord, GstPad *pad);

G_END_DECLS

#endif // _GSTNICECOORDINATOR_H

