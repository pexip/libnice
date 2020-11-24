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
typedef enum
{
  GST_NICE_SRC_POLL_EMPTY = 0,
  GST_NICE_SRC_POLL_PROCESSED,
  GST_NICE_SRC_POLL_SYSTEM_PROCESSED,
  GST_NICE_SRC_POLL_PAUSED,
  GST_NICE_SRC_POLL_EOS,
} GstNiceSrcPollState;

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

typedef struct _GstNiceSrc GstNiceSrc;

typedef struct _GstNiceSrcClass GstNiceSrcClass;

GType gst_nice_src_get_type (void);

GstNiceSrcPollState gst_nice_src_poll (GstNiceSrc* src);

/* TODO: Add more parameters */
void gst_nice_src_handle_receive (GstNiceSrc* src);

G_DECLARE_FINAL_TYPE (GstNiceSrcPad, gst_nice_src_pad,
    GST, NICE_SRC_PAD, GstPad)
#define GST_TYPE_NICE_SRC_PAD (gst_nice_src_pad_get_type())
#define GST_NICE_SRC_PAD_CAST(obj) ((GstNiceSrcPad *)(obj))

typedef struct _GstNiceSrcPad GstNiceSrcPad;

G_END_DECLS

#endif // _GSTNICESRC_H

