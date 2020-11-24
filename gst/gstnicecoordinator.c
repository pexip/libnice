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

#include <gst/gst.h>
#include <gst/base/gstpushsrc.h>

#include <nice/nice.h>
enum
{
  PROP_ASYNC_CONTEXT = 0,
};
#include <gstnicecoordinator.h>

struct _GstNiceCoordinatorClass
{
  GstElementClass parent_class;
};

typedef struct _GstNiceCoordinatorClass GstNiceCoordinatorClass;
typedef struct _GstNiceCoordinator GstNiceCoordinator;

struct _GstNiceCoordinator
{
  GstElement element;
  GstBufferPool *pool;
  GstCaps *caps;
  GAsync *async;
  GMutex lock;
};
#if 0
GBuffer* gst_nice_coordinator_alloc_read_buffer(GstNiceCoordinator *coord)
{

}
#endif

static void
gst_nice_coordinator_init (GstNiceCoordinator * coord)
{
  (void) coord;
}

static void
gst_nice_coordinator_dispose (GObject * object)
{
  GstNiceCoordinator *coord = GST_NICE_COORDINATOR_CAST (object);

  if (coord->pool)
  {
  	gst_object_unref(coord->pool);
  	coord->pool = NULL;
  }
  if (coord->caps)
  {
  	gst_caps_unref(coord->caps);
  	coord->caps = NULL;
  }
  g_object_unref(coord->async);
  G_OBJECT_GET_CLASS (object)->dispose (object);
}



static void
gst_nice_coordinator_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec)
{
  GstNiceCoordinator *coord = GST_NICE_COORDINATOR_CAST (object);

  GST_OBJECT_LOCK (coord);
  switch (property_id) {
    case PROP_ASYNC_CONTEXT:
      g_value_set_pointer (value, coord->async);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }

  GST_OBJECT_UNLOCK (coord);
}


static void
gst_nice_coordinator_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec)
{
  GstNiceCoordinator *coord = GST_NICE_COORDINATOR_CAST (object);

  GST_OBJECT_LOCK (coord);

  switch (property_id) {
    case PROP_ASYNC_CONTEXT:
      coord->async = g_value_get_pointer (value);
      if (coord->async != NULL) {
        g_object_ref (coord->async);
      }
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }

  GST_OBJECT_UNLOCK (coord);

}


static void
gst_nice_coordinator_finalize (GObject * object)
{
  // GstNiceCoordinator *coord = GST_NICE_COORDINATOR_CAST (object);

  G_OBJECT_GET_CLASS (object)->finalize (object);
}

static void
gst_nice_coordinator_class_init (GstNiceCoordinatorClass * klass)
{
  GObjectClass *gobject_class = (GObjectClass *) klass;
  GstElementClass *gstelement_class = (GstElementClass *) klass;
  gobject_class->dispose = gst_nice_coordinator_dispose;
  gobject_class->finalize = gst_nice_coordinator_finalize;
  gobject_class->get_property = gst_nice_coordinator_get_property;
  gobject_class->set_property = gst_nice_coordinator_set_property;

  gst_element_class_set_metadata (gstelement_class,
      "ICE coordinator",
      "Misc.",
      "Used to coordinate Ice sources and Sinks",
      "Frederik Vestre <frederik.vestre@pexip.com>");

  /* For udp sockets gasync objects are used to do asyncronous io */
  g_object_class_install_property (gobject_class, PROP_ASYNC_CONTEXT,
      g_param_spec_pointer ("async-transport",
          "The GAsync io context used for udp transports and timeouts",
          "The GAsync io context used for udp transports and timeouts",
          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

}

G_DEFINE_TYPE (GstNiceCoordinator, gst_nice_coordinator, GST_TYPE_ELEMENT);

GstNiceCoordinator *
gst_nice_coordinator_new (GAsync *async)
{
  GstNiceCoordinator *coord;

  coord = g_object_new (GST_TYPE_NICE_COORDINATOR, NULL);
  coord->caps = gst_caps_new_any ();
  coord->pool = NULL;
  coord->async = g_object_ref(async);
  g_mutex_init(&coord->lock);
  return coord;
}

gboolean gst_nice_coordinator_negotiate_caps(GstNiceCoordinator *coord, GstPad *pad)
{
  GstCaps *caps, *intersect;
  gboolean result = FALSE;

  caps = gst_pad_get_allowed_caps (pad);
  if (!caps)
    caps = gst_pad_get_pad_template_caps (pad);

  g_mutex_lock (&coord->lock);
  intersect = gst_caps_intersect (coord->caps, caps);
  g_mutex_unlock (&coord->lock);

  gst_caps_take (&caps, intersect);

  if (!gst_caps_is_empty (caps)) {
    if (gst_caps_is_any (caps)) {
      GST_DEBUG_OBJECT (coord, "any caps, negotiation not needed");
      result = TRUE;
    } else {
    	 if (gst_pad_push_event (pad, gst_event_new_caps (caps)))
    	 {
        	result = TRUE;
         }
    }
    gst_caps_unref (caps);
  } else {
    GST_DEBUG_OBJECT (coord, "no common caps");
  }
  if (result)
  {
  	coord->caps = caps;
  	if (coord->pool == NULL)
  	{
	  coord->pool = gst_buffer_pool_new();

	  GstAllocationParams alloc_params;
	  gst_allocation_params_init (&alloc_params);
	  alloc_params.align = GST_NICE_MAX_BUFFER_ALIGN;
	  GstStructure *pool_cfg = gst_buffer_pool_get_config (coord->pool);
	  gst_buffer_pool_config_set_params (pool_cfg, caps, GST_NICE_MAX_BUFFER_SIZE, 2, 0);
	  gst_buffer_pool_config_set_allocator (pool_cfg, NULL, &alloc_params);
	  gst_buffer_pool_set_config (coord->pool, pool_cfg);
  	}
  }
  return result;
}