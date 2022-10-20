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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "gstnicesrc.h"
#include <gst/net/gstnetaddressmeta.h>

GST_DEBUG_CATEGORY_STATIC (nicesrc_debug);
#define GST_CAT_DEFAULT nicesrc_debug


//#define BUFFER_SIZE (65536)
#define BUFFER_SIZE (4096)

static gboolean gst_nice_src_query (
  GstBaseSrc * src,
  GstQuery * query);

static GstFlowReturn gst_nice_src_create (
  GstBaseSrc * bsrc,
  guint64 offset,
  guint length,
  GstBuffer ** ret);

static GstFlowReturn gst_nice_src_alloc (
  GstBaseSrc * bsrc,
  guint64 offset,
  guint length,
  GstBuffer ** ret);

static GstFlowReturn gst_nice_src_fill (
  GstBaseSrc * bsrc,
  guint64 offset,
  guint length,
  GstBuffer * ret);

static gboolean
gst_nice_src_unlock (
    GstBaseSrc *basesrc);

static gboolean
gst_nice_src_unlock_stop (
    GstBaseSrc *basesrc);

static gboolean
gst_nice_src_decide_allocation (
  GstBaseSrc * bsrc,
  GstQuery * query);

static void
gst_nice_src_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec);

static void
gst_nice_src_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec);


static void
gst_nice_src_dispose (GObject *object);
static
void gst_nice_src_clean_up_pool(GstNiceSrc * src);

static GstStateChangeReturn
gst_nice_src_change_state (
    GstElement * element,
    GstStateChange transition);


static void gst_nice_src_mem_buffer_ref_array_clear(void *element);

NiceMemoryBufferRef* gst_nice_src_buffer_get(MemlistInterface **ml_interface, gsize size);
void gst_nice_src_buffer_return(MemlistInterface **ml_interface, NiceMemoryBufferRef* buffer);
char* gst_nice_src_buffer_contents(MemlistInterface **ml_interface, NiceMemoryBufferRef* buffer);
gsize gst_nice_src_buffer_size(MemlistInterface **ml_interface, NiceMemoryBufferRef* buffer);
void gst_nice_src_buffer_resize(MemlistInterface **ml_interface,
  NiceMemoryBufferRef* buffer, gsize new_size);

static const MemlistInterface nice_src_mem_interface = {
    .buffer_get = gst_nice_src_buffer_get,
    .buffer_return = gst_nice_src_buffer_return,
    .buffer_contents = gst_nice_src_buffer_contents,
    .buffer_size = gst_nice_src_buffer_size,
    .buffer_resize = gst_nice_src_buffer_resize,
};

static GstStaticPadTemplate gst_nice_src_src_template =
GST_STATIC_PAD_TEMPLATE (
    "src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

#define gst_nice_src_parent_class parent_class

G_DEFINE_TYPE (GstNiceSrc, gst_nice_src, GST_TYPE_BASE_SRC);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM,
  PROP_COMPONENT,
  PROP_CAPS
};

static gboolean
gst_nice_src_handle_event (GstBaseSrc *basesrc, GstEvent * event)
{
  GstNiceSrc *src = GST_NICE_SRC_CAST (basesrc);
  gboolean ret = TRUE;

  GST_LOG_OBJECT (src, "handling %s event", GST_EVENT_TYPE_NAME (event));

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_CUSTOM_UPSTREAM:
    {
      if (gst_event_has_name (event, "PexQosOverflow")) {
        GST_DEBUG_OBJECT (src, "Suspend TCP receive, QOS received");
        nice_agent_set_rx_enabled (src->agent, src->stream_id, src->component_id, FALSE);
        ret = TRUE;
      } else if (gst_event_has_name (event, "PexQosUnderflow")) {
        GST_DEBUG_OBJECT (src, "Resume TCP receive, QOS received");
        nice_agent_set_rx_enabled (src->agent, src->stream_id, src->component_id, TRUE);
        ret = TRUE;
      } else {
        ret = GST_BASE_SRC_CLASS (parent_class)->event (basesrc, event);
      }
      break;
    }

    default:
    {
      GST_LOG_OBJECT (src, "let base class handle event");
      ret = GST_BASE_SRC_CLASS (parent_class)->event (basesrc, event);
      break;
    }
  }

  return ret;
}

static void
gst_nice_src_class_init (GstNiceSrcClass *klass)
{
  GstBaseSrcClass *gstbasesrc_class;
  GstElementClass *gstelement_class;
  GObjectClass *gobject_class;

  GST_DEBUG_CATEGORY_INIT (nicesrc_debug, "nicesrc",
      0, "libnice source");

  //gstpushsrc_class = (GstPushSrcClass *) klass;
  //gstpushsrc_class->create = GST_DEBUG_FUNCPTR (gst_nice_src_create);

  gstbasesrc_class = (GstBaseSrcClass *) klass;
  gstbasesrc_class->unlock = GST_DEBUG_FUNCPTR (gst_nice_src_unlock);
  gstbasesrc_class->unlock_stop = GST_DEBUG_FUNCPTR (gst_nice_src_unlock_stop);
  //gstbasesrc_class->negotiate = GST_DEBUG_FUNCPTR (gst_nice_src_negotiate);
#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
  gstbasesrc_class->decide_allocation = GST_DEBUG_FUNCPTR (gst_nice_src_decide_allocation);
#endif
  gstbasesrc_class->event = GST_DEBUG_FUNCPTR (gst_nice_src_handle_event);

  /* Reimplementation of gstpushsrc in order to support buffer lists */
  gstbasesrc_class->create = GST_DEBUG_FUNCPTR (gst_nice_src_create);
  gstbasesrc_class->alloc = GST_DEBUG_FUNCPTR (gst_nice_src_alloc);
  gstbasesrc_class->fill = GST_DEBUG_FUNCPTR (gst_nice_src_fill);
  gstbasesrc_class->query = GST_DEBUG_FUNCPTR (gst_nice_src_query);

  gobject_class = (GObjectClass *) klass;
  gobject_class->set_property = gst_nice_src_set_property;
  gobject_class->get_property = gst_nice_src_get_property;
  gobject_class->dispose = gst_nice_src_dispose;

  gstelement_class = (GstElementClass *) klass;
  gstelement_class->change_state = gst_nice_src_change_state;

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&gst_nice_src_src_template));
  gst_element_class_set_metadata (gstelement_class,
      "ICE source",
      "Source",
      "Interactive UDP connectivity establishment",
      "Dafydd Harries <dafydd.harries@collabora.co.uk>");

  g_object_class_install_property (gobject_class, PROP_AGENT,
      g_param_spec_object (
         "agent",
         "Agent",
         "The NiceAgent this source is bound to",
         NICE_TYPE_AGENT,
         G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_STREAM,
      g_param_spec_uint (
         "stream",
         "Stream ID",
         "The ID of the stream to read from",
         0,
         G_MAXUINT,
         0,
         G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_COMPONENT,
      g_param_spec_uint (
         "component",
         "Component ID",
         "The ID of the component to read from",
         0,
         G_MAXUINT,
         0,
         G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_CAPS,
      g_param_spec_boxed (
          "caps",
          "Caps",
          "The caps of the source pad",
          GST_TYPE_CAPS,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static guint
gst_nice_src_data_hash(const char* bytes, size_t length, guint h)
{
  /* This was copied from glib byte array, and can probably be optimized
     signifcantly, e.g by hashing words (or SIMD) instead of bytes */
  const signed char *p, *e;
  if (h == 0)
  {
    h = 5381;
  }
  for (p = (signed char *)bytes, e = (signed char *)(bytes + length); p != e; p++)
  {
    h = (h << 5) + h + *p;
  }
  return h;
}

static guint
gst_nice_src_address_hash (gconstpointer key)
{
  const NiceAddress *from = (NiceAddress *)key;

  guint hash = gst_nice_src_data_hash((gpointer)&from->s.addr.sa_family, sizeof(from->s.addr.sa_family), 0);

  switch (from->s.addr.sa_family) {
    case AF_INET:
      hash = gst_nice_src_data_hash((gpointer)&from->s.ip4, sizeof (from->s.ip4), hash);
      break;
    case AF_INET6:
      hash = gst_nice_src_data_hash((gpointer)&from->s.ip6, sizeof (from->s.ip6), hash);
      break;
    default:
      GST_ERROR_OBJECT (from, "Unknown address family");
      break;
  }

  return hash;
}

static GSocketAddress*
gst_nice_src_gsocket_addr_create_or_retrieve (GstNiceSrc *src,
                                              const NiceAddress *native_addr)
{
  GSocketAddress *result = g_hash_table_lookup(src->socket_addresses,
                                               native_addr);
  if (G_UNLIKELY(result == NULL)) {
    /* Convert and insert into hash table if it is not present already */
    switch (native_addr->s.addr.sa_family) {
      case AF_INET:
        result = g_socket_address_new_from_native ((gpointer)&native_addr->s.ip4,
                                                   sizeof (native_addr->s.ip4));
        break;
      case AF_INET6:
        result = g_socket_address_new_from_native ((gpointer)&native_addr->s.ip6,
                                                   sizeof (native_addr->s.ip6));
        break;
      default:
        GST_ERROR_OBJECT (src, "Unknown address family");
        break;
    }

    if (G_UNLIKELY(result == NULL)) {
        GST_ERROR_OBJECT (src, "Could not create address gobject");
        return result;
    }

    NiceAddress *key = g_slice_new(NiceAddress);
    memcpy(key, native_addr, sizeof(NiceAddress));

    gst_object_ref(result);
    g_hash_table_insert(src->socket_addresses, key, result);
  } else {
    gst_object_ref(result);
  }
  return result;
}

static gboolean
gst_nice_src_nice_address_compare (gconstpointer a, gconstpointer b)
{
    const NiceAddress *a_addr = (const NiceAddress*)a;
    const NiceAddress *b_addr = (const NiceAddress*)b;

    if ((a_addr->s.addr.sa_family == b_addr->s.addr.sa_family))
    {
      switch (a_addr->s.addr.sa_family) {
        case AF_INET:
          return memcmp(&a_addr->s.ip4, &b_addr->s.ip4, sizeof (a_addr->s.ip4)) == 0;
        case AF_INET6:
          return memcmp(&a_addr->s.ip6, &b_addr->s.ip6, sizeof (a_addr->s.ip6)) == 0;
      }
    }
    return FALSE;
}

static void
gst_nice_src_destroy_hash_key(void *key)
{
  g_slice_free(NiceAddress, key);
}

static void
gst_nice_src_init (GstNiceSrc *src)
{
  gst_base_src_set_live (GST_BASE_SRC (src), TRUE);
  gst_base_src_set_format (GST_BASE_SRC (src), GST_FORMAT_TIME);
  gst_base_src_set_do_timestamp (GST_BASE_SRC (src), TRUE);
  src->agent = NULL;
  src->stream_id = 0;
  src->component_id = 0;
  src->mainctx = g_main_context_new ();
  src->mainloop = g_main_loop_new (src->mainctx, FALSE);
  src->unlocked = FALSE;
  src->idle_source = NULL;
  src->outbufs = g_queue_new ();
  src->caps = gst_caps_new_any ();
  src->socket_addresses = g_hash_table_new_full(gst_nice_src_address_hash,
                                                gst_nice_src_nice_address_compare,
                                                gst_nice_src_destroy_hash_key,
                                                gst_object_unref);
#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
  src->mem_list_interface.function_interface = &nice_src_mem_interface;
  src->mem_list_interface.gst_src = src;
  src->mem_list_interface.temp_refs = g_array_sized_new(FALSE, TRUE,
    sizeof(GstNiceSrcMemoryBufferRef*), GST_NICE_SRC_MEM_BUFFERS_PREALLOCATED);
  g_array_set_clear_func(src->mem_list_interface.temp_refs, &gst_nice_src_mem_buffer_ref_array_clear);
  src->mem_list_interface_set = FALSE;
#endif
}

static void gst_nice_buffer_address_meta_add(
    GstNiceSrc *nicesrc,
    const NiceAddress *from,
    GstBuffer* buffer
  ){
   if (from != NULL) {
    GSocketAddress * saddr = gst_nice_src_gsocket_addr_create_or_retrieve(
      nicesrc, from);
    if (saddr != NULL) {
      gst_buffer_add_net_address_meta (buffer, saddr);
      g_object_unref (saddr);
    } else {
      GST_ERROR_OBJECT (nicesrc, "Could not convert address to GSocketAddress");
    }
  }
}
static void
gst_nice_src_read_callback (NiceAgent *agent,
    guint stream_id,
    guint component_id,
    guint len,
    gchar *buf,
    gpointer data,
    const NiceAddress *from,
    const NiceAddress *to)
{
  GstBaseSrc *basesrc = GST_BASE_SRC (data);
  GstNiceSrc *nicesrc = GST_NICE_SRC (basesrc);
  GstBaseSrcClass *bclass = GST_BASE_SRC_GET_CLASS (basesrc);
  GstBuffer *buffer = NULL;

  (void)stream_id;
  (void)component_id;

  GST_LOG_OBJECT (agent, "Got buffer, getting out of the main loop");

  (void)to;
  GstFlowReturn status = bclass->alloc(basesrc, 0, len, &buffer);
  if (status != GST_FLOW_OK)
  {
    GST_LOG_OBJECT (nicesrc, "Could not allocate buffer using common allocator"
                               ", allocate using local allocator instead");
    buffer = gst_buffer_new_allocate (NULL, len, NULL);
  }

  if (gst_buffer_get_size(buffer) != len)
  {
    gst_buffer_resize(buffer, 0, len);
    g_assert(gst_buffer_get_size(buffer) == len);
  }

  gst_buffer_fill (buffer, 0, buf, len);

  gst_nice_buffer_address_meta_add(nicesrc, from, buffer);

  g_queue_push_tail (nicesrc->outbufs, buffer);

  g_main_loop_quit (nicesrc->mainloop);
}
#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
/* NB: This function does not support pre 1.0 gstreamer */
static void
gst_nice_src_read_multiple_callback (NiceAgent *agent,
    guint stream_id,
    guint component_id,
    guint num_buffers,
    NiceMemoryBufferRef **buffers,
    const NiceAddress *from,
    const NiceAddress *to,
    gpointer data)
{
  GstBaseSrc *basesrc = GST_BASE_SRC (data);
  GstNiceSrc *nicesrc = GST_NICE_SRC (basesrc);

  GstBufferList *outlist = gst_buffer_list_new_sized (num_buffers);
  for (int i = 0; i < num_buffers; ++i) {
    GstNiceSrcMemoryBufferRef *buffer_ref = (GstNiceSrcMemoryBufferRef*)buffers[i];
    GstBuffer *gbuffer = buffer_ref->buffer;
    gst_buffer_unmap(gbuffer, &(buffer_ref->buf_map));
    gst_nice_buffer_address_meta_add(nicesrc, &from[i], gbuffer);
    gst_buffer_list_insert (outlist, -1, gbuffer);
    buffer_ref->buffer = NULL;
    gst_nice_src_buffer_return((MemlistInterface**)&(nicesrc->mem_list_interface.function_interface), buffer_ref);
  }

  GST_LOG_OBJECT (agent, "Got multiple buffers (%d), getting out of the main loop", num_buffers);
  //GST_ERROR_OBJECT (agent, "Pushing multiple buffers are not implemented for gstnicesrc yet. Dropping buffer.");

  g_queue_push_tail (nicesrc->outbufs, outlist);

  g_main_loop_quit (nicesrc->mainloop);
}
#endif

static gboolean
gst_nice_src_unlock_idler (gpointer data)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (data);

  GST_OBJECT_LOCK (nicesrc);
  if (nicesrc->unlocked)
    g_main_loop_quit (nicesrc->mainloop);

  if (nicesrc->idle_source) {
    g_source_destroy (nicesrc->idle_source);
    g_source_unref (nicesrc->idle_source);
    nicesrc->idle_source = NULL;
  }
  GST_OBJECT_UNLOCK (nicesrc);

  return FALSE;
}

static gboolean
gst_nice_src_unlock (GstBaseSrc *src)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (src);

  GST_OBJECT_LOCK (src);
  nicesrc->unlocked = TRUE;

  g_main_loop_quit (nicesrc->mainloop);

  if (!nicesrc->idle_source) {
    nicesrc->idle_source = g_idle_source_new ();
    g_source_set_priority (nicesrc->idle_source, G_PRIORITY_HIGH);
    g_source_set_callback (nicesrc->idle_source, gst_nice_src_unlock_idler, src, NULL);
    g_source_attach (nicesrc->idle_source, g_main_loop_get_context (nicesrc->mainloop));
  }
  GST_OBJECT_UNLOCK (src);

  return TRUE;
}

static gboolean
gst_nice_src_unlock_stop (GstBaseSrc *src)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (src);

  GST_OBJECT_LOCK (src);
  nicesrc->unlocked = FALSE;
  if (nicesrc->idle_source) {
    g_source_destroy (nicesrc->idle_source);
    g_source_unref(nicesrc->idle_source);
  }
  nicesrc->idle_source = NULL;
  GST_OBJECT_UNLOCK (src);

  return TRUE;
}

#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
static gboolean
gst_nice_src_decide_allocation (GstBaseSrc * bsrc, GstQuery * query)
{
  GstBufferPool *pool;
  gboolean update;
  GstStructure *config;
  GstCaps *caps = NULL;
  guint size = BUFFER_SIZE;

  GstNiceSrc *src = GST_NICE_SRC_CAST (bsrc);

  if (gst_query_get_n_allocation_pools (query) > 0) {
    update = TRUE;
  } else {
    update = FALSE;
  }

  pool = gst_buffer_pool_new ();

  config = gst_buffer_pool_get_config (pool);

  gst_query_parse_allocation (query, &caps, NULL);

  gst_buffer_pool_config_set_params (config, caps, size, 0, 0);

  gst_buffer_pool_set_config (pool, config);

  if (update)
    gst_query_set_nth_allocation_pool (query, 0, pool, size, 0, 0);
  else
    gst_query_add_allocation_pool (query, pool, size, 0, 0);

  src->mem_list_interface.pool = pool;

  return TRUE;
}

static void gst_nice_src_clean_up_pool(GstNiceSrc * src)
{
  if (src->mem_list_interface.pool != NULL) {
    /* The entries that already exists will be with the old pool until they die
       as we have no way of moving them to the new pool. */
    //gst_buffer_pool_set_active (src->mem_list_interface.pool, FALSE);
    gst_object_unref (src->mem_list_interface.pool);
    src->mem_list_interface.pool = NULL;
  }
}
#endif

static gboolean
gst_nice_src_query (GstBaseSrc * src, GstQuery * query)
{
  gboolean ret;

  switch (GST_QUERY_TYPE (query)) {
    case GST_QUERY_SCHEDULING:
    {
      /* a pushsrc can by default never operate in pull mode override
       * if you want something different. */
      gst_query_set_scheduling (query, GST_SCHEDULING_FLAG_SEQUENTIAL, 1, -1,
          0);
      gst_query_add_scheduling_mode (query, GST_PAD_MODE_PUSH);

      ret = TRUE;
      break;
    }
    default:
      ret = GST_BASE_SRC_CLASS (parent_class)->query (src, query);
      break;
  }
  return ret;
}


static GstFlowReturn
gst_nice_src_create (GstBaseSrc * basesrc, guint64 offset, guint length,
    GstBuffer ** ret)
{
  GstNiceSrc *nicesrc = GST_NICE_SRC (basesrc);

  GST_LOG_OBJECT (nicesrc, "create called");

  GST_OBJECT_LOCK (basesrc);
  if (nicesrc->unlocked) {
    GST_LOG_OBJECT (nicesrc, "Source unlinkend, transitioning to flushing");
    GST_OBJECT_UNLOCK (basesrc);
    return GST_FLOW_FLUSHING;
  }
  GST_OBJECT_UNLOCK (basesrc);

  if (g_queue_is_empty (nicesrc->outbufs))
    g_main_loop_run (nicesrc->mainloop);

  gpointer bufptr = g_queue_pop_head (nicesrc->outbufs);

  if (bufptr != NULL) {
    if (GST_IS_BUFFER_LIST(bufptr)){
      *ret = NULL;
      gst_base_src_submit_buffer_list (basesrc, bufptr);
      GST_LOG_OBJECT (nicesrc, "Got buffer list, pushing");
    }
    else
    {
      *ret = bufptr;
      GST_LOG_OBJECT (nicesrc, "Got buffer, pushing");
    }
    return GST_FLOW_OK;
  } else {
    *ret = NULL;
    GST_LOG_OBJECT (nicesrc, "Got interrupting, returning wrong-state");
    return GST_FLOW_FLUSHING;
  }

}

static GstFlowReturn
gst_nice_src_alloc (GstBaseSrc * bsrc, guint64 offset, guint length,
    GstBuffer ** ret)
{
  GstFlowReturn fret;

  fret = GST_BASE_SRC_CLASS (parent_class)->alloc (bsrc, offset, length, ret);

  return fret;
}

static GstFlowReturn
gst_nice_src_fill (GstBaseSrc * bsrc, guint64 offset, guint length,
    GstBuffer * ret)
{
  GstFlowReturn fret;

  fret = GST_BASE_SRC_CLASS (parent_class)->fill (bsrc, offset, length, ret);

  return fret;
}

static void
gst_nice_src_dispose (GObject *object)
{
  GstNiceSrc *src = GST_NICE_SRC (object);

  if (src->idle_source) {
    g_source_destroy (src->idle_source);
    g_source_unref(src->idle_source);
  }
  src->idle_source = NULL;

  if (src->agent){
#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
    if (src->mem_list_interface_set == TRUE)
    {
      nice_agent_set_mem_list_interface(src->agent, NULL);
      src->mem_list_interface_set = FALSE;
    }
#endif
    g_object_unref (src->agent);
  }

  src->agent = NULL;

#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
  if (src->mem_list_interface.temp_refs){
    GArray *temp_refs = src->mem_list_interface.temp_refs;
    /* Clean up all elements in array */
    for(int i=temp_refs->len-1;i==0; i--)
    {
      g_array_remove_index(temp_refs, i);
    }
    g_array_free(temp_refs, TRUE);
  }
  gst_nice_src_clean_up_pool(src);
#endif

  if (src->mainloop)
    g_main_loop_unref (src->mainloop);
  src->mainloop = NULL;

  if (src->mainctx)
    g_main_context_unref (src->mainctx);
  src->mainctx = NULL;

  if (src->outbufs)
    g_queue_free_full (src->outbufs, (GDestroyNotify)gst_buffer_unref);
  src->outbufs = NULL;

  g_hash_table_remove_all(src->socket_addresses);
  g_hash_table_unref(src->socket_addresses);
  src->socket_addresses = NULL;

  gst_caps_replace (&src->caps, NULL);

  G_OBJECT_CLASS (gst_nice_src_parent_class)->dispose (object);
}

static void
gst_nice_src_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec)
{
  GstNiceSrc *src = GST_NICE_SRC (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      if (src->agent)
        GST_ERROR_OBJECT (object,
            "Changing the agent on a nice src not allowed");
      else
        src->agent = g_value_dup_object (value);
      break;

    case PROP_STREAM:
      src->stream_id = g_value_get_uint (value);
      break;

    case PROP_COMPONENT:
      src->component_id = g_value_get_uint (value);
      break;

    case PROP_CAPS:
    {
      const GstCaps *new_caps_val = gst_value_get_caps (value);
      GstCaps *new_caps;

      if (new_caps_val == NULL) {
        new_caps = gst_caps_new_any ();
      } else {
        new_caps = gst_caps_copy (new_caps_val);
      }

      GST_OBJECT_LOCK (src);
      gst_caps_replace (&src->caps, new_caps);
      GST_OBJECT_UNLOCK (src);

      gst_pad_mark_reconfigure (GST_BASE_SRC_PAD (src));
      break;
    }

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
gst_nice_src_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec)
{
  GstNiceSrc *src = GST_NICE_SRC (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      g_value_set_object (value, src->agent);
      break;

    case PROP_STREAM:
      g_value_set_uint (value, src->stream_id);
      break;

    case PROP_COMPONENT:
      g_value_set_uint (value, src->component_id);
      break;

    case PROP_CAPS:
      GST_OBJECT_LOCK (src);
      gst_value_set_caps (value, src->caps);
      GST_OBJECT_UNLOCK (src);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
gst_nice_src_log_callback (NiceAgent *agent, guint stream_id, guint component_id, GLogLevelFlags level,
    gchar *msg, gpointer data)
{
  (void)agent;
  GstBaseSrc *basesrc = GST_BASE_SRC (data);
  GstNiceSrc *nicesrc = GST_NICE_SRC (basesrc);

  switch (level) {
  case G_LOG_LEVEL_WARNING:
    GST_WARNING_OBJECT (nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  case G_LOG_LEVEL_INFO:
    GST_INFO_OBJECT (nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  default:
    GST_DEBUG_OBJECT (nicesrc, "stream=%u component=%u %s", stream_id, component_id, msg);
    break;
  }
}

static GstStateChangeReturn
gst_nice_src_change_state (GstElement * element, GstStateChange transition)
{
  GstNiceSrc *src;
  GstStateChangeReturn ret;

  src = GST_NICE_SRC (element);

  switch (transition) {
    case GST_STATE_CHANGE_NULL_TO_READY:
      if (src->agent == NULL || src->stream_id == 0 || src->component_id == 0)
        {
          GST_ERROR_OBJECT (element,
              "Trying to start Nice source without an agent set");
          return GST_STATE_CHANGE_FAILURE;
        }
      else
        {
          nice_agent_attach_recv (src->agent, src->stream_id, src->component_id,
              src->mainctx, gst_nice_src_read_callback,
#ifdef NICE_UDP_SOCKET_HAVE_RECVMMSG
              gst_nice_src_read_multiple_callback,
#else
              NULL,
#endif
              (gpointer) src);
        }
      break;
    case GST_STATE_CHANGE_READY_TO_NULL:
      nice_agent_attach_recv (src->agent, src->stream_id, src->component_id,
          src->mainctx, NULL, NULL, NULL);
      break;
    default:
      break;
  }

  ret = GST_ELEMENT_CLASS (gst_nice_src_parent_class)->change_state (element,
      transition);

  return ret;
}

NiceMemoryBufferRef* gst_nice_src_buffer_ref_allocate(MemlistInterface **ml_interface){
  struct _GstNiceMemlistInterface *mem_list_interface = (struct _GstNiceMemlistInterface *)ml_interface;

  GstNiceSrcMemoryBufferRef* ref;
  if (mem_list_interface->temp_refs->len > 0)
  {
    /* Use an existing allocated reference */
    int last_index = mem_list_interface->temp_refs->len-1;
    ref = (GstNiceSrcMemoryBufferRef*) g_array_index(mem_list_interface->temp_refs, GstNiceSrcMemoryBufferRef*, last_index);
    // Make sure the ref is not freed when removed from the array
    g_array_index(mem_list_interface->temp_refs, GstNiceSrcMemoryBufferRef*, last_index) = NULL;
    g_array_remove_index(mem_list_interface->temp_refs, last_index);
  }
  else
  {
    /* No existing elements are stored, allocate a new one */
    ref = g_new0(GstNiceSrcMemoryBufferRef, 1);
  }
  g_assert_cmpint((gsize)ref, !=, (gsize)NULL);
  return ref;
}

NiceMemoryBufferRef* gst_nice_src_buffer_get(MemlistInterface **ml_interface, gsize size){
  struct _GstNiceMemlistInterface *mem_list_interface = (struct _GstNiceMemlistInterface *)ml_interface;
  GstBufferPoolAcquireParams params = { 0 };
  GstNiceSrcMemoryBufferRef *ref = gst_nice_src_buffer_ref_allocate(ml_interface);
  GstBuffer *buffer = NULL;

  g_assert(mem_list_interface->pool != NULL);
  gint status = gst_buffer_pool_acquire_buffer (mem_list_interface->pool, &buffer,
      &params);
  if(status != GST_FLOW_OK)
  {
    gst_nice_src_buffer_return(ml_interface, ref);
    return NULL;
  }
  g_assert_cmpint(status, ==, GST_FLOW_OK);
  g_assert(buffer != NULL);
  ref->buffer = buffer;

  gboolean mapped = gst_buffer_map (ref->buffer, &ref->buf_map,
      GST_MAP_WRITE | GST_MAP_READ);
  g_assert(mapped);

  return (NiceMemoryBufferRef*) ref;
}

void gst_nice_src_buffer_return(MemlistInterface **ml_interface, NiceMemoryBufferRef* buffer){
  struct _GstNiceMemlistInterface *mem_list_interface = (struct _GstNiceMemlistInterface *)ml_interface;
  GstNiceSrcMemoryBufferRef *buffer_ref = (GstNiceSrcMemoryBufferRef*)buffer;
  if(buffer_ref->buffer){
    /* Return allocated buffer to the pool after it has been used */
    gst_buffer_unmap (buffer_ref->buffer, &buffer_ref->buf_map);
    gst_buffer_unref (buffer_ref->buffer);
  }
  /* TODO: The ref should be added to the array, this is not done at the moment */
  memset (buffer_ref, 0, sizeof (GstNiceSrcMemoryBufferRef));
  g_array_append_vals(mem_list_interface->temp_refs, &buffer_ref, 1);

}

char* gst_nice_src_buffer_contents(MemlistInterface **ml_interface, NiceMemoryBufferRef* buffer){
  GstNiceSrcMemoryBufferRef *buffer_ref = (GstNiceSrcMemoryBufferRef*)buffer;
  return (char*) buffer_ref->buf_map.data;
}

gsize gst_nice_src_buffer_size(MemlistInterface **ml_interface, NiceMemoryBufferRef* buffer){
  GstNiceSrcMemoryBufferRef *buffer_ref = (GstNiceSrcMemoryBufferRef*)buffer;
  return buffer_ref->buf_map.size;
}

void gst_nice_src_buffer_resize(MemlistInterface **ml_interface, NiceMemoryBufferRef* buffer, gsize new_size) {
  GstNiceSrcMemoryBufferRef *buffer_ref = (GstNiceSrcMemoryBufferRef*)buffer;
  guint8* data_location;
  g_assert(new_size <= buffer_ref->buf_map.size);
  data_location = buffer_ref->buf_map.data;
  gst_buffer_unmap (buffer_ref->buffer, &buffer_ref->buf_map);
  gst_buffer_resize(buffer_ref->buffer, 0, new_size);
  gboolean mapped = gst_buffer_map (buffer_ref->buffer, &buffer_ref->buf_map,
      GST_MAP_WRITE | GST_MAP_READ);
  g_assert(mapped);
  g_assert(buffer_ref->buf_map.data == data_location);
  g_assert(buffer_ref->buf_map.size == new_size);
}

/* Only to be used as a clear function for the temp_refs array, which contains uninitialised refs */
static void gst_nice_src_mem_buffer_ref_array_clear(void *element){
  GstNiceSrcMemoryBufferRef **ref = (GstNiceSrcMemoryBufferRef**)element;
  if (ref != NULL){
    g_free(*ref);
    *ref = NULL;
  }
}