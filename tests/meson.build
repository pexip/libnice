# Standalone regression tests added by the TURN-refresh hardening work.
# These two tests have no dependency on libnice itself (one exercises a
# pure-GLib threading pattern, the other is a pure-computation unit
# test), so they can run in CI without a TURN server.
#
# The other historical tests in this directory (test-fullmode etc.) are
# still wired into autotools via Makefile.am and have not been ported
# to meson here.

test_mainctx_cross_thread = executable('test-mainctx-cross-thread',
  'test-mainctx-cross-thread.c',
  include_directories : config_h_inc,
  dependencies : glib_deps,
)
test('mainctx-cross-thread', test_mainctx_cross_thread,
  timeout : 30,
)

test_turn_refresh_interval = executable('test-turn-refresh-interval',
  'test-turn-refresh-interval.c',
  include_directories : config_h_inc,
  dependencies : glib_deps,
)
test('turn-refresh-interval', test_turn_refresh_interval,
  timeout : 10,
)

# Pins down the parsing contract for the test-only env-var refresh-
# timeout knobs declared in socket/turn.c. See the file header for why.
test_turn_timeout_env = executable('test-turn-timeout-env',
  'test-turn-timeout-env.c',
  include_directories : config_h_inc,
  dependencies : glib_deps,
)
test('turn-timeout-env', test_turn_timeout_env,
  timeout : 10,
)

# Unlike the three above, this one calls the real
# nice_component_add_valid_candidate() / nice_component_verify_remote_candidate()
# rather than mirroring them, so it cannot drift from the code it guards.
# Those are internal symbols with no NICEAPI_EXPORT, so MSVC resolves nothing for
# them from nice.lib; link the agent objects directly rather than the library.
#
# It is also the only executable here that pulls in GStreamer, and a static
# GStreamer requires the executable to supply gst_init_static_plugins(), which
# nothing in libnice does. The logic under test is platform independent, so
# build it for the shared-library configuration only.
if not static_build
  test_valid_candidate_eviction = executable('test-valid-candidate-eviction',
    'test-valid-candidate-eviction.c',
    include_directories : [config_h_inc, libnice_incdir, include_directories('../agent')],
    objects : libagent.extract_all_objects(recursive : false),
    dependencies : libagent_deps,
    c_args : libagent_cargs,
  )
  test('valid-candidate-eviction', test_valid_candidate_eviction,
    timeout : 10,
  )
endif

# Exercises GstNiceSink's handling of nice_agent_send() failures. It links
# the plugin's sink object directly (the plugin is a GStreamer plugin, not a
# library with public symbols) together with the agent, and needs the sink's
# header. Like the test above it pulls in GStreamer, so it is only built for
# the shared-library configuration.
if not static_build
  test_nicesink_send_failure = executable('test-nicesink-send-failure',
    'test-nicesink-send-failure.c',
    include_directories : [config_h_inc, libnice_incdir,
      include_directories('../gst')],
    objects : gstnice.extract_objects('gstnicesink.c'),
    dependencies : [libagent_dep, glib_deps, gst_deps],
  )
  test('nicesink-send-failure', test_nicesink_send_failure,
    timeout : 30,
  )
endif
