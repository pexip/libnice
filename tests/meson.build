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
