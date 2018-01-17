libsocket_sources = [
  'socket.c',
  'udp-bsd.c',
  'tcp-bsd.c',
  'pseudossl.c',
  'socks5.c',
  'http.c',
  'turn.c',
  'tcp-turn.c',
  'tcp-active.c',
  'tcp-passive.c',
  'tcp-established.c',
]

libsocket_deps = [
  glib_deps,
]

libsocket_includes = [
  config_h_inc,
  libnice_random_incdir,
  libagent_incdir,
  libnice_incdir,
]

libsocket = static_library('libsocket',
  libsocket_sources,
  c_args : ['-DG_LOG_DOMAIN="libnice-socket"'],
  include_directories: libsocket_includes,
  dependencies : libsocket_deps,
)

libsocket_dep = declare_dependency(link_with : libsocket,
  include_directories : include_directories('.'),
  dependencies : libsocket_deps)
