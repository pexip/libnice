libstun_sources = [
  'stunagent.c',
  'stunmessage.c',
  'stun5389.c',
  'stuncrc32.c',
  'sha1.c',
  'md5.c',
  'rand.c',
  'stunhmac.c',
  'utils.c',
  'debug.c',
  'usages/ice.c',
  'usages/bind.c',
  'usages/turn.c',
  'usages/timer.c',
]

libstun_deps = [
  glib_deps,
]

libstun_includes = [
  config_h_inc,
  libnice_incdir,
]

libstun_cargs = [
  '-DG_LOG_DOMAIN="libnice-stun"',
]

if host_system == 'windows'
  libstun_cargs += ['-DWINVER=0x0501']
  libstun_deps += [winsock2_dep]
endif

libstun = static_library('libstun',
  libstun_sources,
  c_args : libstun_cargs,
  include_directories: libstun_includes,
  dependencies : libstun_deps,
)

libstun_dep = declare_dependency(link_with : libstun,
  include_directories : include_directories('.'),
  dependencies : libstun_deps)
