libagent_sources = [
  'address.c',
  'agent.c',
  'candidate.c',
  'debug.c',
  'interfaces.c',
]

libagent_extra_sources = [
  'component.c',
  'stream.c',
  'conncheck.c',
  'discovery.c',
]

libagent_headers = [
  'address.h',
  'agent.h',
  'candidate.h',
  'debug.h',
  'interfaces.h',
]
install_headers(libagent_headers, subdir : 'nice')

libagent_deps = [
  glib_deps,
  libnice_random_dep,
  libsocket_dep,
  libstun_dep,
]

libagent_cargs = [
  '-DG_LOG_DOMAIN="libnice"',
]

libagent_largs = []
if host_system == 'windows'
  libagent_cargs += ['-DWINVER=0x0501']
  libagent_deps += [iphlpapi_dep]
endif

libagent = shared_library('nice',
  libagent_sources + libagent_extra_sources,
  c_args : libagent_cargs,
  include_directories: [config_h_inc, libnice_incdir],
  install : true,
  dependencies : libagent_deps,
)
libagent_dep = declare_dependency(link_with : libagent,
  include_directories : include_directories('.'),
  dependencies : libagent_deps)

if build_gir
  gnome.generate_gir(libagent,
    sources : libagent_sources + libagent_headers,
    namespace : 'Nice',
    nsversion : '0.1',
    includes : ['GObject-2.0', 'Gio-2.0'],
    install : true,
    extra_args : ['--accept-unprefixed'],
    dependencies : glib_deps,
  )
endif
