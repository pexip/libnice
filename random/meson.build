libnice_random_sources = [
  'random.c',
  'random-glib.c',
]

libnice_random_deps = [
  glib_deps,
]

libnice_random = static_library('libnice-random',
  libnice_random_sources,
  include_directories: [config_h_inc],
  dependencies : libnice_random_deps,
)

libnice_random_incdir = include_directories('.')

libnice_random_dep = declare_dependency(link_with : libnice_random,
  include_directories : libnice_random_incdir,
  dependencies : libnice_random_deps)
