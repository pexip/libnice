gstnice_sources = [
  'gstnicesrc.c',
  'gstnicesink.c',
  'gstnice.c',
]

gstnice_deps = [
  libagent_dep,
  glib_deps,
  gst_deps,
]

gstnice = library('gstnice',
  gstnice_sources,
  include_directories: [config_h_inc, libnice_incdir],
  dependencies : gstnice_deps,
  install : true,
  install_dir : plugins_install_dir,
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(gstnice)
