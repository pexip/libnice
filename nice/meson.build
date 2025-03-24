install_headers('nice.h', 'niceconfig.h', subdir : 'nice')

pkgconfig = import('pkgconfig')
pkg_install_dir = join_paths(get_option('libdir'), 'pkgconfig')
pkgconfig.generate(libagent,
  filebase: 'nice',
  name: 'libnice',
  description: 'ICE library',
  requires: ['glib-2.0 >= 2.10.0'],  # FIXME: meson adds glib-2.0 >=  2.40.0
  install_dir: pkg_install_dir,
  variables: [
    'exec_prefix=${prefix}'
  ],
)
