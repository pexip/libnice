install_headers('nice.h', 'niceconfig.h', subdir : 'nice')

pkg_install_dir = join_paths(get_option('libdir'), 'pkgconfig')
pkgconf = configuration_data()
pkgconf.set('prefix', join_paths(get_option('prefix')))
pkgconf.set('exec_prefix', '${prefix}')
pkgconf.set('libdir', '${prefix}/@0@'.format(get_option('libdir')))
pkgconf.set('includedir', '${prefix}/@0@'.format(get_option('includedir')))
pkgconf.set('VERSION', meson.project_version())
configure_file(input : 'nice.pc.in',
  output : 'nice.pc',
  configuration : pkgconf,
  install_dir : pkg_install_dir)
