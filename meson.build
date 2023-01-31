project('libnice', 'c',
  version : '0.1.3',
  meson_version : '>= 0.54.0')

glib_req = '>= 2.40.0'
gst_req = '>= 1.0.0'

pname = meson.project_name()
pversion = meson.project_version()
cc = meson.get_compiler('c')
host_system = host_machine.system()

project_arguments = [
  #'-DMESON_BUILD',
  #'-DGLIB_DISABLE_DEPRECATION_WARNINGS',
  '-DHAVE_CONFIG_H',
  '-DNICE_EXPORTS',
  '-fno-strict-aliasing'
]
project_arguments += ['-DHOST_@0@'.format(host_system.to_upper())]

add_project_arguments(project_arguments, language: 'c')

glib_deps = [
  dependency('glib-2.0', version : glib_req, fallback: ['glib', 'libglib_dep']),
  dependency('gobject-2.0', fallback: ['glib', 'libgobject_dep']),
  dependency('gio-2.0', version: glib_req, fallback : ['glib', 'gio_dep']),
]
gst_deps = [
  dependency('gstreamer-1.0', version : gst_req, fallback : ['gstreamer', 'gst_dep']),
  dependency('gstreamer-base-1.0', version : gst_req, fallback : ['gstreamer', 'gst_base_dep']),
  dependency('gstreamer-net-1.0', version : gst_req, fallback : ['gst-plugins-base', 'net_dep']),
]

openssl_dep = dependency('openssl', version : '>= 1.0.1', required : false)
if not openssl_dep.found()
  libeay32_dep = cc.find_library('libeay32', required : false)
  ssleay32_dep = cc.find_library('ssleay32', required : false)
  if libeay32_dep.found() and ssleay32_dep.found()
    openssl_dep = declare_dependency (dependencies : [libeay32_dep, ssleay32_dep])
  endif
endif

if host_system == 'windows'
  winsock2_dep = cc.find_library('ws2_32')
  iphlpapi_dep = cc.find_library('iphlpapi')
endif

install_dir = get_option('libdir')
plugins_install_dir = '@0@/gstreamer-1.0'.format(install_dir)
static_build = get_option('default_library') == 'static'

gir = find_program('g-ir-scanner', required : false)
gnome = import('gnome')
build_gir = gir.found() and not meson.is_cross_build() and not static_build

# config.h generation
config_h_inc = include_directories('.')
core_conf = configuration_data()
core_conf.set('PACKAGE', '"@0@"'.format(pname))
core_conf.set('PACKAGE_NAME', '"@0@"'.format(pname))
core_conf.set('VERSION', '"@0@"'.format(pversion))
core_conf.set('PACKAGE_STRING', '"@0@ @0@"'.format(pname, pversion))
core_conf.set('PLUGIN_DIR', '"@0@"'.format(join_paths(get_option('prefix'), plugins_install_dir)))
core_conf.set('NICEAPI_EXPORT', '')

check_headers = [
  'assert.h',
  'stdbool.h',
  'arpa/inet.h',
  'net/in.h',
  'net/if_arp.h',
  'ifaddrs.h',
]
foreach h : check_headers
  define = 'HAVE_' + h.underscorify().to_upper()
  core_conf.set10(define, cc.has_header(h))
endforeach
configure_file(output : 'config.h', configuration : core_conf)

libagent_incdir = include_directories ('agent')
libnice_incdir = include_directories ('nice')

gst_libraries = []
plugins = []

subdir('random')
subdir('socket')
subdir('stun')
subdir('agent')
subdir('nice')
subdir('gst')

#subdir('tests')
#subdir('python')

pkgconfig = import('pkgconfig')
plugins_pkgconfig_install_dir = join_paths(plugins_install_dir, 'pkgconfig')

plugin_names = []
gst_plugins = []
foreach plugin: plugins
  pkgconfig.generate(plugin, install_dir: plugins_pkgconfig_install_dir)
  dep = declare_dependency(link_with: plugin, variables: {'full_path': plugin.full_path()})
  meson.override_dependency(plugin.name(), dep)
  gst_plugins += [dep]
  if plugin.name().startswith('gst')
    plugin_names += [plugin.name().substring(3)]
  else
    plugin_names += [plugin.name()]
  endif
endforeach

summary({
    'Plugins': plugin_names,
}, list_sep: ', ')
