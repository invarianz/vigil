project(
    'io.github.invarianz.vigil',
    'vala', 'c',
    version: '1.0.0',
    meson_version: '>= 0.59.0',
    default_options: ['warning_level=2']
)

gnome = import('gnome')
i18n = import('i18n')

app_id = meson.project_name()

# Core dependencies
glib_dep = dependency('glib-2.0', version: '>= 2.74')
gobject_dep = dependency('gobject-2.0', version: '>= 2.74')
gio_dep = dependency('gio-2.0', version: '>= 2.74')
gtk_dep = dependency('gtk4', version: '>= 4.0')
granite_dep = dependency('granite-7', version: '>= 7.0')
json_dep = dependency('json-glib-1.0')
soup_dep = dependency('libsoup-3.0', version: '>= 3.0')
portal_dep = dependency('libportal', version: '>= 0.6')
olm_dep = dependency('olm', version: '>= 3.0')
openssl_dep = dependency('openssl', version: '>= 1.1.0')
cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required: false)

add_project_arguments(
    '-DGETTEXT_PACKAGE="@0@"'.format(app_id),
    language: 'c'
)

add_project_arguments(
    '--define=GETTEXT_PACKAGE="@0@"'.format(app_id),
    language: 'vala'
)

# Custom VAPI directory for libolm bindings
add_project_arguments(
    '--vapidir=' + meson.project_source_root() / 'vapi',
    '--pkg', 'linux',
    language: 'vala'
)

conf_data = configuration_data()
conf_data.set_quoted('APP_ID', app_id)
conf_data.set_quoted('VERSION', meson.project_version())
conf_data.set_quoted('LOCALEDIR', get_option('prefix') / get_option('localedir'))

config_file = configure_file(
    input: 'src' / 'Config.vala.in',
    output: 'Config.vala',
    configuration: conf_data
)

# All non-GTK dependencies shared by daemon and service library
service_deps = [
    glib_dep,
    gobject_dep,
    gio_dep,
    json_dep,
    soup_dep,
    portal_dep,
    olm_dep,
    openssl_dep,
]

# All dependencies including GTK/Granite (for the GUI app)
all_dependencies = [
    glib_dep,
    gobject_dep,
    gio_dep,
    gtk_dep,
    granite_dep,
    json_dep,
    soup_dep,
    portal_dep,
    olm_dep,
    openssl_dep,
    m_dep,
]

# ──────────────────────────────────────────────────────────────
#  Service layer: shared between daemon and tests
# ──────────────────────────────────────────────────────────────
service_src_files = files(
    'src' / 'Services' / 'IScreenshotBackend.vala',
    'src' / 'Services' / 'PortalScreenshotBackend.vala',
    'src' / 'Services' / 'GalaScreenshotBackend.vala',
    'src' / 'Services' / 'ScreenshotService.vala',
    'src' / 'Services' / 'SchedulerService.vala',

    'src' / 'Services' / 'StorageService.vala',
    'src' / 'Services' / 'HeartbeatService.vala',
    'src' / 'Services' / 'TamperDetectionService.vala',
    'src' / 'Services' / 'MatrixTransportService.vala',
    'src' / 'Services' / 'EncryptionService.vala',
    'src' / 'Services' / 'SecurityUtils.vala',
    'src' / 'Utils' / 'SessionDetector.vala',
)

vigil_service_lib = static_library(
    'vigil-services',
    service_src_files,
    dependencies: service_deps,
    install: false,
)

vigil_service_dep = declare_dependency(
    link_with: vigil_service_lib,
    dependencies: service_deps,
    include_directories: [
        vigil_service_lib.private_dir_include(),
        include_directories('.'),
    ],
)

# ──────────────────────────────────────────────────────────────
#  Daemon: headless monitoring engine (no GTK)
# ──────────────────────────────────────────────────────────────
daemon_src_files = files(
    'src' / 'Daemon' / 'DBusInterface.vala',
    'src' / 'Daemon' / 'Main.vala',
)

executable(
    app_id + '.daemon',
    daemon_src_files,
    config_file,
    dependencies: [vigil_service_dep, json_dep],
    install: true,
)

# ──────────────────────────────────────────────────────────────
#  GUI: thin D-Bus client (needs GTK/Granite)
# ──────────────────────────────────────────────────────────────
# The GUI needs the D-Bus interface definition for the proxy
gui_dbus_src = files(
    'src' / 'Daemon' / 'DBusInterface.vala',
)

ui_src_files = files(
    'src' / 'MainWindow.vala',
    'src' / 'Widgets' / 'StatusView.vala',
    'src' / 'Widgets' / 'RangeScale.vala',
    'src' / 'Widgets' / 'SettingsView.vala',
)

executable(
    app_id,
    ui_src_files,
    gui_dbus_src,
    config_file,
    'src' / 'Application.vala',
    dependencies: all_dependencies + [vigil_service_dep],
    install: true
)

# ──────────────────────────────────────────────────────────────
#  Data files
# ──────────────────────────────────────────────────────────────

# Desktop file (GUI)
i18n.merge_file(
    input: 'data' / 'vigil.desktop.in',
    output: app_id + '.desktop',
    po_dir: meson.project_source_root() / 'po',
    type: 'desktop',
    install: true,
    install_dir: get_option('datadir') / 'applications'
)

# MetaInfo file
i18n.merge_file(
    input: 'data' / 'vigil.metainfo.xml.in',
    output: app_id + '.metainfo.xml',
    po_dir: meson.project_source_root() / 'po',
    type: 'xml',
    install: true,
    install_dir: get_option('datadir') / 'metainfo'
)

# Application icons (hicolor theme)
icon_sizes = ['32', '48', '64', '128']
foreach size : icon_sizes
    install_data(
        'data' / 'icons' / size / app_id + '.svg',
        install_dir: get_option('datadir') / 'icons' / 'hicolor' / size + 'x' + size / 'apps',
    )
endforeach

# GSettings schema
install_data(
    'data' / 'vigil.gschema.xml',
    install_dir: get_option('datadir') / 'glib-2.0' / 'schemas',
    rename: app_id + '.gschema.xml'
)

# Systemd user service (substitute @BINDIR@)
systemd_service_conf = configuration_data()
systemd_service_conf.set('BINDIR', get_option('prefix') / get_option('bindir'))

configure_file(
    input: 'data' / 'vigil-daemon.service',
    output: 'vigil-daemon.service',
    configuration: systemd_service_conf,
    install: true,
    install_dir: get_option('prefix') / 'lib' / 'systemd' / 'user'
)

# Autostart desktop entry for the daemon
install_data(
    'data' / 'vigil-daemon-autostart.desktop',
    install_dir: get_option('sysconfdir') / 'xdg' / 'autostart',
    rename: app_id + '.daemon.desktop'
)

# Compile schemas after install
gnome.post_install(
    glib_compile_schemas: true,
    gtk_update_icon_cache: true,
    update_desktop_database: true,
)

subdir('po')
subdir('tests')
