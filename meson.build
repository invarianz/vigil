project(
    'io.github.invarianz.vigil',
    'vala', 'c',
    version: '1.0.0',
    meson_version: '>= 0.57.0',
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
portal_gtk4_dep = dependency('libportal-gtk4', version: '>= 0.6')

add_project_arguments(
    '-DGETTEXT_PACKAGE="@0@"'.format(app_id),
    language: 'c'
)

add_project_arguments(
    '--define=GETTEXT_PACKAGE="@0@"'.format(app_id),
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

# Source files shared between application and tests (no main entry point)
src_files = files(
    'src' / 'MainWindow.vala',
    'src' / 'Services' / 'IScreenshotBackend.vala',
    'src' / 'Services' / 'PortalScreenshotBackend.vala',
    'src' / 'Services' / 'GalaScreenshotBackend.vala',
    'src' / 'Services' / 'ScreenshotService.vala',
    'src' / 'Services' / 'SchedulerService.vala',
    'src' / 'Services' / 'UploadService.vala',
    'src' / 'Services' / 'StorageService.vala',
    'src' / 'Widgets' / 'StatusView.vala',
    'src' / 'Widgets' / 'SettingsView.vala',
    'src' / 'Utils' / 'SessionDetector.vala',
)

all_dependencies = [
    glib_dep,
    gobject_dep,
    gio_dep,
    gtk_dep,
    granite_dep,
    json_dep,
    soup_dep,
    portal_dep,
    portal_gtk4_dep,
]

# Build the application executable
executable(
    app_id,
    src_files,
    config_file,
    'src' / 'Application.vala',
    dependencies: all_dependencies,
    install: true
)

# Desktop file
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

# GSettings schema
install_data(
    'data' / 'vigil.gschema.xml',
    install_dir: get_option('datadir') / 'glib-2.0' / 'schemas',
    rename: app_id + '.gschema.xml'
)

# Compile schemas after install
gnome.post_install(
    glib_compile_schemas: true,
    gtk_update_icon_cache: true,
    update_desktop_database: true,
)

subdir('po')
subdir('tests')
