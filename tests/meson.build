# Copy the GSettings schema XML into the test build directory so
# glib-compile-schemas can find it, then compile it.
configure_file(
    input: meson.project_source_root() / 'data' / 'vigil.gschema.xml',
    output: 'io.github.invarianz.vigil.gschema.xml',
    copy: true,
)

glib_compile_schemas = find_program('glib-compile-schemas')
compiled_schemas = custom_target('compile-test-schemas',
    command: [glib_compile_schemas, meson.current_build_dir()],
    output: 'gschemas.compiled',
    build_by_default: true,
)

# Point tests at the compiled schema in the test build directory
test_env = environment()
test_env.set('GSETTINGS_SCHEMA_DIR', meson.current_build_dir())
# Use memory backend so tests don't persist to dconf
test_env.set('GSETTINGS_BACKEND', 'memory')

# Unit tests -- pure logic, no display server needed
unit_tests = {
    'SessionDetector': 'SessionDetectorTest.vala',
    'SchedulerService': 'SchedulerServiceTest.vala',
    'StorageService': 'StorageServiceTest.vala',
    'UploadService': 'UploadServiceTest.vala',
    'HeartbeatService': 'HeartbeatServiceTest.vala',
    'TamperDetectionService': 'TamperDetectionServiceTest.vala',
    'MatrixTransportService': 'MatrixTransportServiceTest.vala',
}

foreach name, source : unit_tests
    test_exe = executable(
        name + '_test',
        source,
        dependencies: [vigil_service_dep],
        install: false,
    )

    test(name, test_exe,
        suite: 'unit',
        timeout: 30,
        env: test_env,
    )
endforeach

# Integration tests -- may use D-Bus, async patterns, mock backends
integration_tests = {
    'ScreenshotService': 'ScreenshotServiceTest.vala',
}

foreach name, source : integration_tests
    test_exe = executable(
        name + '_test',
        source,
        dependencies: [vigil_service_dep],
        install: false,
    )

    test(name, test_exe,
        suite: 'integration',
        timeout: 30,
        env: test_env,
    )
endforeach

# D-Bus server tests -- need the DBusInterface source compiled in
dbus_test_exe = executable(
    'DBusServer_test',
    'DBusServerTest.vala',
    files(meson.project_source_root() / 'src' / 'Daemon' / 'DBusInterface.vala'),
    dependencies: [vigil_service_dep, json_dep],
    install: false,
)

test('DBusServer', dbus_test_exe,
    suite: 'integration',
    timeout: 30,
    env: test_env,
)
