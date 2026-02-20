# Copy the GSettings schema XML into the test build directory so
# glib-compile-schemas can find it, then compile it.
test_schema = configure_file(
    input: meson.project_source_root() / 'data' / 'vigil.gschema.xml',
    output: 'io.github.invarianz.vigil.gschema.xml',
    copy: true,
)

glib_compile_schemas = find_program('glib-compile-schemas')
compiled_schemas = custom_target('compile-test-schemas',
    input: test_schema,
    command: [glib_compile_schemas, meson.current_build_dir()],
    output: 'gschemas.compiled',
    build_by_default: true,
)

# Point tests at the compiled schema in the test build directory
test_env = environment()
test_env.set('GSETTINGS_SCHEMA_DIR', meson.current_build_dir())
# Use memory backend so tests don't persist to dconf
test_env.set('GSETTINGS_BACKEND', 'memory')

# Shared test utilities
test_utils = files('TestUtils.vala')

# Unit tests -- pure logic, no display server needed
unit_tests = {
    'SessionDetector': 'SessionDetectorTest.vala',
    'SchedulerService': 'SchedulerServiceTest.vala',
    'StorageService': 'StorageServiceTest.vala',
    'HeartbeatService': 'HeartbeatServiceTest.vala',
    'TamperDetectionService': 'TamperDetectionServiceTest.vala',
    'MatrixTransportService': 'MatrixTransportServiceTest.vala',
    'EncryptionService': 'EncryptionServiceTest.vala',
}

foreach name, source : unit_tests
    test_exe = executable(
        name + '_test',
        source,
        test_utils,
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
    'MatrixE2EEIntegration': 'MatrixE2EEIntegrationTest.vala',
}

foreach name, source : integration_tests
    test_exe = executable(
        name + '_test',
        source,
        test_utils,
        dependencies: [vigil_service_dep],
        install: false,
    )

    test(name, test_exe,
        suite: 'integration',
        timeout: name == 'MatrixE2EEIntegration' ? 60 : 30,
        env: test_env,
    )
endforeach

# D-Bus server tests -- need the DBusInterface source compiled in
dbus_test_exe = executable(
    'DBusServer_test',
    'DBusServerTest.vala',
    test_utils,
    files(meson.project_source_root() / 'src' / 'Daemon' / 'DBusInterface.vala'),
    dependencies: [vigil_service_dep, json_dep],
    install: false,
)

test('DBusServer', dbus_test_exe,
    suite: 'integration',
    timeout: 30,
    env: test_env,
)

# Performance benchmark (not run as part of normal test suite)
benchmark_exe = executable(
    'PerformanceBenchmark_test',
    'PerformanceBenchmark.vala',
    test_utils,
    dependencies: [vigil_service_dep],
    install: false,
)

benchmark('PerformanceBenchmark', benchmark_exe,
    timeout: 120,
    env: test_env,
)

# Flatpak build check -- verifies the app compiles against the flatpak SDK.
# Run with: meson test -C builddir --suite flatpak
flatpak_builder = find_program('flatpak-builder', required: false)
if flatpak_builder.found()
    flatpak_manifest = meson.project_source_root() / 'io.github.invarianz.vigil.yml'
    flatpak_builddir = meson.project_source_root() / 'flatpak-repo'

    test('flatpak-build', flatpak_builder,
        args: ['--force-clean', '--build-only', flatpak_builddir, flatpak_manifest],
        suite: 'flatpak',
        timeout: 300,
    )
endif
