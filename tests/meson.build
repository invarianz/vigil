# Dependencies needed for tests (no GTK/Granite needed for unit tests)
test_deps = [
    glib_dep,
    gobject_dep,
    gio_dep,
    json_dep,
    soup_dep,
]

# Source files used by tests (service logic, no UI)
test_src_files = files(
    '../src' / 'Services' / 'IScreenshotBackend.vala',
    '../src' / 'Services' / 'PortalScreenshotBackend.vala',
    '../src' / 'Services' / 'GalaScreenshotBackend.vala',
    '../src' / 'Services' / 'ScreenshotService.vala',
    '../src' / 'Services' / 'SchedulerService.vala',
    '../src' / 'Services' / 'UploadService.vala',
    '../src' / 'Services' / 'StorageService.vala',
    '../src' / 'Utils' / 'SessionDetector.vala',
)

# Unit tests -- pure logic, no display server needed
unit_tests = {
    'SessionDetector': 'SessionDetectorTest.vala',
    'SchedulerService': 'SchedulerServiceTest.vala',
    'StorageService': 'StorageServiceTest.vala',
    'UploadService': 'UploadServiceTest.vala',
}

foreach name, source : unit_tests
    test_exe = executable(
        name + '_test',
        source,
        test_src_files,
        dependencies: test_deps + [portal_dep],
        install: false,
    )

    test(name, test_exe,
        suite: 'unit',
        timeout: 30,
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
        test_src_files,
        dependencies: test_deps + [portal_dep],
        install: false,
    )

    test(name, test_exe,
        suite: 'integration',
        timeout: 30,
    )
endforeach
