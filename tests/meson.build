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
        dependencies: [vigil_service_dep],
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
        dependencies: [vigil_service_dep],
        install: false,
    )

    test(name, test_exe,
        suite: 'integration',
        timeout: 30,
    )
endforeach
