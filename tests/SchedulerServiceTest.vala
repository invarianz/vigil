/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Unit tests for the SchedulerService.
 *
 * Tests interval calculation, start/stop behavior, and signal emission.
 */

void test_scheduler_default_state () {
    var scheduler = new Vigil.Services.SchedulerService ();
    assert_true (scheduler.is_running == false);
    assert_true (scheduler.last_capture_time == null);
    assert_true (scheduler.next_capture_time == null);
    assert_true (scheduler.min_interval_seconds == 30);
    assert_true (scheduler.max_interval_seconds == 120);
}

void test_scheduler_random_interval_within_range () {
    var scheduler = new Vigil.Services.SchedulerService ();
    scheduler.min_interval_seconds = 10;
    scheduler.max_interval_seconds = 20;

    // Run many iterations to statistically verify range
    for (int i = 0; i < 100; i++) {
        int interval = scheduler.get_random_interval ();
        assert_true (interval >= 10);
        assert_true (interval <= 20);
    }
}

void test_scheduler_random_interval_equal_min_max () {
    var scheduler = new Vigil.Services.SchedulerService ();
    scheduler.min_interval_seconds = 42;
    scheduler.max_interval_seconds = 42;

    int interval = scheduler.get_random_interval ();
    assert_true (interval == 42);
}

void test_scheduler_random_interval_min_greater_than_max () {
    var scheduler = new Vigil.Services.SchedulerService ();
    scheduler.min_interval_seconds = 50;
    scheduler.max_interval_seconds = 30;

    // When min >= max, should return min
    int interval = scheduler.get_random_interval ();
    assert_true (interval == 50);
}

void test_scheduler_start_sets_running () {
    var scheduler = new Vigil.Services.SchedulerService ();
    scheduler.min_interval_seconds = 9999; // Don't actually fire

    scheduler.start ();
    assert_true (scheduler.is_running);
    assert_true (scheduler.next_capture_time != null);

    scheduler.stop (); // cleanup
}

void test_scheduler_stop_clears_state () {
    var scheduler = new Vigil.Services.SchedulerService ();
    scheduler.min_interval_seconds = 9999;

    scheduler.start ();
    scheduler.stop ();

    assert_true (scheduler.is_running == false);
    assert_true (scheduler.next_capture_time == null);
}

void test_scheduler_double_start_is_safe () {
    var scheduler = new Vigil.Services.SchedulerService ();
    scheduler.min_interval_seconds = 9999;

    scheduler.start ();
    scheduler.start (); // second call should be a no-op

    assert_true (scheduler.is_running);
    scheduler.stop ();
}

void test_scheduler_double_stop_is_safe () {
    var scheduler = new Vigil.Services.SchedulerService ();
    scheduler.min_interval_seconds = 9999;

    scheduler.start ();
    scheduler.stop ();
    scheduler.stop (); // second call should be a no-op

    assert_true (scheduler.is_running == false);
}

void test_scheduler_capture_fires () {
    var loop = new MainLoop ();
    var scheduler = new Vigil.Services.SchedulerService ();
    scheduler.min_interval_seconds = 1;
    scheduler.max_interval_seconds = 1;

    bool capture_requested = false;
    scheduler.capture_requested.connect (() => {
        capture_requested = true;
        scheduler.stop ();
        loop.quit ();
    });

    // Timeout to prevent hanging
    Timeout.add_seconds (5, () => {
        scheduler.stop ();
        loop.quit ();
        return Source.REMOVE;
    });

    scheduler.start ();
    loop.run ();

    assert_true (capture_requested);
    assert_true (scheduler.last_capture_time != null);
}

public static int main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/scheduler/default_state", test_scheduler_default_state);
    Test.add_func ("/scheduler/random_interval_range", test_scheduler_random_interval_within_range);
    Test.add_func ("/scheduler/random_interval_equal", test_scheduler_random_interval_equal_min_max);
    Test.add_func ("/scheduler/random_interval_inverted", test_scheduler_random_interval_min_greater_than_max);
    Test.add_func ("/scheduler/start", test_scheduler_start_sets_running);
    Test.add_func ("/scheduler/stop", test_scheduler_stop_clears_state);
    Test.add_func ("/scheduler/double_start", test_scheduler_double_start_is_safe);
    Test.add_func ("/scheduler/double_stop", test_scheduler_double_stop_is_safe);
    Test.add_func ("/scheduler/capture_fires", test_scheduler_capture_fires);

    return Test.run ();
}
