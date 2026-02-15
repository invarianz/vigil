/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 */

/**
 * Schedules screenshot capture at random intervals within a configurable range.
 *
 * The randomization prevents predictability -- the user cannot anticipate
 * when the next screenshot will be taken.
 */
public class Vigil.Services.SchedulerService : Object {

    public signal void capture_requested ();
    public signal void scheduler_started ();
    public signal void scheduler_stopped ();

    /** Minimum interval between screenshots in seconds. */
    public int min_interval_seconds { get; set; default = 30; }

    /** Maximum interval between screenshots in seconds. */
    public int max_interval_seconds { get; set; default = 120; }

    /** Whether the scheduler is currently running. */
    public bool is_running { get; private set; default = false; }

    /** Timestamp of the last capture request. */
    public DateTime? last_capture_time { get; private set; default = null; }

    /** Timestamp of the next scheduled capture. */
    public DateTime? next_capture_time { get; private set; default = null; }

    private uint _timeout_source = 0;

    /**
     * Start the scheduler. It will emit capture_requested at random intervals.
     */
    public void start () {
        if (is_running) {
            return;
        }

        is_running = true;
        scheduler_started ();
        schedule_next ();
    }

    /**
     * Stop the scheduler.
     */
    public void stop () {
        if (!is_running) {
            return;
        }

        if (_timeout_source != 0) {
            Source.remove (_timeout_source);
            _timeout_source = 0;
        }

        is_running = false;
        next_capture_time = null;
        scheduler_stopped ();
    }

    /**
     * Calculate a random interval in seconds between min and max.
     */
    public int get_random_interval () {
        if (min_interval_seconds >= max_interval_seconds) {
            return min_interval_seconds;
        }

        int range = max_interval_seconds - min_interval_seconds;
        return min_interval_seconds + (int) (Random.next_int () % (range + 1));
    }

    private void schedule_next () {
        if (!is_running) {
            return;
        }

        int interval = get_random_interval ();
        next_capture_time = new DateTime.now_local ().add_seconds (interval);
        debug ("Next screenshot in %d seconds", interval);

        _timeout_source = Timeout.add_seconds ((uint) interval, () => {
            _timeout_source = 0;
            last_capture_time = new DateTime.now_local ();
            capture_requested ();

            // Schedule the next one
            if (is_running) {
                schedule_next ();
            }

            return Source.REMOVE;
        });
    }
}
