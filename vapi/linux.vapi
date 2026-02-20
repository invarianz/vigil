/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2025 invarianz
 *
 * Minimal prctl binding. prctl is in libc, no new dependency needed.
 */

[CCode (cheader_filename = "sys/prctl.h")]
namespace Linux {
    [CCode (cname = "PR_SET_DUMPABLE")]
    public const int PR_SET_DUMPABLE;

    [CCode (cname = "PR_GET_DUMPABLE")]
    public const int PR_GET_DUMPABLE;

    [CCode (cname = "prctl")]
    public int prctl (int option, ulong arg2 = 0, ulong arg3 = 0,
                      ulong arg4 = 0, ulong arg5 = 0);
}
