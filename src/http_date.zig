//! HTTP dates (RFC 9110 §5.6.7): IMF-fixdate, the one form a server sends:
//! `Sun, 06 Nov 1994 08:49:37 GMT`. Pure integer arithmetic on Unix
//! seconds, so it is exact and the same on every machine.

const std = @import("std");
const assert = std.debug.assert;

pub const length = 29;

/// The last second this formats: 9999-12-31T23:59:59Z (four-digit years).
pub const seconds_max: u64 = 253_402_300_799;

const day_names = [7][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
const month_names = [12][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

pub fn format(unix_seconds: u64) [length]u8 {
    assert(unix_seconds <= seconds_max);
    const days = unix_seconds / std.time.s_per_day;
    const second_of_day = unix_seconds % std.time.s_per_day;
    const date = civil_from_days(days);
    var out: [length]u8 = undefined;
    // 1970-01-01 was a Thursday.
    @memcpy(out[0..3], day_names[days % 7]);
    @memcpy(out[3..5], ", ");
    write_digits(out[5..7], date.day);
    out[7] = ' ';
    @memcpy(out[8..11], month_names[date.month - 1]);
    out[11] = ' ';
    write_digits(out[12..16], date.year);
    out[16] = ' ';
    write_digits(out[17..19], second_of_day / 3600);
    out[19] = ':';
    write_digits(out[20..22], second_of_day / 60 % 60);
    out[22] = ':';
    write_digits(out[23..25], second_of_day % 60);
    @memcpy(out[25..29], " GMT");
    return out;
}

fn write_digits(out: []u8, value: u64) void {
    var rest = value;
    var index = out.len;
    while (index > 0) {
        index -= 1;
        out[index] = '0' + @as(u8, @intCast(rest % 10));
        rest /= 10;
    }
    assert(rest == 0); // the value fit its field
}

const Civil = struct { year: u64, month: u8, day: u8 };

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`, for non-negative days only).
fn civil_from_days(days: u64) Civil {
    const shifted = days + 719_468; // days since 0000-03-01
    const era = shifted / 146_097;
    const day_of_era = shifted - era * 146_097;
    const year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 -
        day_of_era / 146_096) / 365;
    const day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    const month_shifted = (5 * day_of_year + 2) / 153; // March is 0
    const day: u8 = @intCast(day_of_year - (153 * month_shifted + 2) / 5 + 1);
    const month: u8 = @intCast(if (month_shifted < 10) month_shifted + 3 else month_shifted - 9);
    const year = year_of_era + era * 400 + @intFromBool(month <= 2);
    assert(day >= 1 and day <= 31);
    assert(month >= 1 and month <= 12);
    return .{ .year = year, .month = month, .day = day };
}

test "http_date: known dates" {
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", &format(0));
    // RFC 9110's own example.
    try std.testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", &format(784_111_777));
    try std.testing.expectEqualStrings("Tue, 29 Feb 2000 12:00:00 GMT", &format(951_825_600));
    try std.testing.expectEqualStrings("Sun, 04 Oct 2026 00:00:00 GMT", &format(1_791_072_000));
    try std.testing.expectEqualStrings("Fri, 31 Dec 9999 23:59:59 GMT", &format(seconds_max));
}

test "http_date: every day for 600 years agrees with a day-by-day count" {
    // The model: walk the calendar one day at a time.
    var year: u64 = 1970;
    var month: u8 = 1;
    var day: u8 = 1;
    for (0..600 * 366) |days| {
        const civil = civil_from_days(days);
        try std.testing.expectEqual(year, civil.year);
        try std.testing.expectEqual(month, civil.month);
        try std.testing.expectEqual(day, civil.day);
        day += 1;
        if (day > days_in_month(year, month)) {
            day = 1;
            month += 1;
            if (month > 12) {
                month = 1;
                year += 1;
            }
        }
    }
}

fn days_in_month(year: u64, month: u8) u8 {
    const leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0;
    const days = [12]u8{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    return days[month - 1];
}
