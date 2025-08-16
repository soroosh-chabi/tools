const std = @import("std");
const gio = @import("clibs.zig").gio;
const credentials = @import("credentials.zig");
const client = @import("client.zig");

pub const std_options = std.Options{
    .logFn = timedLog,
};

var allocator: std.mem.Allocator = undefined;
var config_path: []const u8 = undefined;
var session_manager: client.SessionManager = undefined;
var session: ?client.Session = null;
var creds: credentials.Credentials = undefined;
var main_loop: *gio.GMainLoop = undefined;
var connect_thread: ?std.Thread = null;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    allocator = gpa.allocator();

    creds = try credentials.getCredentials(allocator);
    defer creds.deinit();

    var config_manager = try client.ConfigManager.init();
    defer config_manager.deinit();

    session_manager = try client.SessionManager.init();
    defer session_manager.deinit();

    config_path = (try config_manager.LookupConfigName(allocator, creds.config_name)).?;
    defer allocator.free(config_path);

    try startSession();
    defer endSession();

    main_loop = gio.g_main_loop_new(null, gio.FALSE) orelse return;
    defer gio.g_main_loop_unref(main_loop);

    _ = gio.g_unix_signal_add(std.os.linux.SIG.INT, sigIntHandler, null);

    gio.g_main_loop_run(main_loop);
}

pub fn timedLog(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const now = gio.g_date_time_new_now_local();
    defer gio.g_date_time_unref(now);
    const now_str = gio.g_date_time_format(now, "%H:%M");
    defer gio.g_free(now_str);
    std.log.defaultLog(level, scope, "({s}) " ++ format, .{now_str} ++ args);
}

fn startSession() !void {
    session = try session_manager.createNewTunnel(allocator, config_path);

    try session.?.listenToStatusChange(statusChangedHandler, .{});
    try session.?.listenToAttentionRequired(attentionRequiredHandler, .{});

    connect_thread = try std.Thread.spawn(.{}, connect, .{});
}

fn endSession() void {
    if (connect_thread) |t|
        t.join();
    connect_thread = null;

    if (session) |s| {
        s.disconnect() catch {};
        s.deinit();
    }
    session = null;
}

fn sigIntHandler(_: ?*anyopaque) callconv(.c) gio.gboolean {
    quit();
    return gio.FALSE;
}

fn quit() void {
    std.io.getStdOut().writeAll("Quitting...\n") catch {};
    gio.g_main_loop_quit(main_loop);
}

fn statusChangedHandler(major: u32, minor: u32, message: []const u8) void {
    const stdOut = std.io.getStdOut().writer();
    stdOut.writeAll("Status change: ") catch {};
    if (major == 2) {
        switch (minor) {
            2, 16 => return,
            6 => stdOut.writeAll("connecting...\n") catch {},
            7 => stdOut.writeAll("connected.\n") catch {},
            8 => stdOut.writeAll("disconnecting...\n") catch {},
            9 => {
                stdOut.writeAll("disconnected.\n") catch {};
                endSession();
                startSession() catch {
                    stdOut.writeAll("Failed to reconnect.\n") catch {};
                    quit();
                };
            },
            11 => {
                stdOut.writeAll("authentication failed ") catch {};
                if (session.?.ready()) {
                    stdOut.writeAll("but ready!\n") catch {};
                } else |_| {
                    stdOut.writeAll("and not ready.\n") catch {};
                }
            },
            12 => stdOut.writeAll("reconnecting...\n") catch {},
            else => stdOut.print("{d}.{d}: {s}\n", .{ major, minor, message }) catch {},
        }
    } else {
        stdOut.print("{d}.{d}: {s}\n", .{ major, minor, message }) catch {};
    }
}

fn attentionRequiredHandler(@"type": u32, group: u32, message: []const u8) void {
    std.debug.print("Attention required: {d}.{d}: {s}\n", .{ @"type", group, message });
}

fn connect() !void {
    const totp = try creds.generateTotp();
    defer allocator.free(totp);
    try session.?.setInputs(.{
        .username = creds.username,
        .password = creds.password,
        .totp = totp,
    });
    try session.?.connect();
}
