const std = @import("std");
const gio = @import("clibs.zig").gio;
const credentials = @import("credentials.zig");
const client = @import("client.zig");

var allocator: std.mem.Allocator = undefined;
var config_path: []const u8 = undefined;
var session_manager: client.SessionManager = undefined;
var session: ?client.Session = null;
var creds: credentials.Credentials = undefined;

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

    const main_loop = gio.g_main_loop_new(null, gio.FALSE) orelse return;
    defer gio.g_main_loop_unref(main_loop);

    _ = gio.g_unix_signal_add(std.os.linux.SIG.INT, sigIntHandler, main_loop);

    gio.g_main_loop_run(main_loop);
}

fn startSession() !void {
    endSession();
    session = try session_manager.createNewTunnel(allocator, config_path);

    try session.?.listenToStatusChange(statusChangedHandler, .{});
    try session.?.listenToAttentionRequired(attentionRequiredHandler, .{});

    const thread = try std.Thread.spawn(.{}, connect, .{});
    defer thread.join();
}

fn endSession() void {
    if (session) |s| {
        s.disconnect() catch {};
        s.deinit();
    }
    session = null;
}

fn sigIntHandler(user_data: ?*anyopaque) callconv(.c) gio.gboolean {
    std.debug.print("quitting...\n", .{});
    gio.g_main_loop_quit(@ptrCast(user_data));
    return gio.FALSE;
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
            9 => stdOut.writeAll("disconnected.\n") catch {},
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
    const totp = try generateTotp(creds.totp_secret);
    defer allocator.free(totp);
    try session.?.setInputs(.{
        .username = creds.username,
        .password = creds.password,
        .totp = totp,
    });
    try session.?.connect();
}

fn generateTotp(totp_secret: []const u8) ![]u8 {
    // Build oathtool command
    const argv = [_][]const u8{
        "oathtool",
        "--totp",
        "-d6",
        "-b",
        totp_secret,
    };

    // Execute oathtool and capture output
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
    });
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);
    if (result.stderr.len > 0) {
        try std.io.getStdOut().writer().print("Generating TOTP failed: {s}\n", .{result.stderr});
        return error.TOTPError;
    }
    // Trim newline
    return try allocator.dupe(u8, result.stdout[0 .. result.stdout.len - 1]);
}
