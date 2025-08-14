const std = @import("std");
const gio = @import("clibs.zig").gio;
const credentials = @import("credentials.zig");
const client = @import("client.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const creds = try credentials.getCredentials(allocator);
    defer creds.deinit();

    var config_manager = try client.ConfigManager.init();
    defer config_manager.deinit();

    var session_manager = try client.SessionManager.init();
    defer session_manager.deinit();

    const config_path = (try config_manager.LookupConfigName(allocator, creds.config_name)).?;
    defer allocator.free(config_path);

    var session = try session_manager.createNewTunnel(allocator, config_path);
    defer session.deinit();
    defer session.disconnect() catch {};

    const main_loop = gio.g_main_loop_new(null, gio.FALSE) orelse return;
    defer gio.g_main_loop_unref(main_loop);

    _ = gio.g_unix_signal_add(std.os.linux.SIG.INT, sigIntHandler, main_loop);

    try session.listenToStatusChange(statusChangedHandler, .{session});
    try session.listenToAttentionRequired(attentionRequiredHandler, .{});

    const thread = try std.Thread.spawn(.{}, connect, .{ allocator, session, creds });
    defer thread.join();

    gio.g_main_loop_run(main_loop);
}

fn sigIntHandler(user_data: ?*anyopaque) callconv(.c) gio.gboolean {
    std.debug.print("quitting...\n", .{});
    gio.g_main_loop_quit(@ptrCast(user_data));
    return gio.FALSE;
}

fn statusChangedHandler(session: client.Session, major: u32, minor: u32, message: []const u8) void {
    const stdOut = std.io.getStdOut().writer();
    if (major == 2) {
        switch (minor) {
            2, 16 => return,
            6 => stdOut.writeAll("Connecting...\n") catch {},
            7 => stdOut.writeAll("Connected.\n") catch {},
            8 => stdOut.writeAll("Disconnecting...\n") catch {},
            9 => stdOut.writeAll("Disconnected.\n") catch {},
            11 => {
                stdOut.writeAll("Authentication failed ") catch {};
                if (session.ready()) {
                    stdOut.writeAll("but ready!\n") catch {};
                } else |_| {
                    stdOut.writeAll("and not ready.\n") catch {};
                }
            },
            12 => stdOut.writeAll("Reconnecting...\n") catch {},
            else => stdOut.print("Status change: {d}.{d}: {s}\n", .{ major, minor, message }) catch {},
        }
    } else {
        stdOut.print("Status change: {d}.{d}: {s}\n", .{ major, minor, message }) catch {};
    }
}

fn attentionRequiredHandler(@"type": u32, group: u32, message: []const u8) void {
    std.debug.print("Attention required: {d}.{d}: {s}\n", .{ @"type", group, message });
}

fn connect(allocator: std.mem.Allocator, session: client.Session, creds: credentials.Credentials) !void {
    const totp = try generateTotp(allocator, creds.totp_secret);
    defer allocator.free(totp);
    try session.setInputs(.{
        .username = creds.username,
        .password = creds.password,
        .totp = totp,
    });
    try session.connect();
}

fn generateTotp(allocator: std.mem.Allocator, totp_secret: []const u8) ![]u8 {
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
