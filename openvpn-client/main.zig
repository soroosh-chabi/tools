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

    try session.listenToStatusChange(statusChangedHandler, .{});

    const thread = try std.Thread.spawn(.{}, client.Session.connect, .{session});
    defer thread.join();

    gio.g_main_loop_run(main_loop);
}

fn sigIntHandler(user_data: ?*anyopaque) callconv(.c) gio.gboolean {
    std.debug.print("quitting...\n", .{});
    gio.g_main_loop_quit(@ptrCast(user_data));
    return gio.FALSE;
}

fn statusChangedHandler(major: u32, minor: u32, message: []const u8) void {
    std.debug.print("Status Changed. {d}.{d}: {s}\n", .{ major, minor, message });
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
    errdefer allocator.free(result.stdout);
    if (result.stderr.len > 0) {
        try std.io.getStdOut().writer().print("Generating TOTP failed: {s}\n", .{result.stderr});
        return error.TOTPError;
    }
    // Trim newline
    return result.stdout[0 .. result.stdout.len - 1];
}
