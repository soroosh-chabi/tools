const std = @import("std");
const gio = @import("clibs.zig").gio;
const credentials = @import("credentials.zig");
const client = @import("client.zig");

var main_loop: *gio.GMainLoop = undefined;
var allocator: std.mem.Allocator = undefined;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer _ = gpa.deinit();
    allocator = gpa.allocator();

    const creds = try credentials.getCredentials(allocator);
    defer creds.deinit();

    main_loop = gio.g_main_loop_new(null, gio.FALSE) orelse return error.GError;
    defer gio.g_main_loop_unref(main_loop);

    _ = gio.g_idle_add_once(asyncMain, null);
    gio.g_main_loop_run(main_loop);
}

fn asyncMain(_: gio.gpointer) callconv(.c) void {
    client.ConfigMgrClient.lookupConfigName(
        allocator,
        "daricheh",
        lookupConfigNameReady,
        null,
    ) catch {};
}

fn lookupConfigNameReady(config_path: ?[*:0]u8, g_error: ?*gio.GError, _: ?*anyopaque) void {
    defer gio.g_main_loop_quit(main_loop);
    if (g_error) |e| {
        defer gio.g_error_free(e);
        std.io.getStdOut().writer().print(
            "Error:\n\tdomain: {s}\n\tcode: {d}\n\tmessage: {s}\n",
            .{ gio.g_quark_to_string(e.domain), e.code, e.message },
        ) catch {};
    } else if (config_path) |p| {
        defer gio.g_free(p);
        std.io.getStdOut().writer().print("Config path: {s}\n", .{p}) catch {};
    }
}
