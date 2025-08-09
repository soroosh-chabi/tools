const std = @import("std");
const gio = @import("clibs.zig").gio;
const credentials = @import("credentials.zig");
const client = @import("client.zig");

var main_loop: *gio.GMainLoop = undefined;
var allocator: std.mem.Allocator = undefined;
var cancellable: ?*gio.GCancellable = null;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer _ = gpa.deinit();
    allocator = gpa.allocator();

    const creds = try credentials.getCredentials(allocator);
    defer creds.deinit();

    cancellable = gio.g_cancellable_new();
    defer gio.g_object_unref(cancellable);

    main_loop = gio.g_main_loop_new(null, gio.FALSE) orelse return error.GError;
    defer gio.g_main_loop_unref(main_loop);

    _ = gio.g_unix_signal_add(
        std.os.linux.SIG.INT,
        sigIntCallback,
        null,
    );

    _ = gio.g_idle_add_once(asyncMain, null);

    gio.g_main_loop_run(main_loop);
}

fn sigIntCallback(_: ?*anyopaque) callconv(.c) c_int {
    gio.g_cancellable_cancel(cancellable);
    gio.g_main_loop_quit(main_loop);
    return gio.G_SOURCE_REMOVE;
}

fn reportGError(g_error: ?*gio.GError) error{GError}!void {
    if (g_error) |e| {
        defer gio.g_error_free(e);
        std.io.getStdOut().writer().print(
            "Error:\n\tdomain: {s}\n\tcode: {d}\n\tmessage: {s}\n",
            .{ gio.g_quark_to_string(e.domain), e.code, e.message },
        ) catch {};
        return error.GError;
    }
}

fn asyncMain(_: gio.gpointer) callconv(.c) void {
    client.ConfigMgrClient.lookupConfigName(
        "daricheh",
        allocator,
        null,
        lookupConfigNameReady,
        null,
    ) catch {};
}

fn lookupConfigNameReady(config_path: ?[*:0]u8, g_error: ?*gio.GError, _: ?*anyopaque) void {
    defer gio.g_main_loop_quit(main_loop);
    reportGError(g_error) catch return;
    if (config_path) |p| {
        defer gio.g_free(p);
        std.io.getStdOut().writer().print("Config path: {s}\n", .{p}) catch {};
    }
}
