const std = @import("std");
const credentials = @import("credentials.zig");
const client = @import("client.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const creds = try credentials.getCredentials(allocator);
    defer creds.deinit();

    var session_factory = try client.SessionFactory.init(allocator);
    defer session_factory.deinit();

    const main_loop = client.gio.g_main_loop_new(
        null,
        client.gio.FALSE,
    );
    defer client.gio.g_main_loop_unref(main_loop);

    var session = try session_factory.newSession(creds.config_name.?);
    defer session.deinit();

    try session.setCredentials(.{
        .username = creds.username.?,
        .password = creds.password.?,
        .totp_secret = creds.totp_secret.?,
    });

    const SigIntClosure = struct {
        const SigIntClosure = @This();
        closure_session: *client.Session,
        closure_main_loop: *client.gio.GMainLoop,
        fn callback(user_data: ?*anyopaque) callconv(.c) c_int {
            const self: *const SigIntClosure = @alignCast(@ptrCast(user_data));
            self.closure_session.disconnect(struct {
                fn callback(_: ?*client.gio.GVariant, err: ?*client.gio.GError, disconnect_user_data: ?*anyopaque) void {
                    const disconnect_self: *const SigIntClosure = @alignCast(@ptrCast(disconnect_user_data));
                    defer client.gio.g_main_loop_quit(disconnect_self.closure_main_loop);
                    if (err) |_| {
                        std.debug.print("Error disconnecting.\n", .{});
                    }
                }
            }.callback, user_data) catch {
                std.debug.print("Error disconnecting.\n", .{});
            };
            return client.gio.G_SOURCE_REMOVE;
        }
    };
    var sigint_closure = SigIntClosure{ .closure_session = &session, .closure_main_loop = main_loop.? };

    // Set up SIGINT handler to quit the mainloop
    _ = client.gio.g_unix_signal_add(
        std.os.linux.SIG.INT,
        SigIntClosure.callback,
        &sigint_closure,
    );

    // Schedule connect to be called when the main loop is idle
    _ = client.gio.g_idle_add_once(struct {
        fn callback(user_data: ?*anyopaque) callconv(.c) void {
            const session_ptr: *client.Session = @alignCast(@ptrCast(user_data));
            session_ptr.connect(struct {
                fn callback(_: ?*client.gio.GVariant, err: ?*client.gio.GError, _: ?*anyopaque) void {
                    if (err) |_| {
                        std.debug.print("Error connecting.\n", .{});
                    }
                }
            }.callback, null) catch {
                std.debug.print("Error connecting.\n", .{});
            };
        }
    }.callback, &session);

    client.gio.g_main_loop_run(main_loop);
}
