const std = @import("std");
const credentials = @import("credentials.zig");
const client = @import("client.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut();

    // Get current working directory and create absolute path
    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);

    const cred_filename = "credentials.enc";
    const cred_path = try std.fs.path.join(allocator, &[_][]const u8{ cwd, cred_filename });
    defer allocator.free(cred_path);

    var cred_file = try credentials.EncryptedCredentialsFile.init(allocator, cred_path);
    defer cred_file.deinit();

    if (cred_file.exists()) {
        // Load existing credentials
        try cred_file.load();
        try stdout.writeAll("Loaded encrypted credentials from file\n");
    } else {
        // Ask for new credentials and save them
        try cred_file.askAndSave();
        try stdout.writeAll("Saved encrypted credentials to file\n");
    }

    var session_factory = try client.SessionFactory.init(allocator);
    defer session_factory.deinit();

    const main_loop = client.gio.g_main_loop_new(
        null,
        client.gio.FALSE,
    );
    defer client.gio.g_main_loop_unref(main_loop);

    var session = try session_factory.newSession(cred_file.credentials.config_name.?);
    defer session.deinit();

    try session.setCredentials(.{
        .username = cred_file.credentials.username.?,
        .password = cred_file.credentials.password.?,
        .totp_secret = cred_file.credentials.totp_secret.?,
    });
    try session.setInputs();

    // Set up SIGINT handler to quit the mainloop
    _ = client.gio.g_unix_signal_add(std.os.linux.SIG.INT, struct {
        fn callback(user_data: ?*anyopaque) callconv(.c) c_int {
            client.gio.g_main_loop_quit(@ptrCast(user_data));
            return client.gio.G_SOURCE_REMOVE;
        }
    }.callback, main_loop);

    // Schedule connect to be called when the main loop is idle
    _ = client.gio.g_idle_add_once(struct {
        fn callback(user_data: ?*anyopaque) callconv(.c) void {
            const session_ptr: *client.Session = @alignCast(@ptrCast(user_data));
            session_ptr.connect();
        }
    }.callback, &session);

    defer session.disconnect() catch {};
    client.gio.g_main_loop_run(main_loop);
}
