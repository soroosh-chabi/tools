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

    // Convert []const u8 to null-terminated string for C function
    const c_config_name = try allocator.dupeZ(u8, cred_file.credentials.config_name.?);
    defer allocator.free(c_config_name);

    const config_path = try client.getConfigPath(c_config_name.ptr);
    defer client.gio.g_free(config_path);
    const session = try client.createNewTunnel(config_path);
    defer session.deinit() catch {};

    const username = try allocator.dupeZ(u8, cred_file.credentials.username.?);
    defer allocator.free(username);
    const password = try allocator.dupeZ(u8, cred_file.credentials.password.?);
    defer allocator.free(password);
    const totp_secret = try allocator.dupeZ(u8, cred_file.credentials.totp_secret.?);
    defer allocator.free(totp_secret);
    try session.setInputs(.{
        .username = username.ptr,
        .password = password.ptr,
        .totp_secret = totp_secret.ptr,
    });
}
