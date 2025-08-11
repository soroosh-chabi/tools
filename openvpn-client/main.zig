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

    var config_manager = try client.ConfigManager.init();
    defer config_manager.deinit();

    var session_manager = try client.SessionManager.init();
    defer session_manager.deinit();

    const config_path = (try config_manager.LookupConfigName(allocator, cred_file.credentials.config_name.?)).?;
    defer allocator.free(config_path);

    const session = try session_manager.createNewTunnel(allocator, config_path);
    defer session.deinit();
    defer session.disconnect() catch {};
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
    errdefer allocator.free(result.stdout);
    if (result.stderr.len > 0) {
        try std.io.getStdOut().writer().print("Generating TOTP failed: {s}\n", .{result.stderr});
        return error.TOTPError;
    }
    // Trim newline
    return result.stdout[0 .. result.stdout.len - 1];
}
