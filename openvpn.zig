const std = @import("std");

pub fn askSecret(allocator: std.mem.Allocator, prompt: []const u8) ![]const u8 {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();

    try stdout.writeAll(prompt);

    // Disable echo for password input
    var original_termios: std.os.linux.termios = undefined;
    if (std.os.linux.tcgetattr(stdin.handle, &original_termios) != 0) {
        return error.TerminalError;
    }
    var new_termios = original_termios;
    new_termios.lflag.ECHO = false;
    new_termios.lflag.ECHONL = true;
    if (std.os.linux.tcsetattr(stdin.handle, .FLUSH, &new_termios) != 0) {
        return error.TerminalError;
    }
    defer {
        _ = std.os.linux.tcsetattr(stdin.handle, .FLUSH, &original_termios);
    }

    const secret = try stdin.reader().readUntilDelimiterAlloc(
        allocator,
        '\n',
        1024,
    );

    return secret;
}

pub fn askCredentials(allocator: std.mem.Allocator) !struct { username: []const u8, password: []const u8, totp_secret: []const u8, config_name: []const u8 } {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();

    // Get username
    try stdout.writeAll("Enter username: ");
    const username = try stdin.reader().readUntilDelimiterAlloc(
        allocator,
        '\n',
        1024,
    );

    // Get password (without echo)
    const password = try askSecret(allocator, "Enter password: ");

    // Get TOTP secret (without echo)
    const totp_secret = try askSecret(allocator, "Enter TOTP secret: ");

    // Get config name
    try stdout.writeAll("Enter config name: ");
    const config_name = try stdin.reader().readUntilDelimiterAlloc(
        allocator,
        '\n',
        1024,
    );

    return .{
        .username = username,
        .password = password,
        .totp_secret = totp_secret,
        .config_name = config_name,
    };
}

// Example usage function
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const credentials = try askCredentials(allocator);
    defer allocator.free(credentials.username);
    defer allocator.free(credentials.password);
    defer allocator.free(credentials.totp_secret);
    defer allocator.free(credentials.config_name);

    std.debug.print("Username: {s}\n", .{credentials.username});
    std.debug.print("Password: {s}\n", .{credentials.password});
    std.debug.print("TOTP Secret: {s}\n", .{credentials.totp_secret});
    std.debug.print("Config Name: {s}\n", .{credentials.config_name});
}
