const std = @import("std");
const credentials = @import("credentials.zig");
const client = @import("client.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const creds = try credentials.getCredentials(allocator);
    defer creds.deinit();

    var ovpn_client = try client.OpenVPNClient.init(allocator, creds.config_name, .{
        .username = creds.username,
        .password = creds.password,
        .totp_secret = creds.totp_secret,
    });
    defer ovpn_client.deinit();
    try ovpn_client.connect();
}
