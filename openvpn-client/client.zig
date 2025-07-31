const std = @import("std");
const credentials = @import("credentials.zig");

const gio = @cImport({
    @cInclude("gio/gio.h");
});

fn getConfigPath(config_name: [*:0]const u8) ![*:0]u8 {
    const proxy = gio.g_dbus_proxy_new_for_bus_sync(
        gio.G_BUS_TYPE_SYSTEM,
        gio.G_DBUS_PROXY_FLAGS_NONE,
        null,
        "net.openvpn.v3.configuration",
        "/net/openvpn/v3/configuration",
        "net.openvpn.v3.configuration",
        null,
        null,
    ) orelse return error.FailedToConnectToOpenvpn3ServiceConfigmgr;
    defer gio.g_object_unref(proxy);

    const result = gio.g_dbus_proxy_call_sync(
        proxy,
        "LookupConfigName",
        gio.g_variant_new("(s)", config_name),
        gio.G_DBUS_CALL_FLAGS_NONE,
        -1,
        null,
        null,
    ) orelse return error.FailedToConnectToOpenvpn3ServiceConfigmgr;
    defer gio.g_variant_unref(result);
    const config_paths = gio.g_variant_get_child_value(result, 0);
    defer gio.g_variant_unref(config_paths);
    var config_path: [*:0]u8 = undefined;
    gio.g_variant_get_child(config_paths, 0, "o", &config_path);
    return config_path;
}

fn createNewTunnel(config_path: [*:0]const u8) ![*:0]u8 {
    const proxy = gio.g_dbus_proxy_new_for_bus_sync(
        gio.G_BUS_TYPE_SYSTEM,
        gio.G_DBUS_PROXY_FLAGS_NONE,
        null,
        "net.openvpn.v3.sessions",
        "/net/openvpn/v3/sessions",
        "net.openvpn.v3.sessions",
        null,
        null,
    ) orelse return error.FailedToConnectToOpenvpn3ServiceSessionmgr;
    defer gio.g_object_unref(proxy);

    const result = gio.g_dbus_proxy_call_sync(
        proxy,
        "NewTunnel",
        gio.g_variant_new("(o)", config_path),
        gio.G_DBUS_CALL_FLAGS_NONE,
        -1,
        null,
        null,
    ) orelse return error.FailedToConnectToOpenvpn3ServiceSessionmgr;
    defer gio.g_variant_unref(result);
    var session_path: [*:0]u8 = undefined;
    gio.g_variant_get_child(result, 0, "o", &session_path);
    return session_path;
}

// Example usage function
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
    const c_config_name = try allocator.dupeZ(u8, cred_file.credentials.config_name orelse return error.MissingConfigName);
    defer allocator.free(c_config_name);

    const config_path = try getConfigPath(c_config_name.ptr);
    defer gio.g_free(config_path);
    const session_path = try createNewTunnel(config_path);
    defer gio.g_free(session_path);
    std.debug.print("Session path: {s}\n", .{session_path});
}
