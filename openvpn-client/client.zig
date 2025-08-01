const std = @import("std");

pub const gio = @cImport({
    @cInclude("gio/gio.h");
});

fn reportGError(g_error: ?*gio.GError) !void {
    if (g_error) |e| {
        defer gio.g_error_free(e);
        try std.io.getStdOut().writer().print(
            "Error:\n\tdomain: {s}\n\tcode: {d}\n\tmessage: {s}\n",
            .{ gio.g_quark_to_string(e.domain), e.code, e.message },
        );
        return error.GError;
    }
}

const max_retries = 3;

fn callWithRetry(
    proxy: *gio.GDBusProxy,
    method_name: [*:0]const u8,
    params: ?*gio.GVariant,
) !*gio.GVariant {
    var g_error: ?*gio.GError = null;
    var backoff: u32 = 100;
    var retries: u32 = 0;
    _ = gio.g_variant_ref_sink(params);
    defer gio.g_variant_unref(params);
    while (true) {
        const result = gio.g_dbus_proxy_call_sync(
            proxy,
            method_name,
            params,
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            null,
            &g_error,
        );
        if (g_error) |e| {
            if (e.domain == gio.g_dbus_error_quark() and e.code == gio.G_DBUS_ERROR_UNKNOWN_METHOD and retries < max_retries) {
                gio.g_clear_error(&g_error);
                std.time.sleep(std.time.ns_per_ms * backoff);
                backoff *= 2;
                retries += 1;
                continue;
            }
        }
        try reportGError(g_error);
        return result.?;
    }
}

pub fn getConfigPath(config_name: [*:0]const u8) ![*:0]u8 {
    var g_error: ?*gio.GError = null;
    const proxy = gio.g_dbus_proxy_new_for_bus_sync(
        gio.G_BUS_TYPE_SYSTEM,
        gio.G_DBUS_PROXY_FLAGS_NONE,
        null,
        "net.openvpn.v3.configuration",
        "/net/openvpn/v3/configuration",
        "net.openvpn.v3.configuration",
        null,
        &g_error,
    );
    try reportGError(g_error);
    defer gio.g_object_unref(proxy);

    const result = try callWithRetry(
        proxy,
        "LookupConfigName",
        gio.g_variant_new("(s)", config_name),
    );
    defer gio.g_variant_unref(result);
    const config_paths = gio.g_variant_get_child_value(result, 0);
    defer gio.g_variant_unref(config_paths);
    var config_path: [*:0]u8 = undefined;
    gio.g_variant_get_child(config_paths, 0, "o", &config_path);
    return config_path;
}

pub fn createNewTunnel(config_path: [*:0]const u8) ![*:0]u8 {
    var g_error: ?*gio.GError = null;
    const proxy = gio.g_dbus_proxy_new_for_bus_sync(
        gio.G_BUS_TYPE_SYSTEM,
        gio.G_DBUS_PROXY_FLAGS_NONE,
        null,
        "net.openvpn.v3.sessions",
        "/net/openvpn/v3/sessions",
        "net.openvpn.v3.sessions",
        null,
        &g_error,
    );
    try reportGError(g_error);
    defer gio.g_object_unref(proxy);

    const result = try callWithRetry(
        proxy,
        "NewTunnel",
        gio.g_variant_new("(o)", config_path),
    );
    defer gio.g_variant_unref(result);
    var session_path: [*:0]u8 = undefined;
    gio.g_variant_get_child(result, 0, "o", &session_path);
    return session_path;
}
