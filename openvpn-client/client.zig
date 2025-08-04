const std = @import("std");

pub const gio = @cImport({
    @cInclude("gio/gio.h");
    @cInclude("glib-unix.h");
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
    if (params) |p| {
        _ = gio.g_variant_ref_sink(p);
    }
    defer {
        if (params) |p| {
            gio.g_variant_unref(p);
        }
    }
    var g_error: ?*gio.GError = null;
    var backoff: u32 = 100;
    var retries: u32 = 0;
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

pub const SessionFactory = struct {
    config_mgr_proxy: *gio.GDBusProxy,
    session_mgr_proxy: *gio.GDBusProxy,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !SessionFactory {
        return .{
            .config_mgr_proxy = blk: {
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
                break :blk proxy;
            },
            .session_mgr_proxy = blk: {
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
                break :blk proxy;
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: SessionFactory) void {
        gio.g_object_unref(self.config_mgr_proxy);
        gio.g_object_unref(self.session_mgr_proxy);
    }

    fn getConfigPath(self: SessionFactory, config_name: []const u8) ![*:0]u8 {
        const config_name_c = try self.allocator.dupeZ(u8, config_name);
        defer self.allocator.free(config_name_c);
        const result = try callWithRetry(
            self.config_mgr_proxy,
            "LookupConfigName",
            gio.g_variant_new("(s)", config_name_c.ptr),
        );
        defer gio.g_variant_unref(result);
        const config_paths = gio.g_variant_get_child_value(result, 0);
        defer gio.g_variant_unref(config_paths);
        var config_path: [*:0]u8 = undefined;
        gio.g_variant_get_child(config_paths, 0, "o", &config_path);
        return config_path;
    }

    fn createNewTunnel(self: SessionFactory, config_path: [*:0]const u8) !Session {
        const result = try callWithRetry(
            self.session_mgr_proxy,
            "NewTunnel",
            gio.g_variant_new("(o)", config_path),
        );
        defer gio.g_variant_unref(result);
        var session_path: [*:0]u8 = undefined;
        gio.g_variant_get_child(result, 0, "o", &session_path);
        defer gio.g_free(session_path);
        return try Session.init(self.allocator, session_path);
    }

    pub fn newSession(self: SessionFactory, config_name: []const u8) !Session {
        const config_path = try self.getConfigPath(config_name);
        defer gio.g_free(config_path);
        return try self.createNewTunnel(config_path);
    }
};

pub const Session = struct {
    session_proxy: *gio.GDBusProxy,
    log_proxy: *gio.GDBusProxy,
    allocator: std.mem.Allocator,
    username: ?[*:0]u8 = null,
    password: ?[*:0]u8 = null,
    totp_secret: ?[]u8 = null,

    fn init(allocator: std.mem.Allocator, session_path: [*:0]const u8) !Session {
        var g_error: ?*gio.GError = null;
        const session_proxy = gio.g_dbus_proxy_new_for_bus_sync(
            gio.G_BUS_TYPE_SYSTEM,
            gio.G_DBUS_PROXY_FLAGS_NONE,
            null,
            "net.openvpn.v3.sessions",
            session_path,
            "net.openvpn.v3.sessions",
            null,
            &g_error,
        );
        try reportGError(g_error);
        _ = try callWithRetry(
            session_proxy,
            "LogForward",
            gio.g_variant_new("(b)", gio.TRUE),
        );
        const log_proxy = gio.g_dbus_proxy_new_for_bus_sync(
            gio.G_BUS_TYPE_SYSTEM,
            gio.G_DBUS_PROXY_FLAGS_NONE,
            null,
            "net.openvpn.v3.log",
            session_path,
            "net.openvpn.v3.backends",
            null,
            &g_error,
        );
        try reportGError(g_error);
        if (gio.g_signal_connect_data(
            log_proxy,
            "g-signal",
            gio.G_CALLBACK(handleLogSignals),
            null,
            null,
            gio.G_CONNECT_DEFAULT,
        ) <= 0) {
            return error.GError;
        }
        return .{
            .session_proxy = session_proxy,
            .log_proxy = log_proxy,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Session) void {
        gio.g_object_unref(self.session_proxy);
        gio.g_object_unref(self.log_proxy);
        if (self.username) |username| {
            self.allocator.free(std.mem.span(username));
        }
        if (self.password) |password| {
            self.allocator.free(std.mem.span(password));
        }
        if (self.totp_secret) |totp_secret| {
            self.allocator.free(totp_secret);
        }
    }

    fn handleLogSignals(
        _: ?*gio.GDBusProxy,
        _: [*:0]u8,
        _: [*:0]u8,
        _: ?*gio.GVariant,
        _: ?*anyopaque,
    ) callconv(.c) void {
        std.debug.print("Signal received\n", .{});
    }

    pub fn setCredentials(
        self: *Session,
        credentials: struct { username: []const u8, password: []const u8, totp_secret: []const u8 },
    ) !void {
        self.username = try self.allocator.dupeZ(u8, credentials.username);
        self.password = try self.allocator.dupeZ(u8, credentials.password);
        self.totp_secret = try self.allocator.dupe(u8, credentials.totp_secret);
    }

    fn generateTotp(self: Session) ![*:0]u8 {
        // Build oathtool command
        const argv = [_][]const u8{
            "oathtool",
            "--totp",
            "-d6",
            "-b",
            self.totp_secret.?,
        };

        // Execute oathtool and capture output
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &argv,
        });
        defer self.allocator.free(result.stderr);
        errdefer self.allocator.free(result.stdout);
        if (result.stderr.len > 0) {
            try std.io.getStdOut().writer().print("Generating TOTP failed: {s}\n", .{result.stderr});
            return error.TOTPError;
        }
        // Convert output to null-terminated string, trimming newline
        result.stdout[result.stdout.len - 1] = 0;
        return @ptrCast(result.stdout);
    }

    pub fn connect(self: Session) void {
        gio.g_dbus_proxy_call(
            self.session_proxy,
            "Connect",
            null,
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            null,
            null,
            null,
        );
    }

    pub fn disconnect(self: Session) !void {
        gio.g_variant_unref(try callWithRetry(self.session_proxy, "Disconnect", null));
    }

    pub fn setInputs(self: Session) !void {
        gio.g_variant_unref(try callWithRetry(
            self.session_proxy,
            "UserInputProvide",
            gio.g_variant_new("(uuus)", @as(u32, 1), @as(u32, 1), @as(u32, 0), self.username.?),
        ));
        gio.g_variant_unref(try callWithRetry(
            self.session_proxy,
            "UserInputProvide",
            gio.g_variant_new("(uuus)", @as(u32, 1), @as(u32, 1), @as(u32, 1), self.password.?),
        ));
        const totp = try self.generateTotp();
        defer self.allocator.free(std.mem.span(totp));
        gio.g_variant_unref(try callWithRetry(
            self.session_proxy,
            "UserInputProvide",
            gio.g_variant_new("(uuus)", @as(u32, 1), @as(u32, 4), @as(u32, 0), totp),
        ));
    }
};
