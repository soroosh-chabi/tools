const std = @import("std");

pub const gio = @cImport({
    @cInclude("gio/gio.h");
    @cInclude("glib-unix.h");
});

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
    session_mgr_proxy: *gio.GDBusProxy,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !SessionFactory {
        return .{
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

    pub const ResultCallback = *const fn (result: ?*gio.GVariant, err: ?*gio.GError, user_data: ?*anyopaque) void;
    const GDBusCallClosure = struct {
        result_callback: ResultCallback,
        user_data: ?*anyopaque,
        allocator: std.mem.Allocator,

        fn init(result_callback: ResultCallback, user_data: ?*anyopaque, allocator: std.mem.Allocator) !*GDBusCallClosure {
            const closure = try allocator.create(GDBusCallClosure);
            closure.result_callback = result_callback;
            closure.user_data = user_data;
            closure.allocator = allocator;
            return closure;
        }

        fn callback(source_object: ?*gio.GObject, res: ?*gio.GAsyncResult, user_data: ?*anyopaque) callconv(.c) void {
            const self: *GDBusCallClosure = @alignCast(@ptrCast(user_data));
            defer self.allocator.destroy(self);
            var g_error: ?*gio.GError = null;
            const result_variant = gio.g_dbus_proxy_call_finish(@ptrCast(source_object), res, &g_error);
            defer gio.g_clear_error(&g_error);
            if (g_error) |_| {} else {
                defer gio.g_variant_unref(result_variant);
            }
            self.result_callback(result_variant, g_error, self.user_data);
        }
    };

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
            "g-signal::StatusChange",
            gio.G_CALLBACK(handleStatusChange),
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
    }

    fn handleStatusChange(
        _: ?*gio.GDBusProxy,
        _: [*:0]u8,
        _: [*:0]u8,
        parameters: ?*gio.GVariant,
        _: ?*anyopaque,
    ) callconv(.c) void {
        var code_major: u32 = undefined;
        var code_minor: u32 = undefined;
        var message: [*:0]u8 = undefined;
        gio.g_variant_get(parameters, "(uus)", &code_major, &code_minor, &message);
        defer gio.g_free(message);
        const stdOut = std.io.getStdOut().writer();
        if (code_major == 2) {
            switch (code_minor) {
                2, 16 => return,
                6 => stdOut.writeAll("Connecting...\n") catch {},
                7 => stdOut.writeAll("Connected.\n") catch {},
                8 => stdOut.writeAll("Disconnecting...\n") catch {},
                9 => stdOut.writeAll("Disconnected.\n") catch {},
                11 => stdOut.writeAll("Authentication failed. Disconnecting...\n") catch {},
                else => stdOut.print("Status change: {d}.{d}: {s}\n", .{ code_major, code_minor, message }) catch {},
            }
        } else {
            stdOut.print("Status change: {d}.{d}: {s}\n", .{ code_major, code_minor, message }) catch {};
        }
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

    pub fn connect(self: Session, result_callback: ResultCallback, user_data: ?*anyopaque) !void {
        gio.g_dbus_proxy_call(
            self.session_proxy,
            "Connect",
            null,
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            null,
            GDBusCallClosure.callback,
            try GDBusCallClosure.init(result_callback, user_data, self.allocator),
        );
    }

    fn ready(self: Session, result_callback: ResultCallback, user_data: ?*anyopaque) void {
        gio.g_dbus_proxy_call(
            self.session_proxy,
            "Ready",
            null,
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            null,
            GDBusCallClosure.callback,
            try GDBusCallClosure.init(result_callback, user_data, self.allocator),
        );
    }

    pub fn disconnect(self: Session, result_callback: ResultCallback, user_data: ?*anyopaque) !void {
        gio.g_dbus_proxy_call(
            self.session_proxy,
            "Disconnect",
            null,
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            null,
            GDBusCallClosure.callback,
            try GDBusCallClosure.init(result_callback, user_data, self.allocator),
        );
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

const DisconnectQuitClosure = struct {
    main_loop: *gio.GMainLoop,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, main_loop: *gio.GMainLoop) !*DisconnectQuitClosure {
        const closure = try allocator.create(DisconnectQuitClosure);
        closure.main_loop = main_loop;
        closure.allocator = allocator;
        return closure;
    }

    fn callback(_: ?*gio.GVariant, err: ?*gio.GError, user_data: ?*anyopaque) void {
        const self: *DisconnectQuitClosure = @alignCast(@ptrCast(user_data));
        defer self.allocator.destroy(self);
        defer gio.g_main_loop_quit(self.main_loop);
        if (err) |_| {
            std.debug.print("Error disconnecting.\n", .{});
        }
    }
};

const RetryingAsyncTask = struct {
    backoff_ms: gio.guint = 100,
    client: *OpenVPNClient,
    start: *const fn (task: *RetryingAsyncTask) anyerror!void,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, start: *const fn (task: *RetryingAsyncTask) anyerror!void, client: *OpenVPNClient) !*RetryingAsyncTask {
        const self = try allocator.create(RetryingAsyncTask);
        self.start = start;
        self.client = client;
        self.allocator = allocator;
        return self;
    }

    fn deinit(self: *RetryingAsyncTask) void {
        self.allocator.destroy(self);
    }

    fn callback(user_data: ?*anyopaque) callconv(.c) void {
        const self: *RetryingAsyncTask = @alignCast(@ptrCast(user_data));
        self.start(self) catch |err| {
            std.io.getStdOut().writer().print("Error: {}\n", .{err}) catch {};
            self.scheduleRetry();
        };
    }

    fn will_retry(self: *RetryingAsyncTask, g_error: ?*gio.GError) bool {
        reportGError(g_error) catch {
            self.scheduleRetry();
            return true;
        };
        return false;
    }

    fn scheduleRetry(self: *RetryingAsyncTask) void {
        _ = gio.g_timeout_add_once(
            self.backoff_ms,
            callback,
            self,
        );
        self.backoff_ms *= 2;
    }
};

pub const OpenVPNClient = struct {
    allocator: std.mem.Allocator,
    username: [*:0]u8,
    password: [*:0]u8,
    totp_secret: []u8,
    config_name: [*:0]const u8,
    main_loop: ?*gio.GMainLoop = null,
    config_mgr_proxy: ?*gio.GDBusProxy = null,

    pub fn init(
        allocator: std.mem.Allocator,
        config_name: []const u8,
        credentials: struct { username: []const u8, password: []const u8, totp_secret: []const u8 },
    ) !OpenVPNClient {
        return .{
            .allocator = allocator,
            .username = try allocator.dupeZ(u8, credentials.username),
            .password = try allocator.dupeZ(u8, credentials.password),
            .totp_secret = try allocator.dupe(u8, credentials.totp_secret),
            .config_name = try allocator.dupeZ(u8, config_name),
        };
    }

    pub fn deinit(self: *OpenVPNClient) void {
        self.allocator.free(std.mem.span(self.username));
        self.allocator.free(std.mem.span(self.password));
        self.allocator.free(self.totp_secret);
        self.allocator.free(std.mem.span(self.config_name));
        if (self.config_mgr_proxy) |p| {
            gio.g_object_unref(p);
        }
    }

    fn createConfigMgrProxy(task: *RetryingAsyncTask) !void {
        gio.g_dbus_proxy_new_for_bus(
            gio.G_BUS_TYPE_SYSTEM,
            gio.G_DBUS_PROXY_FLAGS_NONE,
            null,
            "net.openvpn.v3.configuration",
            "/net/openvpn/v3/configuration",
            "net.openvpn.v3.configuration",
            null,
            configMgrProxyCallback,
            task,
        );
    }

    fn configMgrProxyCallback(_: ?*gio.GObject, res: ?*gio.GAsyncResult, user_data: ?*anyopaque) callconv(.c) void {
        var g_error: ?*gio.GError = null;
        const proxy = gio.g_dbus_proxy_new_for_bus_finish(res, &g_error);
        const task: *RetryingAsyncTask = @alignCast(@ptrCast(user_data));
        if (task.will_retry(g_error)) return;
        defer task.deinit();
        task.client.config_mgr_proxy = proxy;
    }

    pub fn connect(self: *OpenVPNClient) !void {
        self.main_loop = gio.g_main_loop_new(
            null,
            gio.FALSE,
        ) orelse return error.GError;
        defer gio.g_main_loop_unref(self.main_loop);

        _ = gio.g_unix_signal_add(
            std.os.linux.SIG.INT,
            sigIntCallback,
            self,
        );

        _ = gio.g_idle_add_once(
            RetryingAsyncTask.callback,
            try RetryingAsyncTask.init(self.allocator, createConfigMgrProxy, self),
        );

        gio.g_main_loop_run(self.main_loop);
    }

    fn sigIntCallback(user_data: ?*anyopaque) callconv(.c) c_int {
        const self: *OpenVPNClient = @alignCast(@ptrCast(user_data));
        gio.g_main_loop_quit(self.main_loop);
        return gio.G_SOURCE_REMOVE;
    }
};
