const std = @import("std");
const gio = @import("clibs.zig").gio;

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

pub const Session = struct {
    session_proxy: *gio.GDBusProxy,
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

const RetryingAsyncTask = struct {
    const default_backoff_ms = 100;
    backoff_ms: gio.guint,
    client: *OpenVPNClient,
    start: *const fn (task: *RetryingAsyncTask) anyerror!void,
    ready: *const fn (task: *RetryingAsyncTask, source_object: ?*gio.GObject, res: ?*gio.GAsyncResult) anyerror!void,
    allocator: std.mem.Allocator,

    fn init(
        allocator: std.mem.Allocator,
        start: *const fn (task: *RetryingAsyncTask) anyerror!void,
        ready: *const fn (task: *RetryingAsyncTask, source_object: ?*gio.GObject, res: ?*gio.GAsyncResult) anyerror!void,
        client: *OpenVPNClient,
    ) *RetryingAsyncTask {
        const self = allocator.create(RetryingAsyncTask) catch @panic("Failed to create retrying async task");
        self.start = start;
        self.ready = ready;
        self.client = client;
        self.allocator = allocator;
        self.backoff_ms = default_backoff_ms;
        return self;
    }

    fn deinit(self: *RetryingAsyncTask) void {
        self.allocator.destroy(self);
    }

    fn reuseWith(
        self: *RetryingAsyncTask,
        start: *const fn (task: *RetryingAsyncTask) anyerror!void,
        ready: *const fn (task: *RetryingAsyncTask, source_object: ?*gio.GObject, res: ?*gio.GAsyncResult) anyerror!void,
    ) void {
        self.start = start;
        self.ready = ready;
        self.reuse();
    }

    fn reuse(self: *RetryingAsyncTask) void {
        self.backoff_ms = default_backoff_ms;
    }

    fn start_callback(user_data: ?*anyopaque) callconv(.c) void {
        const self: *RetryingAsyncTask = @alignCast(@ptrCast(user_data));
        self.start(self) catch |err| {
            std.io.getStdOut().writer().print("Error: {}\n", .{err}) catch {};
            self.scheduleRetry();
        };
    }

    fn ready_callback(source_object: ?*gio.GObject, res: ?*gio.GAsyncResult, user_data: ?*anyopaque) callconv(.c) void {
        const self: *RetryingAsyncTask = @alignCast(@ptrCast(user_data));
        self.ready(self, source_object, res) catch |err| {
            std.io.getStdOut().writer().print("Error: {}\n", .{err}) catch {};
            self.scheduleRetry();
        };
    }

    fn should_return(self: *RetryingAsyncTask, g_error: ?*gio.GError) bool {
        if (g_error) |e| {
            if (e.domain == gio.g_io_error_quark() and e.code == gio.G_IO_ERROR_CANCELLED) {
                gio.g_error_free(e);
                return true;
            }
        }
        reportGError(g_error) catch {
            self.scheduleRetry();
            return true;
        };
        return false;
    }

    fn scheduleRetry(self: *RetryingAsyncTask) void {
        _ = gio.g_timeout_add_once(
            self.backoff_ms,
            start_callback,
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
    config_path: ?[*:0]u8 = null,
    session_mgr_proxy: ?*gio.GDBusProxy = null,
    session_path: ?[*:0]u8 = null,
    log_proxy: ?*gio.GDBusProxy = null,
    session_proxy: ?*gio.GDBusProxy = null,
    connection_cancellable: *gio.GCancellable,
    disconnecting: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        credentials: struct { username: []const u8, password: []const u8, totp_secret: []const u8 },
    ) !OpenVPNClient {
        return .{
            .allocator = allocator,
            .username = try allocator.dupeZ(u8, credentials.username),
            .password = try allocator.dupeZ(u8, credentials.password),
            .totp_secret = try allocator.dupe(u8, credentials.totp_secret),
            .connection_cancellable = gio.g_cancellable_new(),
        };
    }

    pub fn deinit(self: *OpenVPNClient) void {
        self.allocator.free(std.mem.span(self.username));
        self.allocator.free(std.mem.span(self.password));
        self.allocator.free(self.totp_secret);
        if (self.config_path) |p| {
            gio.free(p);
        }
        if (self.session_mgr_proxy) |p| {
            gio.g_object_unref(p);
        }
        if (self.session_path) |p| {
            gio.free(p);
        }
        if (self.log_proxy) |p| {
            gio.g_object_unref(p);
        }
        if (self.session_proxy) |p| {
            gio.g_object_unref(p);
        }
        gio.g_object_unref(self.connection_cancellable);
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

    fn createSessionMgrProxy(task: *RetryingAsyncTask) !void {
        gio.g_dbus_proxy_new_for_bus(
            gio.G_BUS_TYPE_SYSTEM,
            gio.G_DBUS_PROXY_FLAGS_NONE,
            null,
            "net.openvpn.v3.sessions",
            "/net/openvpn/v3/sessions",
            "net.openvpn.v3.sessions",
            task.client.connection_cancellable,
            RetryingAsyncTask.ready_callback,
            task,
        );
    }

    fn createSessionMgrProxyReady(task: *RetryingAsyncTask, _: ?*gio.GObject, res: ?*gio.GAsyncResult) !void {
        var g_error: ?*gio.GError = null;
        const proxy = gio.g_dbus_proxy_new_for_bus_finish(res, &g_error);
        if (task.should_return(g_error)) return;
        task.client.session_mgr_proxy = proxy;
        task.reuseWith(createSession, createSessionReady);
        RetryingAsyncTask.start_callback(task);
    }

    fn createSession(task: *RetryingAsyncTask) !void {
        gio.g_dbus_proxy_call(
            task.client.session_mgr_proxy,
            "NewTunnel",
            gio.g_variant_new("(o)", task.client.config_path),
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            // We don't want this to be cancellable so we always know the path to the new session if one is created
            null,
            RetryingAsyncTask.ready_callback,
            task,
        );
    }

    fn createSessionReady(task: *RetryingAsyncTask, source_object: ?*gio.GObject, res: ?*gio.GAsyncResult) !void {
        var g_error: ?*gio.GError = null;
        const result = gio.g_dbus_proxy_call_finish(@ptrCast(source_object), res, &g_error);
        if (task.should_return(g_error)) return;
        defer gio.g_variant_unref(result);
        gio.g_variant_get_child(result, 0, "o", &task.client.session_path);
        task.reuseWith(createSessionProxy, createSessionProxyReady);
        std.debug.print("session created\n", .{});
        _ = gio.g_timeout_add_once(5000, RetryingAsyncTask.start_callback, task);
    }

    fn createSessionProxy(task: *RetryingAsyncTask) !void {
        var cancellable: ?*gio.GCancellable = task.client.connection_cancellable;
        if (task.client.disconnecting) {
            if (task.client.session_path == null) {
                task.scheduleRetry();
                return;
            } else {
                cancellable = null;
            }
        }
        gio.g_dbus_proxy_new_for_bus(
            gio.G_BUS_TYPE_SYSTEM,
            gio.G_DBUS_PROXY_FLAGS_NONE,
            null,
            "net.openvpn.v3.sessions",
            task.client.session_path.?,
            "net.openvpn.v3.sessions",
            cancellable,
            RetryingAsyncTask.ready_callback,
            task,
        );
    }

    fn createSessionProxyReady(task: *RetryingAsyncTask, _: ?*gio.GObject, res: ?*gio.GAsyncResult) !void {
        var g_error: ?*gio.GError = null;
        const proxy = gio.g_dbus_proxy_new_for_bus_finish(res, &g_error);
        if (task.should_return(g_error)) {
            std.debug.print("session proxy creation failed\n", .{});
            return;
        }
        task.client.session_proxy = proxy;
        std.debug.print("session proxy created\n", .{});
        if (task.client.disconnecting) {
            task.reuseWith(disconnect, disconnectReady);
        } else {
            task.reuseWith(forwardLog, forwardLogReady);
        }
        RetryingAsyncTask.start_callback(task);
    }

    fn forwardLog(task: *RetryingAsyncTask) !void {
        gio.g_dbus_proxy_call(
            task.client.session_proxy,
            "LogForward",
            gio.g_variant_new("(b)", gio.TRUE),
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            task.client.connection_cancellable,
            RetryingAsyncTask.ready_callback,
            task,
        );
    }

    fn forwardLogReady(task: *RetryingAsyncTask, source_object: ?*gio.GObject, res: ?*gio.GAsyncResult) !void {
        var g_error: ?*gio.GError = null;
        const result = gio.g_dbus_proxy_call_finish(@ptrCast(source_object), res, &g_error);
        if (task.should_return(g_error)) return;
        defer gio.g_variant_unref(result);
        task.reuseWith(createLogProxy, createLogProxyReady);
        RetryingAsyncTask.start_callback(task);
    }

    fn createLogProxy(task: *RetryingAsyncTask) !void {
        gio.g_dbus_proxy_new_for_bus(
            gio.G_BUS_TYPE_SYSTEM,
            gio.G_DBUS_PROXY_FLAGS_NONE,
            null,
            "net.openvpn.v3.log",
            task.client.session_path.?,
            "net.openvpn.v3.backends",
            task.client.connection_cancellable,
            RetryingAsyncTask.ready_callback,
            task,
        );
    }

    fn createLogProxyReady(task: *RetryingAsyncTask, _: ?*gio.GObject, res: ?*gio.GAsyncResult) !void {
        var g_error: ?*gio.GError = null;
        const proxy = gio.g_dbus_proxy_new_for_bus_finish(res, &g_error);
        errdefer gio.g_object_unref(proxy);
        if (task.should_return(g_error)) return;
        if (gio.g_signal_connect_data(
            proxy,
            "g-signal::StatusChange",
            gio.G_CALLBACK(handleStatusChange),
            null,
            null,
            gio.G_CONNECT_DEFAULT,
        ) <= 0) {
            return error.GError;
        }
        task.client.log_proxy = proxy;
        task.deinit();
    }

    fn disconnect(task: *RetryingAsyncTask) !void {
        gio.g_dbus_proxy_call(
            task.client.session_proxy,
            "Disconnect",
            null,
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            null,
            RetryingAsyncTask.ready_callback,
            task,
        );
    }

    fn disconnectReady(task: *RetryingAsyncTask, source_object: ?*gio.GObject, res: ?*gio.GAsyncResult) !void {
        var g_error: ?*gio.GError = null;
        const result = gio.g_dbus_proxy_call_finish(@ptrCast(source_object), res, &g_error);
        if (task.should_return(g_error)) return;
        defer gio.g_variant_unref(result);
        gio.g_main_loop_quit(task.client.main_loop);
        task.deinit();
    }

    pub fn connect(self: *OpenVPNClient) !void {
        _ = gio.g_unix_signal_add(
            std.os.linux.SIG.INT,
            sigIntCallback,
            self,
        );
    }

    fn sigIntCallback(user_data: ?*anyopaque) callconv(.c) c_int {
        const self: *OpenVPNClient = @alignCast(@ptrCast(user_data));
        gio.g_cancellable_cancel(self.connection_cancellable);
        // We definitely have not created a session, so we can quit the main loop
        if (self.session_mgr_proxy == null) {
            gio.g_main_loop_quit(self.main_loop);
        } else {
            var task: *RetryingAsyncTask = undefined;
            if (self.session_proxy == null) {
                self.disconnecting = true;
                task = RetryingAsyncTask.init(
                    self.allocator,
                    createSessionProxy,
                    createSessionProxyReady,
                    self,
                );
            } else {
                task = RetryingAsyncTask.init(
                    self.allocator,
                    disconnect,
                    disconnectReady,
                    self,
                );
            }
            _ = gio.g_idle_add_once(RetryingAsyncTask.start_callback, task);
        }
        return gio.G_SOURCE_REMOVE;
    }
};

pub const ConfigMgrClient = struct {
    const max_retries = 3;
    const default_backoff_ms = 100;
    pub const LookupCallback = *const fn (config_path: ?[*:0]u8, g_error: ?*gio.GError, user_data: ?*anyopaque) void;
    const LookupContext = struct {
        config_name: [*:0]const u8,
        callback: LookupCallback,
        user_data: ?*anyopaque,
        allocator: std.mem.Allocator,
        backoff_ms: u32,
        retries: u32,
        proxy: ?*gio.GDBusProxy = null,
        cancellable: ?*gio.GCancellable,

        fn deinit(self: *LookupContext) void {
            if (self.proxy) |p| {
                gio.g_object_unref(p);
            }
        }

        fn resetRetries(self: *LookupContext) void {
            self.retries = 0;
            self.backoff_ms = default_backoff_ms;
        }
    };

    fn shouldReturn(
        ctx: *LookupContext,
        g_error: ?*gio.GError,
        retry_callback: fn (user_data: gio.gpointer) callconv(.c) void,
    ) bool {
        if (g_error) |e| {
            const cancelled = gio.g_cancellable_is_cancelled(ctx.cancellable) != gio.FALSE;
            const retries_exceeded = ctx.retries >= ConfigMgrClient.max_retries;
            if (cancelled or retries_exceeded) {
                ctx.callback(null, e, ctx.user_data);
                destroy(ctx);
            } else {
                _ = gio.g_timeout_add_once(ctx.backoff_ms, retry_callback, ctx);
                ctx.retries += 1;
                ctx.backoff_ms *= 2;
            }
            return true;
        }
        ctx.resetRetries();
        return false;
    }

    fn destroy(ctx: *LookupContext) void {
        ctx.deinit();
        ctx.allocator.destroy(ctx);
    }

    pub fn lookupConfigName(
        config_name: [*:0]const u8,
        allocator: std.mem.Allocator,
        cancellable: ?*gio.GCancellable,
        callback: LookupCallback,
        user_data: ?*anyopaque,
    ) !void {
        const ctx = try allocator.create(LookupContext);
        ctx.allocator = allocator;
        ctx.config_name = config_name;
        ctx.callback = callback;
        ctx.user_data = user_data;
        ctx.backoff_ms = default_backoff_ms;
        ctx.retries = 0;
        ctx.cancellable = cancellable;
        createProxy(ctx);
    }

    fn createProxy(user_data: gio.gpointer) callconv(.c) void {
        const ctx: *LookupContext = @alignCast(@ptrCast(user_data));
        gio.g_dbus_proxy_new_for_bus(
            gio.G_BUS_TYPE_SYSTEM,
            gio.G_DBUS_PROXY_FLAGS_NONE,
            null,
            "net.openvpn.v3.configuration",
            "/net/openvpn/v3/configuration",
            "net.openvpn.v3.configuration",
            ctx.cancellable,
            proxyReady,
            ctx,
        );
    }

    fn proxyReady(
        _: ?*gio.GObject,
        res: ?*gio.GAsyncResult,
        user_data: gio.gpointer,
    ) callconv(.c) void {
        const ctx: *LookupContext = @alignCast(@ptrCast(user_data));
        var g_error: ?*gio.GError = null;
        const proxy = gio.g_dbus_proxy_new_for_bus_finish(res, &g_error);
        if (shouldReturn(ctx, g_error, createProxy)) {
            return;
        }
        ctx.proxy = proxy;
        callLookupConfigName(ctx);
    }

    fn callLookupConfigName(user_data: gio.gpointer) callconv(.c) void {
        const ctx: *LookupContext = @alignCast(@ptrCast(user_data));
        gio.g_dbus_proxy_call(
            ctx.proxy,
            "LookupConfigName",
            gio.g_variant_new("(s)", ctx.config_name),
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            ctx.cancellable,
            callLookupConfigNameReady,
            ctx,
        );
    }

    fn callLookupConfigNameReady(
        source_object: ?*gio.GObject,
        res: ?*gio.GAsyncResult,
        user_data: gio.gpointer,
    ) callconv(.c) void {
        const ctx: *LookupContext = @alignCast(@ptrCast(user_data));
        var g_error: ?*gio.GError = null;
        const result = gio.g_dbus_proxy_call_finish(@ptrCast(source_object), res, &g_error);
        if (shouldReturn(ctx, g_error, callLookupConfigName)) {
            return;
        }
        defer gio.g_variant_unref(result);
        const expected_type = gio.g_variant_type_new("(ao)");
        defer gio.g_variant_type_free(expected_type);
        if (gio.g_variant_is_of_type(result, expected_type) == gio.FALSE) {
            _ = shouldReturn(ctx, gio.g_error_new_literal(
                gio.g_io_error_quark(),
                gio.G_IO_ERROR_FAILED,
                "Invalid response from configuration manager",
            ), callLookupConfigName);
            return;
        }
        defer destroy(ctx);
        const config_paths = gio.g_variant_get_child_value(result, 0);
        defer gio.g_variant_unref(config_paths);
        var config_path: ?[*:0]u8 = null;
        if (gio.g_variant_n_children(config_paths) > 0) {
            gio.g_variant_get_child(config_paths, 0, "o", &config_path);
        }
        ctx.callback(config_path, null, ctx.user_data);
    }
};
