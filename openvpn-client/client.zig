const std = @import("std");

const gio = @import("clibs.zig").gio;

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

pub const ConfigManager = struct {
    proxy: *gio.GDBusProxy,

    pub fn init() !ConfigManager {
        return .{
            .proxy = blk: {
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
        };
    }

    pub fn deinit(self: ConfigManager) void {
        gio.g_object_unref(self.proxy);
    }

    pub fn LookupConfigName(self: ConfigManager, allocator: std.mem.Allocator, config_name: []const u8) !?[]u8 {
        const config_name_c = try allocator.dupeZ(u8, config_name);
        defer allocator.free(config_name_c);
        const result = try callWithRetry(self.proxy, "LookupConfigName", gio.g_variant_new("(s)", config_name_c.ptr));
        defer gio.g_variant_unref(result);
        const expected_type = gio.g_variant_type_new("(ao)");
        defer gio.g_variant_type_free(expected_type);
        if (gio.g_variant_is_of_type(result, expected_type) == gio.FALSE) {
            return error.GError;
        }
        const config_paths = gio.g_variant_get_child_value(result, 0);
        defer gio.g_variant_unref(config_paths);
        if (gio.g_variant_n_children(config_paths) == 0) {
            return null;
        }
        var config_path: [*:0]u8 = undefined;
        gio.g_variant_get_child(config_paths, 0, "o", &config_path);
        defer gio.g_free(config_path);
        return try allocator.dupe(u8, std.mem.span(config_path));
    }
};

pub const SessionManager = struct {
    proxy: *gio.GDBusProxy,

    pub fn init() !SessionManager {
        return .{
            .proxy = blk: {
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
        };
    }

    pub fn deinit(self: SessionManager) void {
        gio.g_object_unref(self.proxy);
    }

    pub fn createNewTunnel(self: SessionManager, allocator: std.mem.Allocator, config_path: []const u8) !Session {
        const config_path_c = try allocator.dupeZ(u8, config_path);
        defer allocator.free(config_path_c);
        const result = try callWithRetry(
            self.proxy,
            "NewTunnel",
            gio.g_variant_new("(o)", config_path_c.ptr),
        );
        defer gio.g_variant_unref(result);
        const expected_type = gio.g_variant_type_new("(o)");
        defer gio.g_variant_type_free(expected_type);
        if (gio.g_variant_is_of_type(result, expected_type) == gio.FALSE) {
            return error.GError;
        }
        var session_path: [*:0]u8 = undefined;
        gio.g_variant_get_child(result, 0, "o", &session_path);
        defer gio.g_free(session_path);
        return try Session.init(allocator, session_path);
    }
};

fn PreArgsClosure(comptime T: type, comptime post_args_len: usize) type {
    var info = @typeInfo(std.meta.ArgsTuple(T));
    var post_args_fields: [post_args_len]std.builtin.Type.StructField = undefined;
    for (info.@"struct".fields[info.@"struct".fields.len - post_args_len ..], 0..) |field, i| {
        post_args_fields[i] = field;
        var num_buf: [128]u8 = undefined;
        post_args_fields[i].name = std.fmt.bufPrintZ(&num_buf, "{d}", .{i}) catch unreachable;
    }
    info.@"struct".fields = info.@"struct".fields[0 .. info.@"struct".fields.len - post_args_len];
    const PreArgs = @Type(info);
    info.@"struct".fields = &post_args_fields;
    const PostArgs = @Type(info);
    const PostArgsExtractor = fn (*gio.GDBusProxy, [*:0]u8, [*:0]u8, *gio.GVariant) PostArgs;
    const PostArgsDeinit = fn (PostArgs) void;

    return struct {
        callback: *const T,
        pre_args: PreArgs,
        post_args_extractor: *const PostArgsExtractor,
        post_args_deinit: *const PostArgsDeinit,
        allocator: std.mem.Allocator,

        fn init(
            allocator: std.mem.Allocator,
            callback: *const T,
            user_data: PreArgs,
            post_args_extractor: *const PostArgsExtractor,
            post_args_deinit: *const PostArgsDeinit,
        ) !*@This() {
            const self = try allocator.create(@This());
            self.callback = callback;
            self.pre_args = user_data;
            self.allocator = allocator;
            self.post_args_extractor = post_args_extractor;
            self.post_args_deinit = post_args_deinit;
            return self;
        }

        fn destroy_data(data: ?*anyopaque, _: ?*gio.GClosure) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(data));
            self.allocator.destroy(self);
        }

        fn c_handler(proxy: *gio.GDBusProxy, sender_name: [*:0]u8, signal_name: [*:0]u8, parameters: *gio.GVariant, user_data: ?*anyopaque) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(user_data));
            const post_args = self.post_args_extractor(proxy, sender_name, signal_name, parameters);
            defer self.post_args_deinit(post_args);
            @call(.auto, self.callback, self.pre_args ++ post_args);
        }
    };
}

pub const Session = struct {
    proxy: *gio.GDBusProxy,
    log_proxy: ?*gio.GDBusProxy = null,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, session_path: [*:0]const u8) !Session {
        var g_error: ?*gio.GError = null;
        const proxy = gio.g_dbus_proxy_new_for_bus_sync(
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
        return .{ .proxy = proxy, .allocator = allocator };
    }

    pub fn deinit(self: Session) void {
        gio.g_object_unref(self.proxy);
        if (self.log_proxy) |proxy| {
            gio.g_object_unref(proxy);
        }
    }

    pub fn connect(self: Session) !void {
        gio.g_variant_unref(try callWithRetry(self.proxy, "Connect", null));
    }

    pub fn disconnect(self: Session) !void {
        gio.g_variant_unref(try callWithRetry(self.proxy, "Disconnect", null));
    }

    pub fn ready(self: Session) !void {
        gio.g_variant_unref(try callWithRetry(self.proxy, "Ready", null));
    }

    pub fn setInputs(
        self: Session,
        credentials: struct { username: []const u8, password: []const u8, totp: []const u8 },
    ) !void {
        const username_c = try self.allocator.dupeZ(u8, credentials.username);
        defer self.allocator.free(username_c);
        const password_c = try self.allocator.dupeZ(u8, credentials.password);
        defer self.allocator.free(password_c);
        const totp_c = try self.allocator.dupeZ(u8, credentials.totp);
        defer self.allocator.free(totp_c);
        gio.g_variant_unref(try callWithRetry(
            self.proxy,
            "UserInputProvide",
            gio.g_variant_new("(uuus)", @as(u32, 1), @as(u32, 1), @as(u32, 0), username_c.ptr),
        ));
        gio.g_variant_unref(try callWithRetry(
            self.proxy,
            "UserInputProvide",
            gio.g_variant_new("(uuus)", @as(u32, 1), @as(u32, 1), @as(u32, 1), password_c.ptr),
        ));
        gio.g_variant_unref(try callWithRetry(
            self.proxy,
            "UserInputProvide",
            gio.g_variant_new("(uuus)", @as(u32, 1), @as(u32, 4), @as(u32, 0), totp_c.ptr),
        ));
    }

    pub fn listenToStatusChange(
        self: *Session,
        callback: anytype,
        pre_args: anytype,
    ) !void {
        const StatusChangeClosure = PreArgsClosure(@TypeOf(callback), 3);
        var g_error: ?*gio.GError = null;
        const result = gio.g_dbus_proxy_call_sync(
            self.proxy,
            "LogForward",
            gio.g_variant_new("(b)", gio.TRUE),
            gio.G_DBUS_CALL_FLAGS_NONE,
            -1,
            null,
            &g_error,
        );
        try reportGError(g_error);
        gio.g_variant_unref(result);
        if (self.log_proxy == null) {
            self.log_proxy = gio.g_dbus_proxy_new_for_bus_sync(
                gio.G_BUS_TYPE_SYSTEM,
                gio.G_DBUS_PROXY_FLAGS_NONE,
                null,
                "net.openvpn.v3.log",
                gio.g_dbus_proxy_get_object_path(self.proxy),
                "net.openvpn.v3.backends",
                null,
                &g_error,
            );
            try reportGError(g_error);
        }
        _ = gio.g_signal_connect_data(
            self.log_proxy.?,
            "g-signal::StatusChange",
            gio.G_CALLBACK(StatusChangeClosure.c_handler),
            try StatusChangeClosure.init(
                self.allocator,
                callback,
                pre_args,
                statusChangePostArgsExtractor,
                statusChangePostArgsDeinit,
            ),
            StatusChangeClosure.destroy_data,
            gio.G_CONNECT_DEFAULT,
        );
    }

    fn statusChangePostArgsExtractor(_: *gio.GDBusProxy, _: [*:0]u8, _: [*:0]u8, parameters: *gio.GVariant) struct { u32, u32, []const u8 } {
        var major: u32 = undefined;
        var minor: u32 = undefined;
        var message: [*:0]u8 = undefined;
        gio.g_variant_get(parameters, "(uus)", &major, &minor, &message);
        return .{ major, minor, std.mem.span(message) };
    }

    fn statusChangePostArgsDeinit(args: struct { u32, u32, []const u8 }) void {
        gio.g_free(@constCast(args[2].ptr));
    }

    pub fn listenToAttentionRequired(self: *Session, callback: anytype, pre_args: anytype) !void {
        const AttentionRequiredClosure = PreArgsClosure(@TypeOf(callback), 3);
        _ = gio.g_signal_connect_data(
            self.proxy,
            "g-signal::AttentionRequired",
            gio.G_CALLBACK(AttentionRequiredClosure.c_handler),
            try AttentionRequiredClosure.init(
                self.allocator,
                callback,
                pre_args,
                attentionRequiredPostArgsExtractor,
                attentionRequiredPostArgsDeinit,
            ),
            AttentionRequiredClosure.destroy_data,
            gio.G_CONNECT_DEFAULT,
        );
    }

    fn attentionRequiredPostArgsExtractor(_: *gio.GDBusProxy, _: [*:0]u8, _: [*:0]u8, parameters: *gio.GVariant) struct { u32, u32, []const u8 } {
        var @"type": u32 = undefined;
        var group: u32 = undefined;
        var message: [*:0]u8 = undefined;
        gio.g_variant_get(parameters, "(uus)", &@"type", &group, &message);
        return .{ @"type", group, std.mem.span(message) };
    }

    fn attentionRequiredPostArgsDeinit(args: struct { u32, u32, []const u8 }) void {
        gio.g_free(@constCast(args[2].ptr));
    }
};
