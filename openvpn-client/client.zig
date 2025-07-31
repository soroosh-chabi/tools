const std = @import("std");
const crypto = std.crypto;

const gio = @cImport({
    @cInclude("gio/gio.h");
});

fn askSecret(allocator: std.mem.Allocator, prompt: []const u8, max_length: usize) ![]const u8 {
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
        max_length,
    );

    return secret;
}

const Credentials = struct {
    pub const max_length = 1024;

    allocator: std.mem.Allocator,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    totp_secret: ?[]const u8 = null,
    config_name: ?[]const u8 = null,

    pub fn deinit(self: Credentials) void {
        if (self.username) |username| self.allocator.free(username);
        if (self.password) |password| self.allocator.free(password);
        if (self.totp_secret) |totp_secret| self.allocator.free(totp_secret);
        if (self.config_name) |config_name| self.allocator.free(config_name);
    }

    fn serialize(self: Credentials, writer: anytype) !void {
        try writer.print("username={s}\npassword={s}\ntotp_secret={s}\nconfig_name={s}\n", .{ self.username orelse "", self.password orelse "", self.totp_secret orelse "", self.config_name orelse "" });
    }

    fn deserialize(self: *Credentials, reader: anytype) !void {
        self.deinit();

        // Read entire content and parse key=value pairs without loops
        const content = try reader.readAllAlloc(self.allocator, (max_length + 20) * 4);
        defer self.allocator.free(content);

        // Parse each field directly using string operations
        const username_start = std.mem.indexOf(u8, content, "username=") orelse return error.MissingUsername;
        const username_line_start = username_start + 9; // "username=".len
        const username_end = std.mem.indexOf(u8, content[username_line_start..], "\n") orelse return error.MissingUsername;
        self.username = try self.allocator.dupe(u8, content[username_line_start .. username_line_start + username_end]);

        const password_start = std.mem.indexOf(u8, content, "password=") orelse return error.MissingPassword;
        const password_line_start = password_start + 9; // "password=".len
        const password_end = std.mem.indexOf(u8, content[password_line_start..], "\n") orelse return error.MissingPassword;
        self.password = try self.allocator.dupe(u8, content[password_line_start .. password_line_start + password_end]);

        const totp_start = std.mem.indexOf(u8, content, "totp_secret=") orelse return error.MissingTotpSecret;
        const totp_line_start = totp_start + 12; // "totp_secret=".len
        const totp_end = std.mem.indexOf(u8, content[totp_line_start..], "\n") orelse return error.MissingTotpSecret;
        self.totp_secret = try self.allocator.dupe(u8, content[totp_line_start .. totp_line_start + totp_end]);

        const config_start = std.mem.indexOf(u8, content, "config_name=") orelse return error.MissingConfigName;
        const config_line_start = config_start + 12; // "config_name=".len
        const config_end = std.mem.indexOf(u8, content[config_line_start..], "\n") orelse return error.MissingConfigName;
        self.config_name = try self.allocator.dupe(u8, content[config_line_start .. config_line_start + config_end]);
    }

    fn ask(self: *Credentials) !void {
        self.deinit();

        const stdin = std.io.getStdIn();
        const stdout = std.io.getStdOut();

        // Get username
        try stdout.writeAll("Enter username: ");
        self.username = try stdin.reader().readUntilDelimiterAlloc(
            self.allocator,
            '\n',
            Credentials.max_length,
        );

        // Get password (without echo)
        self.password = try askSecret(self.allocator, "Enter password: ", Credentials.max_length);

        // Get TOTP secret (without echo)
        self.totp_secret = try askSecret(self.allocator, "Enter TOTP secret: ", Credentials.max_length);

        // Get config name
        try stdout.writeAll("Enter config name: ");
        self.config_name = try stdin.reader().readUntilDelimiterAlloc(
            self.allocator,
            '\n',
            Credentials.max_length,
        );
    }
};

const EncryptedCredentialsFile = struct {
    file_path: []const u8,
    credentials: Credentials,
    allocator: std.mem.Allocator,

    const AesGcm = crypto.aead.aes_gcm.Aes256Gcm;
    const salt_length = 16;

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !EncryptedCredentialsFile {
        return .{
            .file_path = try allocator.dupe(u8, file_path),
            .credentials = Credentials{ .allocator = allocator },
            .allocator = allocator,
        };
    }

    fn deinit(self: *EncryptedCredentialsFile) void {
        self.credentials.deinit();
        self.allocator.free(self.file_path);
    }

    fn deriveKey(password: []const u8, salt: []const u8) ![AesGcm.key_length]u8 {
        var key: [AesGcm.key_length]u8 = undefined;
        const iterations = 100000;

        try crypto.pwhash.pbkdf2(&key, password, salt, iterations, crypto.auth.hmac.sha2.HmacSha256);
        return key;
    }

    fn encryptData(self: EncryptedCredentialsFile, data: []const u8, password: []const u8) ![]u8 {
        // Generate salt and nonce
        var salt: [salt_length]u8 = undefined;
        var nonce: [AesGcm.nonce_length]u8 = undefined;
        crypto.random.bytes(&salt);
        crypto.random.bytes(&nonce);

        // Derive key from password
        const key = try deriveKey(password, &salt);

        // Encrypt data
        const encrypted_len = salt_length + AesGcm.nonce_length + data.len + AesGcm.tag_length;
        var encrypted = try self.allocator.alloc(u8, encrypted_len);

        // Copy salt and nonce
        @memcpy(encrypted[0..salt_length], &salt);
        @memcpy(encrypted[salt_length .. salt_length + AesGcm.nonce_length], &nonce);

        // Encrypt
        var tag: [AesGcm.tag_length]u8 = undefined;
        AesGcm.encrypt(
            encrypted[salt_length + AesGcm.nonce_length .. salt_length + AesGcm.nonce_length + data.len],
            &tag,
            data,
            "",
            nonce,
            key,
        );
        @memcpy(encrypted[salt_length + AesGcm.nonce_length + data.len ..], &tag);

        // Return a copy of the encrypted data
        return encrypted;
    }

    fn decryptData(self: EncryptedCredentialsFile, encrypted_data: []const u8, password: []const u8) ![]u8 {
        if (encrypted_data.len < salt_length + AesGcm.nonce_length + AesGcm.tag_length) {
            return error.InvalidData;
        }

        // Extract salt and nonce
        const salt = encrypted_data[0..salt_length];
        var nonce: [AesGcm.nonce_length]u8 = undefined;
        @memcpy(&nonce, encrypted_data[salt_length .. salt_length + AesGcm.nonce_length]);
        const encrypted = encrypted_data[salt_length + AesGcm.nonce_length .. encrypted_data.len - AesGcm.tag_length];
        var tag: [AesGcm.tag_length]u8 = undefined;
        @memcpy(&tag, encrypted_data[encrypted_data.len - AesGcm.tag_length ..]);

        // Derive key from password
        const key = try deriveKey(password, salt);

        // Decrypt directly into result
        const decrypted = try self.allocator.alloc(u8, encrypted.len);
        errdefer self.allocator.free(decrypted);
        try AesGcm.decrypt(decrypted, encrypted, tag, "", nonce, key);

        return decrypted;
    }

    fn save(self: *EncryptedCredentialsFile) !void {
        // Serialize credentials to string
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();
        try self.credentials.serialize(writer);

        // Ask for master password
        const master_password = try askSecret(self.allocator, "Enter master password to encrypt credentials: ", Credentials.max_length);
        defer self.allocator.free(master_password);

        // Encrypt the data
        const encrypted = try self.encryptData(buffer.items, master_password);
        defer self.allocator.free(encrypted);

        // Save encrypted data to file
        const file = try std.fs.createFileAbsolute(self.file_path, .{});
        defer file.close();

        try file.writeAll(encrypted);
    }

    pub fn load(self: *EncryptedCredentialsFile) !void {
        // Read encrypted data from file
        const file = try std.fs.openFileAbsolute(self.file_path, .{});
        defer file.close();

        const encrypted_data = try file.reader().readAllAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(encrypted_data);

        // Ask for master password
        const master_password = try askSecret(self.allocator, "Enter master password to decrypt credentials: ", Credentials.max_length);
        defer self.allocator.free(master_password);

        // Decrypt the data
        const decrypted = try self.decryptData(encrypted_data, master_password);
        defer self.allocator.free(decrypted);

        // Parse the decrypted data
        var stream = std.io.fixedBufferStream(decrypted);
        const reader = stream.reader();
        try self.credentials.deserialize(reader);
    }

    pub fn exists(self: *EncryptedCredentialsFile) bool {
        if (std.fs.cwd().access(self.file_path, .{})) {
            return true;
        } else |_| {
            return false;
        }
    }

    pub fn askAndSave(self: *EncryptedCredentialsFile) !void {
        try self.credentials.ask();
        try self.save();
    }
};

fn getConfigPath(allocator: std.mem.Allocator, config_name: []const u8) ![]const u8 {
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

    // Convert []const u8 to null-terminated string for C function
    const c_config_name = try allocator.dupeZ(u8, config_name);
    defer allocator.free(c_config_name);

    const result = gio.g_dbus_proxy_call_sync(
        proxy,
        "LookupConfigName",
        gio.g_variant_new("(s)", c_config_name.ptr),
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
    defer gio.g_free(@ptrCast(config_path));
    const path_slice = std.mem.span(config_path);
    return try allocator.dupe(u8, path_slice);
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

    var cred_file = try EncryptedCredentialsFile.init(allocator, cred_path);
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

    const config_path = try getConfigPath(allocator, cred_file.credentials.config_name orelse return error.MissingConfigName);
    defer allocator.free(config_path);
    std.debug.print("Config path: {s}\n", .{config_path});
}
