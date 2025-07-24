const std = @import("std");
const crypto = std.crypto;

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
    username: []const u8 = undefined,
    password: []const u8 = undefined,
    totp_secret: []const u8 = undefined,
    config_name: []const u8 = undefined,

    pub fn deinit(self: Credentials) void {
        self.allocator.free(self.username);
        self.allocator.free(self.password);
        self.allocator.free(self.totp_secret);
        self.allocator.free(self.config_name);
    }

    fn serialize(self: Credentials, writer: anytype) !void {
        try writer.print("username={s}\npassword={s}\ntotp_secret={s}\nconfig_name={s}\n", .{ self.username, self.password, self.totp_secret, self.config_name });
    }

    fn deserialize(self: *Credentials, reader: anytype) !void {
        // Read entire content and parse key=value pairs without loops
        const content = try reader.readAllAlloc(self.allocator, (max_length + 20) * 4);
        defer self.allocator.free(content);

        // Parse each field directly using string operations
        if (std.mem.indexOf(u8, content, "username=")) |username_start| {
            const username_line_start = username_start + 9; // "username=".len
            if (std.mem.indexOf(u8, content[username_line_start..], "\n")) |username_end| {
                self.username = try self.allocator.dupe(u8, content[username_line_start .. username_line_start + username_end]);
            }
        }

        if (std.mem.indexOf(u8, content, "password=")) |password_start| {
            const password_line_start = password_start + 9; // "password=".len
            if (std.mem.indexOf(u8, content[password_line_start..], "\n")) |password_end| {
                self.password = try self.allocator.dupe(u8, content[password_line_start .. password_line_start + password_end]);
            }
        }

        if (std.mem.indexOf(u8, content, "totp_secret=")) |totp_start| {
            const totp_line_start = totp_start + 12; // "totp_secret=".len
            if (std.mem.indexOf(u8, content[totp_line_start..], "\n")) |totp_end| {
                self.totp_secret = try self.allocator.dupe(u8, content[totp_line_start .. totp_line_start + totp_end]);
            }
        }

        if (std.mem.indexOf(u8, content, "config_name=")) |config_start| {
            const config_line_start = config_start + 12; // "config_name=".len
            if (std.mem.indexOf(u8, content[config_line_start..], "\n")) |config_end| {
                self.config_name = try self.allocator.dupe(u8, content[config_line_start .. config_line_start + config_end]);
            }
        }
    }

    fn ask(self: *Credentials) !void {
        const stdin = std.io.getStdIn();
        const stdout = std.io.getStdOut();

        // Get username
        try stdout.writeAll("Enter username: ");
        const username = try stdin.reader().readUntilDelimiterAlloc(
            self.allocator,
            '\n',
            Credentials.max_length,
        );

        // Get password (without echo)
        const password = try askSecret(self.allocator, "Enter password: ", Credentials.max_length);

        // Get TOTP secret (without echo)
        const totp_secret = try askSecret(self.allocator, "Enter TOTP secret: ", Credentials.max_length);

        // Get config name
        try stdout.writeAll("Enter config name: ");
        const config_name = try stdin.reader().readUntilDelimiterAlloc(
            self.allocator,
            '\n',
            Credentials.max_length,
        );

        self.username = username;
        self.password = password;
        self.totp_secret = totp_secret;
        self.config_name = config_name;
    }
};

const EncryptedCredentialsFile = struct {
    file_path: []const u8,
    credentials: Credentials,
    allocator: std.mem.Allocator,

    const AesGcm = crypto.aead.aes_gcm.Aes256Gcm;
    const salt_length = 16;

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !EncryptedCredentialsFile {
        return EncryptedCredentialsFile{
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
        AesGcm.encrypt(encrypted[salt_length + AesGcm.nonce_length ..], &tag, data, "", nonce, key);
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
        const file = try std.fs.cwd().createFile(self.file_path, .{});
        defer file.close();

        try file.writeAll(encrypted);
    }

    pub fn load(self: *EncryptedCredentialsFile) !void {
        // Read encrypted data from file
        const file = try std.fs.cwd().openFile(self.file_path, .{});
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

// Example usage function
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cred_file = try EncryptedCredentialsFile.init(allocator, "credentials.enc");
    defer cred_file.deinit();

    if (cred_file.exists()) {
        // Load existing credentials
        try cred_file.load();
        std.debug.print("Loaded encrypted credentials from file\n", .{});
    } else {
        // Ask for new credentials and save them
        try cred_file.askAndSave();
        std.debug.print("Saved encrypted credentials to file\n", .{});
    }

    std.debug.print("Username: {s}\n", .{cred_file.credentials.username});
    std.debug.print("Password: {s}\n", .{cred_file.credentials.password});
    std.debug.print("TOTP Secret: {s}\n", .{cred_file.credentials.totp_secret});
    std.debug.print("Config Name: {s}\n", .{cred_file.credentials.config_name});
}
