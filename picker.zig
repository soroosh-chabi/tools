const std = @import("std");

pub fn main() !void {
    // Initialize allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // Get command line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Skip the program name
    _ = args.skip();

    // Get directory path from command line argument
    const dir_path = args.next() orelse {
        try stdout.writeAll("Usage: picker <directory_path>\n");
        return error.MissingArgument;
    };

    // Open directory
    var dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });
    defer dir.close();

    // Count files and store names
    var file_list = std.ArrayList([]const u8).init(allocator);
    defer file_list.deinit();

    var dir_iterator = dir.iterate();
    while (try dir_iterator.next()) |entry| {
        try file_list.append(try allocator.dupe(u8, entry.name));
    }

    // Check if any files were found
    if (file_list.items.len == 0) {
        try stdout.writeAll("No files found in directory.\n");
        return;
    }

    // Generate random number
    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        while (std.os.linux.getrandom(std.mem.asBytes(&seed), 8, 0) != 8) {}
        break :blk seed;
    });
    const random = prng.random();

    // Pick random file
    const random_index = random.intRangeAtMost(usize, 0, file_list.items.len - 1);
    const chosen_file = file_list.items[random_index];

    // Print the chosen file
    try stdout.print("{s}\n", .{chosen_file});

    // Clean up allocated memory
    for (file_list.items) |name| {
        allocator.free(name);
    }
}
