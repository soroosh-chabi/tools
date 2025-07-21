const std = @import("std");

/// Adds subtitle stream to video file using ffmpeg
///
/// Args:
///   allocator: Memory allocator
///   video_file: Path to input video file
///   subtitle_file: Path to input subtitle file
///   output_file: Path to output file with embedded subtitles
///
/// Returns:
///   void on success, error on failure
pub fn addSubtitlesToVideo(
    allocator: std.mem.Allocator,
    video_file: []const u8,
    subtitle_file: []const u8,
    output_file: []const u8,
) !void {
    // Build ffmpeg command
    const argv = [_][]const u8{
        "ffmpeg",
        "-i",
        video_file,
        "-i",
        subtitle_file,
        "-c:v",
        "copy",
        "-c:a",
        "copy",
        "-c:s",
        "mov_text",
        output_file,
    };

    // Execute ffmpeg command
    const result = std.process.Child.run(.{
        .argv = &argv,
        .allocator = allocator,
    }) catch |err| {
        return err;
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    // Check if command was successful
    if (result.term.Exited != 0) {
        return error.FfmpegFailed;
    }
}

/// Constructs the subtitle file path by finding the first subtitle file
///
/// Args:
///   allocator: Memory allocator
///   video_dir: Directory containing the video files
///   filename_no_ext: Filename without the .mp4 extension
///
/// Returns:
///   Allocated string containing the subtitle file path
pub fn constructSubtitlePath(
    allocator: std.mem.Allocator,
    video_dir: []const u8,
    filename_no_ext: []const u8,
) ![]u8 {
    // Construct the subs directory path
    const subs_dir_path = try std.fmt.allocPrint(allocator, "{s}/Subs/{s}", .{ video_dir, filename_no_ext });
    defer allocator.free(subs_dir_path);

    // Open the subs directory
    var subs_dir = std.fs.openDirAbsolute(subs_dir_path, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) {
            return error.NoSubtitleFileFound;
        }
        return err;
    };
    defer subs_dir.close();

    // Find the first subtitle file
    var iter = subs_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".srt")) {
            return std.fmt.allocPrint(allocator, "{s}/{s}", .{ subs_dir_path, entry.name });
        }
    }

    return error.NoSubtitleFileFound;
}

/// Iterator that yields MP4 file paths from a directory
pub const Mp4FileIterator = struct {
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    iter: std.fs.Dir.Iterator,
    dir_path: []const u8,

    /// Initialize the iterator
    pub fn init(allocator: std.mem.Allocator, dir_path: []const u8) !Mp4FileIterator {
        var dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });
        const iter = dir.iterate();

        return Mp4FileIterator{
            .allocator = allocator,
            .dir = dir,
            .iter = iter,
            .dir_path = dir_path,
        };
    }

    /// Deinitialize the iterator
    pub fn deinit(self: *Mp4FileIterator) void {
        self.dir.close();
    }

    /// Get the next MP4 file path
    pub fn next(self: *Mp4FileIterator) !?[]const u8 {
        while (try self.iter.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".mp4")) {
                const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dir_path, entry.name });
                return full_path;
            }
        }
        return null;
    }
};

/// Extracts the season number from a video directory name
///
/// Args:
///   dir_name: The directory name (e.g., "Rick and Morty S06")
///
/// Returns:
///   The index where the season number starts (e.g., "S06") or null if not found
pub fn extractSeasonNumber(dir_name: []const u8) ?usize {
    // Look for pattern like "S06" in the directory name
    for (0..dir_name.len - 2) |i| {
        if (dir_name[i] == 'S' and std.ascii.isDigit(dir_name[i + 1]) and std.ascii.isDigit(dir_name[i + 2])) {
            return i;
        }
    }
    return null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // Get command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Check if correct number of arguments provided
    if (args.len != 2) {
        try stdout.print("Usage: {s} <video_dir>\n", .{args[0]});
        try stdout.print("  video_dir: Directory containing video files and Subs subdirectory\n", .{});
        std.process.exit(1);
    }

    const video_dir = args[1];

    // Extract season number
    const video_dir_basename = std.fs.path.basename(video_dir);
    const season_index = extractSeasonNumber(video_dir_basename) orelse {
        try stdout.print("No season number found in directory name: {s}\n", .{video_dir_basename});
        std.process.exit(1);
    };
    const season_number = video_dir_basename[season_index .. season_index + 3];

    // Get current working directory once
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);

    // Resolve relative paths to absolute paths
    const resolved_video_dir = if (std.fs.path.isAbsolute(video_dir))
        video_dir
    else
        try std.fs.path.resolve(allocator, &[_][]const u8{ cwd, video_dir });
    defer if (!std.fs.path.isAbsolute(video_dir)) allocator.free(resolved_video_dir);

    // Use season number as output directory in the same directory as video_dir
    const video_dir_parent = std.fs.path.dirname(resolved_video_dir).?;
    const output_dir = try std.fs.path.resolve(allocator, &[_][]const u8{ video_dir_parent, season_number });
    defer allocator.free(output_dir);

    // Create output directory
    try std.fs.makeDirAbsolute(output_dir);

    var mp4_iter = try Mp4FileIterator.init(allocator, resolved_video_dir);
    defer mp4_iter.deinit();

    while (try mp4_iter.next()) |video_file| {
        defer allocator.free(video_file);

        // Extract filename without extension
        const basename = std.fs.path.basename(video_file);
        const filename_no_ext = basename[0 .. basename.len - 4]; // remove .mp4

        // Construct output file path following the pattern
        const output_file = try std.fmt.allocPrint(allocator, "{s}/{s}.mp4", .{ output_dir, filename_no_ext });
        defer allocator.free(output_file);

        // Construct subtitle path following the pattern
        const subtitle_file = constructSubtitlePath(allocator, resolved_video_dir, filename_no_ext) catch |err| {
            if (err == error.NoSubtitleFileFound) {
                // Copy the video file instead of adding subtitles
                try stdout.print("No subtitle file found for {s}.\n", .{video_file});
                try std.fs.copyFileAbsolute(video_file, output_file, .{});
                continue;
            }
            return err;
        };
        defer allocator.free(subtitle_file);

        try addSubtitlesToVideo(allocator, video_file, subtitle_file, output_file);
    }
}
