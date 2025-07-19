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

/// Example usage function
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Check if correct number of arguments provided
    if (args.len != 3) {
        std.debug.print("Usage: {s} <video_dir> <output_dir>\n", .{args[0]});
        std.debug.print("  video_dir: Directory containing video files and Subs subdirectory\n", .{});
        std.debug.print("  output_dir: Directory where output files will be saved\n", .{});
        std.process.exit(1);
    }

    const video_dir = args[1];
    const output_dir = args[2];

    // Get current working directory once
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);

    // Resolve relative paths to absolute paths
    const resolved_video_dir = if (std.fs.path.isAbsolute(video_dir))
        video_dir
    else
        try std.fs.path.resolve(allocator, &[_][]const u8{ cwd, video_dir });
    defer if (!std.fs.path.isAbsolute(video_dir)) allocator.free(resolved_video_dir);

    const resolved_output_dir = if (std.fs.path.isAbsolute(output_dir))
        output_dir
    else
        try std.fs.path.resolve(allocator, &[_][]const u8{ cwd, output_dir });
    defer if (!std.fs.path.isAbsolute(output_dir)) allocator.free(resolved_output_dir);

    var mp4_iter = try Mp4FileIterator.init(allocator, resolved_video_dir);
    defer mp4_iter.deinit();

    while (try mp4_iter.next()) |video_file| {
        defer allocator.free(video_file);

        // Extract filename without extension
        const basename = std.fs.path.basename(video_file);
        const filename_no_ext = basename[0 .. basename.len - 4]; // remove .mp4

        // Construct output file path following the pattern
        const output_file = try std.fmt.allocPrint(allocator, "{s}/{s}.mp4", .{ resolved_output_dir, filename_no_ext });
        defer allocator.free(output_file);

        // Construct subtitle path following the pattern
        const subtitle_file = constructSubtitlePath(allocator, resolved_video_dir, filename_no_ext) catch |err| {
            if (err == error.NoSubtitleFileFound) {
                // Copy the video file instead of adding subtitles
                try std.fs.copyFileAbsolute(video_file, output_file, .{});
                continue;
            }
            return err;
        };
        defer allocator.free(subtitle_file);

        try addSubtitlesToVideo(allocator, video_file, subtitle_file, output_file);
    }
}
