const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "openvpn-client",
        .root_source_file = .{ .path = "client.zig" },
    });

    // Add C standard library
    exe.linkLibC();

    // Add GIO dependencies using pkg-config
    exe.addLibraryPath(.{ .cwd_relative = "system" });
    exe.linkSystemLibrary("gio-2.0");
    exe.linkSystemLibrary("gobject-2.0");
    exe.linkSystemLibrary("glib-2.0");

    // Add include directories
    exe.addIncludeDir(.{ .path = "/usr/include/glib-2.0" });
    exe.addIncludeDir(.{ .path = "/usr/lib/x86_64-linux-gnu/glib-2.0/include" });
    exe.addIncludeDir(.{ .path = "/usr/include/libmount" });
    exe.addIncludeDir(.{ .path = "/usr/include/blkid" });

    // Add pthread for threading support
    exe.linkSystemLibrary("pthread");

    b.installArtifact(exe);

    // Create a run step
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the openvpn tool");
    run_step.dependOn(&run_cmd.step);
}
