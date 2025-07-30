const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "openvpn-client",
        .root_module = b.createModule(.{
            .optimize = b.standardOptimizeOption(.{}),
            .root_source_file = b.path("client.zig"),
            .target = b.standardTargetOptions(.{}),
        }),
    });

    // Add C standard library
    exe.linkLibC();

    // Add GIO dependencies using pkg-config
    exe.linkSystemLibrary("gio-2.0");
    // exe.linkSystemLibrary("gobject-2.0");
    // exe.linkSystemLibrary("glib-2.0");

    // Add pthread for threading support
    // exe.linkSystemLibrary("pthread");

    b.installArtifact(exe);

    // Create a run step
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the openvpn tool");
    run_step.dependOn(&run_cmd.step);
}
