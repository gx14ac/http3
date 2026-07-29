const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "http3",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // Tests
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Frame codec tests
    const frame_test_mod = b.createModule(.{
        .root_source_file = b.path("src/h2/frame.zig"),
        .target = target,
        .optimize = optimize,
    });
    const frame_tests = b.addTest(.{
        .root_module = frame_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(frame_tests).step);

    // HPACK tests
    const hpack_test_mod = b.createModule(.{
        .root_source_file = b.path("src/h2/hpack.zig"),
        .target = target,
        .optimize = optimize,
    });
    const hpack_tests = b.addTest(.{
        .root_module = hpack_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(hpack_tests).step);
}
