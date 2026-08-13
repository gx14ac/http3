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

    // Stream tests
    const stream_test_mod = b.createModule(.{
        .root_source_file = b.path("src/h2/stream.zig"),
        .target = target,
        .optimize = optimize,
    });
    const stream_tests = b.addTest(.{
        .root_module = stream_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(stream_tests).step);

    // Connection tests
    const conn_test_mod = b.createModule(.{
        .root_source_file = b.path("src/h2/connection.zig"),
        .target = target,
        .optimize = optimize,
    });
    const conn_tests = b.addTest(.{
        .root_module = conn_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(conn_tests).step);

    // Client tests
    const client_test_mod = b.createModule(.{
        .root_source_file = b.path("src/h2/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    const client_tests = b.addTest(.{
        .root_module = client_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(client_tests).step);

    // gRPC message tests
    const grpc_msg_test_mod = b.createModule(.{
        .root_source_file = b.path("src/grpc/message.zig"),
        .target = target,
        .optimize = optimize,
    });
    const grpc_msg_tests = b.addTest(.{
        .root_module = grpc_msg_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(grpc_msg_tests).step);

    // Fuzz tests
    // - Seed-corpus validation: zig build fuzz
    // - Continuous fuzzing (Linux only): zig build fuzz --fuzz
    //   (macOS unsupported in Zig 0.15 — std.debug.Info is ELF-only)
    const fuzz_test_mod = b.createModule(.{
        .root_source_file = b.path("src/h2/fuzz_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_test_mod,
    });
    const run_fuzz = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run fuzz tests");
    fuzz_step.dependOn(&run_fuzz.step);

    // QUIC tests
    const quic_test_mod = b.createModule(.{
        .root_source_file = b.path("src/quic/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const quic_tests = b.addTest(.{
        .root_module = quic_test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(quic_tests).step);

    // Integration tests (requires external gRPC server on localhost:50051)
    const integration_test_mod = b.createModule(.{
        .root_source_file = b.path("test/integration/smoke_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_test_mod.addImport("http3", lib_mod);
    const integration_tests = b.addTest(.{
        .root_module = integration_test_mod,
    });
    const run_integration = b.addRunArtifact(integration_tests);
    const integration_step = b.step("integration-test", "Run integration tests (requires gRPC server on :50051)");
    integration_step.dependOn(&run_integration.step);

}
