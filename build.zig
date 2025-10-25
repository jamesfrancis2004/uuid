const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const uuid_module = b.addModule("uuid", .{
        .root_source_file = b.path("src/uuid.zig"),
        .target = target,
        .optimize = optimize,
    });

    const main_tests = b.addTest(.{
        .root_module = uuid_module,
    });
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&b.addRunArtifact(main_tests).step);
    const run_bench = addBenchmark(b, uuid_module, "bench", "bench/main.zig", target);
    if (b.args) |args| {
        run_bench.addArgs(args);
    }
    const bench = b.step("bench", "Run the v7 benchmark");
    bench.dependOn(&run_bench.step);
}

fn addBenchmark(b: *std.Build, uuid_module: *std.Build.Module, exeName: []const u8, sourceFile: []const u8, target: std.Build.ResolvedTarget) *std.Build.Step.Run {
    const exe_mod = b.createModule(.{
        .root_source_file = b.path(sourceFile),
        .target = target,
        .optimize = .ReleaseFast,
    });

    const exe = b.addExecutable(.{
        .name = exeName,
        .root_module = exe_mod,
    });

    exe.root_module.addImport("uuid", uuid_module);

    b.installArtifact(exe);

    return b.addRunArtifact(exe);
}
