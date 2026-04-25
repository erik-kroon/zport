const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version = b.option([]const u8, "version", "Version reported by zport --version") orelse "0.1.0";

    const options = b.addOptions();
    options.addOption([]const u8, "version", version);

    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root.addOptions("build_options", options);

    const test_root = b.createModule(.{
        .root_source_file = b.path("src/test_all.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_root.addOptions("build_options", options);

    if (target.result.os.tag == .macos) {
        const macos_c = b.addTranslateC(.{
            .root_source_file = b.path("src/platform/macos_c.h"),
            .target = target,
            .optimize = optimize,
        });
        macos_c.linkSystemLibrary("proc", .{});
        const macos_c_mod = macos_c.createModule();
        root.addImport("macos_c", macos_c_mod);
        test_root.addImport("macos_c", macos_c_mod);
    }

    const exe = b.addExecutable(.{
        .name = "zport",
        .root_module = root,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zport");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_module = test_root,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
