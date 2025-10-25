const std = @import("std");
const uuid = @import("uuid");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = std.fs.File.stdout().writer(&stderr_buffer);
    const stderr = &stderr_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try stderr.print("unsupported version!\nversions: v1, v3, v4, v5, v6, v7\nusage: {s} <nr-of-UUIDs> <version>\n", .{args[0]});
        return;
    }

    const iterations = try std.fmt.parseInt(usize, args[1], 10);
    const version_str = args[2];

    var timer = try std.time.Timer.start();
    var i: usize = 0;

    if (std.mem.eql(u8, version_str, "v1")) {
        const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
        while (i < iterations) : (i += 1) {
            const id = uuid.Uuid.v1(node1);
            std.mem.doNotOptimizeAway(id);
        }
    } else if (std.mem.eql(u8, version_str, "v3")) {
        const namespace = uuid.Uuid.v4();
        while (i < iterations) : (i += 1) {
            const id = uuid.Uuid.v3(&namespace, "some_name");
            std.mem.doNotOptimizeAway(id);
        }
    } else if (std.mem.eql(u8, version_str, "v4")) {
        while (i < iterations) : (i += 1) {
            const id = uuid.Uuid.v4();
            std.mem.doNotOptimizeAway(id);
        }
    } else if (std.mem.eql(u8, version_str, "v5")) {
        const namespace = uuid.Uuid.v4();
        while (i < iterations) : (i += 1) {
            const id = uuid.Uuid.v5(&namespace, "some_name");
            std.mem.doNotOptimizeAway(id);
        }
    } else if (std.mem.eql(u8, version_str, "v6")) {
        const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
        while (i < iterations) : (i += 1) {
            const id = uuid.Uuid.v6(node1);
            std.mem.doNotOptimizeAway(id);
        }
    } else if (std.mem.eql(u8, version_str, "v7")) {
        while (i < iterations) : (i += 1) {
            const id = uuid.Uuid.v7();
            std.mem.doNotOptimizeAway(id);
        }
    } else if (std.mem.eql(u8, version_str, "parseString")) {
        const str = uuid.Uuid.v4().toString();
        while (i < iterations) : (i += 1) {
            const id = try uuid.Uuid.parse(&str);
            std.mem.doNotOptimizeAway(id);
        }
    } else {
        try stderr.print("unsupported version!\nversions: v1, v3, v4, v5, v6 v7\nusage: {s} <nr-of-UUIDs> <version>\n", .{args[0]});
        return;
    }

    const duration = timer.read();
    try stdout.print("{s}: {d} UUIDs in ", .{ version_str, iterations });
    try stdout.printDurationUnsigned(duration);
    try stdout.print("\n", .{});
    try stdout.flush();
    try stderr.flush();
}
