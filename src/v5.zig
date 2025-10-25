const Uuid = @import("uuid.zig").Uuid;
const Version = @import("uuid.zig").Version;
const std = @import("std");

pub fn generate(namespace: *const Uuid, name: []const u8) Uuid {
    var uuid = Uuid{ .bytes = undefined };
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(&namespace.bytes);
    hasher.update(name);
    var digest: [20]u8 = undefined;
    hasher.final(&digest);
    uuid.bytes = digest[0..16].*;
    // Set version to 5 (bits 4-7 of byte 6)
    uuid.setVersion(Version.Sha1);
    // Set variant to RFC 4122 (bits 6-7 of byte 8)
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80;
    return uuid;
}
