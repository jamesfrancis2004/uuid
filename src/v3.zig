const Uuid = @import("uuid.zig").Uuid;
const Version = @import("uuid.zig").Version;
const std = @import("std");

pub fn generate(namespace: *const Uuid, name: []const u8) Uuid {
    var uuid = Uuid{ .bytes = undefined };
    var hasher = std.crypto.hash.Md5.init(.{});
    hasher.update(&namespace.bytes);
    hasher.update(name);
    hasher.final(&uuid.bytes);
    // Set version to 5 (bits 4-7 of byte 6)
    uuid.setVersion(Version.Md5);
    // Set variant to RFC 4122 (bits 6-7 of byte 8)
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80;
    return uuid;
}
