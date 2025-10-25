const std = @import("std");
const Uuid = @import("uuid.zig").Uuid;
const Version = @import("uuid.zig").Version;

pub fn generate(rng: std.Random) Uuid {
    var uuid = Uuid{ .bytes = undefined };
    rng.bytes(&uuid.bytes);
    // Version 4
    uuid.setVersion(Version.Random);
    // Variant 1
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80;
    return uuid;
}
