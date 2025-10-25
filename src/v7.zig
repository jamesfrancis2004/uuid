const std = @import("std");
const Uuid = @import("uuid.zig").Uuid;
const Version = @import("uuid.zig").Version;

pub fn getMillis(uuid: Uuid) i64 {
    // Read the first 48 bits (milliseconds since Unix epoch)
    const millis = std.mem.readInt(u48, uuid.bytes[0..6], .big);
    // Convert to nanoseconds
    return @as(i64, millis);
}

pub fn generate(millis: i64, r: std.Random) Uuid {
    var uuid = Uuid{ .bytes = undefined };
    const ts = @as(u48, @intCast(millis));
    std.mem.writeInt(u48, uuid.bytes[0..6], ts, .big);
    std.mem.writeInt(u80, uuid.bytes[6..], r.int(u80), .big);
    // Set Version to 7 SortRand
    uuid.setVersion(Version.SortRand);
    // Set variant to RFC 4122 (bits 6-7 of byte 8)
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80;
    return uuid;
}
