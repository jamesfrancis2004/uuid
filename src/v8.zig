const Uuid = @import("uuid.zig").Uuid;
const Version = @import("uuid.zig").Version;

pub fn generate(bytes: [16]u8) Uuid {
    var uuid = Uuid{ .bytes = bytes };
    uuid.setVersion(Version.Custom);
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80;
    return uuid;
}
