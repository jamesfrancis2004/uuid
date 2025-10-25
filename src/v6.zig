const Uuid = @import("uuid.zig").Uuid;
const Version = @import("uuid.zig").Version;
const std = @import("std");

var global_clock_seq: u16 = 0;
var clock_seq_initialised: bool = false;

// The number of 100 nanosecond ticks between the RFC 9562 epoch
// (`1582-10-15 00:00:00`) and the Unix epoch (`1970-01-01 00:00:00`).
const UUID_TICKS_BETWEEN_EPOCHS: i128 = 0x01B2_1DD2_1381_4000;

pub fn setGlobalClockSeq(count: u14) void {
    @atomicStore(u16, &global_clock_seq, @intCast(count), .seq_cst);
    @atomicStore(bool, &clock_seq_initialised, true, .release);
}

pub fn fetchAndAddCounter() u16 {
    const is_initialised = @atomicRmw(bool, &clock_seq_initialised, .Xchg, true, .acq_rel);
    if (!is_initialised) {
        @atomicStore(u16, &global_clock_seq, std.crypto.random.int(u16), .release);
    }
    return @intCast((@atomicRmw(u16, &global_clock_seq, .Add, 1, .acq_rel)) & (std.math.maxInt(u16) >> 2));
}

pub fn getTimestamp100Ns(nanos: i128) u64 {
    // Convert nanoseconds to 100-ns intervals
    const hundredNs = @divTrunc(nanos, 100);
    // Add the offset between Unix epoch and UUID epoch
    const uuidTs = hundredNs + UUID_TICKS_BETWEEN_EPOCHS;
    return @intCast(uuidTs);
}

pub fn getNanos(uuid: Uuid) i128 {
    // Extract time fields
    const timestamp_high = std.mem.readInt(u32, uuid.bytes[0..4], .big);
    const timestamp_mid = std.mem.readInt(u16, uuid.bytes[4..6], .big);
    const timestamp_low_and_version = std.mem.readInt(u16, uuid.bytes[6..8], .big);

    // Mask out the version bits (upper 4 bits)
    const timestamp_low = timestamp_low_and_version & 0x0FFF;

    // Reconstruct 60-bit timestamp (100-ns intervals since 1582-10-15)
    const timestamp_100ns: i128 =
        (@as(i128, timestamp_high) << 28) |
        (@as(i128, timestamp_mid) << 12) |
        (@as(i128, timestamp_low));

    // Convert to nanoseconds since Unix epoch
    const nanos_since_unix: i128 =
        (timestamp_100ns - UUID_TICKS_BETWEEN_EPOCHS) * 100;

    return nanos_since_unix;
}

pub fn generate(nanos: i128, counter: u16, node: [6]u8) Uuid {
    var uuid = Uuid{ .bytes = undefined };
    const timestamp_100ns = getTimestamp100Ns(nanos);
    const timestamp_low = @as(u16, @intCast(timestamp_100ns & 0x0FFF));
    const timestamp_mid = @as(u16, @intCast((timestamp_100ns >> 12) & 0xFFFF));
    const timestamp_high = @as(u32, @intCast((timestamp_100ns >> 28) & 0xFFFF_FFFF));
    std.mem.writeInt(u32, uuid.bytes[0..4], timestamp_high, .big);
    std.mem.writeInt(u16, uuid.bytes[4..6], timestamp_mid, .big);
    std.mem.writeInt(u16, uuid.bytes[6..8], timestamp_low, .big);
    std.mem.writeInt(u16, uuid.bytes[8..10], counter, .big);
    // Set version to version 1
    uuid.setVersion(Version.SortMac);
    // Set variant to RFC 4122 (bits 6-7 of byte 8)
    uuid.bytes[8] = (uuid.bytes[8] & 0x3F) | 0x80;
    @memcpy(uuid.bytes[10..16], node[0..6]);
    return uuid;
}
