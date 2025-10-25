const std = @import("std");
const v1_helpers = @import("v1.zig");
const v3_helpers = @import("v3.zig");
const v4_helpers = @import("v4.zig");
const v5_helpers = @import("v5.zig");
const v6_helpers = @import("v6.zig");
const v7_helpers = @import("v7.zig");
const v8_helpers = @import("v8.zig");

/// Error set returned by parsing or invalid operations.
pub const Error = error{InvalidUuid};

/// Enumeration of UUID variants.
pub const Variant = enum { Ncs, Rfc4122, Microsoft, Future };

/// Enumeration of UUID versions, including standard (1–5) and non-standard/custom extensions (6–8).
pub const Version = enum(u8) {
    Nil = 0,
    Mac = 1,
    Dce = 2,
    Md5 = 3,
    Random = 4,
    Sha1 = 5,
    SortMac = 6,
    SortRand = 7,
    Custom = 8,
    Max = 0xFF,
};

/// Represents a UUID (Universally Unique Identifier) as 16 bytes.
/// Provides methods for generating, parsing, comparing, and formatting UUIDs.
pub const Uuid = struct {
    bytes: [16]u8,

    const HEX = "0123456789abcdef";
    const ENCODED_POS = [16]usize{ 0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34 };
    const HEX_TO_NIBBLE: [256]u8 = blk: {
        // Fills this table at compile time
        var table: [256]u8 = undefined;
        for (0..256) |idx| {
            const cur_char: u8 = @intCast(idx);
            table[idx] = switch (cur_char) {
                '0'...'9' => cur_char - '0',
                'a'...'f' => cur_char - 'a' + 10,
                'A'...'F' => cur_char - 'A' + 10,
                else => 0xFF,
            };
        }
        break :blk table;
    };

    // Creates a UUID from two integers representing the high and low 64-bit portions.
    /// If the integers are smaller than 64 bits, they are zero-extended to fill the byte array.
    pub fn init(high: comptime_int, low: comptime_int) Uuid {
        var bytes: [16]u8 = undefined;
        const high64: u64 = @intCast(high);
        const low64: u64 = @intCast(low);
        std.mem.writeInt(u64, bytes[0..8], high64, .big);
        std.mem.writeInt(u64, bytes[8..16], low64, .big);

        return Uuid{ .bytes = bytes };
    }

    /// Returns a nil uuid
    pub fn nil() Uuid {
        return Uuid.init(0, 0);
    }

    /// Returns a max uuid
    pub fn max() Uuid {
        const max_u64 = std.math.maxInt(u64);
        return Uuid.init(max_u64, max_u64);
    }

    /// Constructs a UUID directly from a 16-byte array.
    /// This does not perform any validation on the version or variant bits.
    pub fn fromBytes(bytes: [16]u8) Uuid {
        return Uuid{ .bytes = bytes };
    }

    /// Returns a pointer to the internal 16-byte array representation of the UUID.
    pub fn asBytes(self: Uuid) *const [16]u8 {
        return &self.bytes;
    }

    /// Returns the 14-bit counter (clock sequence) from a version 1 or 6 UUID, if applicable.
    /// For other UUID versions, returns null.
    pub fn getCounter(self: Uuid) ?u14 {
        const version = self.getVersionNum();
        if (version != 1 and version != 6) return null;
        // bytes[8..10] contains the 14-bit counter
        const high = self.bytes[8] & 0x3F; // mask out the upper 2 variant bits
        const low = self.bytes[9];
        return (@as(u14, high) << 8) | @as(u14, low);
    }

    /// Returns the Unix timestamp of the UUID in nanoseconds, if available.
    /// The timestamp is measured relative to the Unix epoch (`1970-01-01 00:00:00 UTC`).
    /// Supports UUID versions 1, 6, and 7:
    /// - Version 1: returns the 100-nanosecond timestamp converted to nanoseconds since Unix epoch.
    /// - Version 6: returns the timestamp converted to nanoseconds since Unix epoch.
    /// - Version 7: returns the milliseconds timestamp multiplied by 1,000,000 to get nanoseconds.
    /// - Other versions: returns `null`.
    pub fn getNanos(self: Uuid) ?i128 {
        const version = self.getVersionNum();
        switch (version) {
            1 => return v1_helpers.getNanos(self),
            6 => return v6_helpers.getNanos(self),
            7 => return v7_helpers.getMillis(self) * 1_000_000,
            else => return null,
        }
    }

    /// Returns the Unix timestamp of the UUID in milliseconds, if available.
    /// The timestamp is measured relative to the Unix epoch (`1970-01-01 00:00:00 UTC`).
    /// Supports UUID versions 1, 6, and 7:
    /// - Version 1: converts the nanosecond timestamp to milliseconds (truncated).
    /// - Version 6: converts the nanosecond timestamp to milliseconds (truncated).
    /// - Version 7: returns the millisecond timestamp directly.
    /// - Other versions: returns `null`.
    pub fn getMillis(self: Uuid) ?i64 {
        const version = self.getVersionNum();
        switch (version) {
            1 => return @intCast(@divTrunc(v1_helpers.getNanos(self), 1_000_000)),
            6 => return @intCast(@divTrunc(v6_helpers.getNanos(self), 1_000_000)),
            7 => return v7_helpers.getMillis(self),
            else => return null,
        }
    }

    /// Returns the node (MAC) portion of a version 1 or 6 UUID.
    /// For other versions, returns `null`.
    pub fn getNode(self: Uuid) ?[6]u8 {
        const version = self.getVersionNum();
        if (version != 1 and version != 6) return null;
        var node: [6]u8 = undefined;
        @memcpy(&node, self.bytes[10..16]);
        return node;
    }

    /// Generates a Version 1 UUID (time-based) using current time and a MAC node.
    pub fn v1(node: [6]u8) Uuid {
        return v1_helpers.generate(std.time.nanoTimestamp(), v1_helpers.fetchAndAddCounter(), node);
    }

    /// Sets the global clock sequence used for generating V1 UUIDs.
    /// `clockSeq` must be a 14-bit value (0..=16383).
    pub fn v1SetGlobalClockSeq(clockSeq: u14) void {
        return v1_helpers.setGlobalClockSeq(clockSeq);
    }

    /// Generates a Version 1 UUID at a specific timestamp (nanoseconds).
    pub fn v1At(nanos: i128, node: [6]u8) Uuid {
        return v1_helpers.generate(nanos, v1_helpers.fetchAndAddCounter(), node);
    }

    /// Generates a Version 1 UUID with a specific count.
    pub fn v1WithCount(count: u14, node: [6]u8) Uuid {
        return v1_helpers.generate(std.time.nanoTimestamp(), @intCast(count), node);
    }

    /// Generates a Version 1 Uuid with a specific count at a specific timestamp (nanoseconds).
    pub fn v1WithCountAt(nanos: i128, count: u14, node: [6]u8) Uuid {
        return v1_helpers.generate(nanos, @intCast(count), node);
    }

    /// Generates a Version 3 UUID (name-based with MD5) from a namespace and name.
    pub fn v3(namespace: *const Uuid, name: []const u8) Uuid {
        return v3_helpers.generate(namespace, name);
    }

    /// Generates a Version 4 UUID using cryptographically secure randomness.
    pub fn v4() Uuid {
        return v4_helpers.generate(std.crypto.random);
    }

    /// Generates a Version 4 UUID using the provided random number generator.
    pub fn v4WithRng(rng: std.Random) Uuid {
        return v4_helpers.generate(rng);
    }

    /// Generates a Version 5 UUID (name-based with SHA-1) from a namespace and name.
    pub fn v5(namespace: *const Uuid, name: []const u8) Uuid {
        return v5_helpers.generate(namespace, name);
    }

    /// Generates a Version 6 UUID (time-ordered MAC-based) using current timestamp.
    pub fn v6(node: [6]u8) Uuid {
        return v6_helpers.generate(std.time.nanoTimestamp(), v6_helpers.fetchAndAddCounter(), node);
    }

    /// Sets the global clock sequence used for generating V6 UUIDs.
    /// `clockSeq` must be a 14-bit value (0..=16383).
    pub fn v6SetGlobalClockSeq(clockSeq: u14) void {
        return v6_helpers.setGlobalClockSeq(clockSeq);
    }

    /// Generates a Version 6 UUID (time-ordered MAC-based) using current timestamp, but a specified count.
    pub fn v6WithCount(count: u14, node: [6]u8) Uuid {
        return v6_helpers.generate(std.time.nanoTimestamp(), @intCast(count), node);
    }

    /// Generates a Version 6 UUID with a specified nanosecond timestamp.
    pub fn v6At(nanos: i128, node: [6]u8) Uuid {
        return v6_helpers.generate(nanos, v6_helpers.fetchAndAddCounter(), node);
    }

    /// Generates a Version 6 Uuid with a specific count at a specific timestamp (nanoseconds).
    pub fn v6WithCountAt(nanos: i128, count: u14, node: [6]u8) Uuid {
        return v6_helpers.generate(nanos, @intCast(count), node);
    }

    /// Generates a Version 7 UUID using the current timestamp (milliseconds).
    /// Includes random bits for uniqueness and sortability.
    pub fn v7() Uuid {
        return v7_helpers.generate(std.time.milliTimestamp(), std.crypto.random);
    }

    /// Generates a Version 7 UUID using the current timestamp (milliseconds).
    /// Uses the provided Random Number Generator
    pub fn v7WithRng(rng: std.Random) Uuid {
        return v7_helpers.generate(std.time.milliTimestamp(), rng);
    }

    /// Generates a Version 7 UUID using a specific timestamp (milliseconds).
    pub fn v7At(millis: i64) Uuid {
        return v7_helpers.generate(millis, std.crypto.random);
    }

    /// Generates a Version 7 UUID with a specific timestamp and RNG.
    pub fn v7WithRngAt(millis: i64, rng: std.Random) Uuid {
        return v7_helpers.generate(millis, rng);
    }

    /// Generates a Version 8 (custom) UUID using the given 16 raw bytes.
    /// Sets version and variant bits automatically.
    pub fn v8(bytes: [16]u8) Uuid {
        return v8_helpers.generate(bytes);
    }

    /// Returns true if `self` is greater than `other`.
    pub fn gt(self: Uuid, other: Uuid) bool {
        return std.mem.readInt(u128, &self.bytes, .big) > std.mem.readInt(u128, &other.bytes, .big);
    }

    /// Returns true if `self` is greater than or equal to `other`.
    pub fn gte(self: Uuid, other: Uuid) bool {
        return std.mem.readInt(u128, &self.bytes, .big) >= std.mem.readInt(u128, &other.bytes, .big);
    }

    /// Returns true if `self` is less than `other`.
    pub fn lt(self: Uuid, other: Uuid) bool {
        return std.mem.readInt(u128, &self.bytes, .big) < std.mem.readInt(u128, &other.bytes, .big);
    }

    /// Returns true if `self` is less or equal to than `other`.
    pub fn lte(self: Uuid, other: Uuid) bool {
        return std.mem.readInt(u128, &self.bytes, .big) <= std.mem.readInt(u128, &other.bytes, .big);
    }

    /// Returns true if `self` is equal to `other`.
    pub fn eql(self: Uuid, other: Uuid) bool {
        return std.mem.eql(u8, self.bytes[0..], other.bytes[0..]);
    }

    /// Returns the upper 64 bits of the UUID as a u64.
    pub fn getHighBits(self: Uuid) u64 {
        return std.mem.readInt(u64, self.bytes[0..8], .big);
    }

    /// Returns the lower 64 bits of the UUID as a u64.
    pub fn getLowBits(self: Uuid) u64 {
        return std.mem.readInt(u64, self.bytes[8..16], .big);
    }

    /// Returns the UUID as a tuple of high and low 64-bit parts.
    pub fn getHighLowBits(self: Uuid) struct { u64, u64 } {
        return .{ self.getHighBits(), self.getLowBits() };
    }

    /// Returns true if the UUID is the Nil UUID (all zeros).
    pub fn isNil(self: Uuid) bool {
        const high, const low = self.getHighLowBits();
        return high == 0 and low == 0;
    }

    /// Returns true if the UUID is the Max UUID (all bits set to 1).
    pub fn isMax(self: Uuid) bool {
        const high, const low = self.getHighLowBits();
        const max_u64 = std.math.maxInt(u64);
        return high == max_u64 and low == max_u64;
    }

    /// Returns the raw version number from the UUID (high nibble of byte 6).
    pub fn getVersionNum(self: Uuid) u64 {
        return (self.bytes[6] >> 4);
    }

    /// Sets the version number in the UUID (upper 4 bits of byte 6).
    pub fn setVersion(self: *Uuid, version: Version) void {
        self.bytes[6] = (self.bytes[6] & 0x0F) | (@intFromEnum(version) << 4);
    }

    /// Returns the UUID variant, determined from bits 6–7 of byte 8.
    /// Supports standard variants: NCS, RFC 4122, Microsoft, and Future.
    pub fn getVariant(self: Uuid) Variant {
        const byte = self.bytes[8];
        return switch (byte >> 5) {
            0b000...0b011 => Variant.Ncs,
            0b100...0b101 => Variant.Rfc4122,
            0b110 => Variant.Microsoft,
            else => Variant.Future,
        };
    }

    /// Returns the recognized `Version` enum corresponding to this UUID's version field,
    /// or `null` if the version is unrecognized. Special-case handling for Nil and Max UUIDs.
    pub fn getVersion(self: Uuid) ?Version {
        switch (self.getVersionNum()) {
            0 => if (self.isNil()) return Version.Nil,
            1 => return Version.Mac,
            2 => return Version.Dce,
            3 => return Version.Md5,
            4 => return Version.Random,
            5 => return Version.Sha1,
            6 => return Version.SortMac,
            7 => return Version.SortRand,
            8 => return Version.Custom,
            0xF => if (self.isMax()) return Version.Max,
            else => return null,
        }
        return null;
    }

    /// Converts the UUID to a simple string format (e.g., 123e4567e89b12d3a456426614174000).
    pub fn toSimpleString(self: Uuid) [32]u8 {
        var buf: [32]u8 = undefined;
        inline for (0..16) |i| {
            buf[i * 2] = HEX[self.bytes[i] >> 4];
            buf[i * 2 + 1] = HEX[self.bytes[i] & 0x0F];
        }
        return buf;
    }

    /// Converts the UUID to a hyphenated string format (e.g., 123e4567-e89b-12d3-a456-426614174000).
    pub fn toString(self: Uuid) [36]u8 {
        var buf: [36]u8 = undefined;
        buf[8] = '-';
        buf[13] = '-';
        buf[18] = '-';
        buf[23] = '-';
        inline for (ENCODED_POS, 0..) |i, j| {
            buf[i] = HEX[self.bytes[j] >> 4];
            buf[i + 1] = HEX[self.bytes[j] & 0x0F];
        }
        return buf;
    }

    /// Writes the formatted UUID to a writer using `toString`.
    pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
        return writer.writeAll(&self.toString());
    }

    /// Parses a UUID from a 32-character hex string (no hyphens).
    pub fn parseSimple(buf: []const u8) Error!Uuid {
        var uuid = Uuid{ .bytes = undefined };
        if (buf.len != 32)
            return Error.InvalidUuid;

        inline for (0..16) |i| {
            const buf_index = i * 2;
            const hi = HEX_TO_NIBBLE[buf[buf_index]];
            const lo = HEX_TO_NIBBLE[buf[buf_index + 1]];
            if (hi | lo == 0xFF) {
                return Error.InvalidUuid;
            }
            uuid.bytes[i] = hi << 4 | lo;
        }
        return uuid;
    }

    /// Parses a UUID from a 36-character hyphenated string.
    pub fn parseHyphenated(buf: []const u8) Error!Uuid {
        var uuid = Uuid{ .bytes = undefined };
        if (buf.len != 36 or buf[8] != '-' or buf[13] != '-' or buf[18] != '-' or buf[23] != '-')
            return Error.InvalidUuid;

        inline for (ENCODED_POS, 0..) |i, j| {
            const hi = HEX_TO_NIBBLE[buf[i]];
            const lo = HEX_TO_NIBBLE[buf[i + 1]];
            if (hi | lo == 0xFF) {
                return Error.InvalidUuid;
            }
            uuid.bytes[j] = hi << 4 | lo;
        }
        return uuid;
    }

    /// Parses a UUID from various formats:
    /// - 32-character hex string
    /// - 36-character hyphenated string
    /// - 38-character string with braces {uuid}
    /// - URN format "urn:uuid:..."
    pub fn parse(buf: []const u8) Error!Uuid {
        const len = buf.len;
        switch (len) {
            32 => return parseSimple(buf),
            36 => return parseHyphenated(buf),
            38 => if (buf[0] == '{' and buf[len - 1] == '}') return parseHyphenated(buf[1..(len - 1)]),
            45 => if (std.mem.startsWith(u8, buf, "urn:uuid:")) return parseHyphenated(buf[9..]),
            else => return error.InvalidUuid,
        }
        return error.InvalidUuid;
    }

    /// HashContext for using `Uuid` in hash maps or sets.
    /// Uses Wyhash for hashing and `eql` for equality checks.
    pub const HashContext = struct {
        /// Computes a `u64` hash of the UUID using Wyhash.
        pub fn hash(_: HashContext, u: Uuid) u64 {
            return std.hash.Wyhash.hash(0, u.asBytes());
        }

        /// Compares two UUIDs for equality.
        pub fn eql(_: HashContext, a: Uuid, b: Uuid) bool {
            return a.eql(b);
        }
    };
};

test "Uuid.init produces expected bytes" {
    const high: u32 = 0x12345678;
    const low: u32 = 0x9abcdef0;
    const uuid = Uuid.init(high, low);

    // Expected bytes: high and low as big-endian u64.
    // Because high and low are u32 here, they get zero-extended to u64.
    // So the expected byte arrays are 4 bytes zeros + 4 bytes of the u32 value in big-endian.
    const expected_high: [8]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78 };
    const expected_low: [8]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x9a, 0xbc, 0xde, 0xf0 };

    try std.testing.expectEqualSlices(u8, uuid.bytes[0..8], expected_high[0..8]);
    try std.testing.expectEqualSlices(u8, uuid.bytes[8..16], expected_low[0..8]);
}

test "Uuid.nil produces a nil uuid" {
    const uuid = Uuid.nil();
    try std.testing.expectEqual(0, std.mem.readInt(u128, &uuid.bytes, .big));
    try std.testing.expect(uuid.isNil());
}

test "Uuid.max produces a max uuid" {
    const uuid = Uuid.max();
    try std.testing.expectEqual(std.math.maxInt(u128), std.mem.readInt(u128, &uuid.bytes, .big));
    try std.testing.expect(uuid.isMax());
}

test "Uuid comparison operators work" {
    const uuid1 = Uuid.init(0, 1);
    const uuid2 = Uuid.init(0, 2);
    try std.testing.expect(uuid2.gt(uuid1));
    try std.testing.expect(uuid1.lt(uuid2));
    try std.testing.expect(uuid1.lte(uuid1));
    try std.testing.expect(uuid2.gte(uuid2));
    try std.testing.expect(!uuid1.eql(uuid2));
    const uuid3 = Uuid.init(1, 1);
    const uuid4 = Uuid.init(1, 1);
    try std.testing.expect(uuid3.gte(uuid4));
    try std.testing.expect(uuid3.lte(uuid4));
}

test "Uuid.setVersion correctly updates version" {
    var uuid = Uuid.nil();
    uuid.setVersion(.Sha1);
    try std.testing.expectEqual(5, uuid.getVersionNum());
}

test "Uuid.getVariant returns correct variant" {
    var uuid = Uuid.nil();
    uuid.bytes[8] = 0b0000_0000;
    try std.testing.expect(uuid.getVariant() == .Ncs);

    uuid.bytes[8] = 0b1000_0000;
    try std.testing.expect(uuid.getVariant() == .Rfc4122);

    uuid.bytes[8] = 0b1100_0000;
    try std.testing.expect(uuid.getVariant() == .Microsoft);

    uuid.bytes[8] = 0b1110_0000;
    try std.testing.expect(uuid.getVariant() == .Future);
}

test "Uuid.HashContext hash/eql" {
    const uuid1 = Uuid.v4();
    const uuid2 = uuid1;
    const hash_context = Uuid.HashContext{};
    try std.testing.expect(Uuid.HashContext.eql(hash_context, uuid1, uuid2));
    try std.testing.expect(Uuid.HashContext.hash(hash_context, uuid1) == Uuid.HashContext.hash(hash_context, uuid2));
}

test "Uuid.toString converts to dashed hex string" {
    const uuid_bytes: [16]u8 = .{
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const uuid = Uuid{ .bytes = uuid_bytes };
    const result_slice = uuid.toString();
    // The expected string in dashed format
    const expected_string = "12345678-90ab-cdef-fedc-ba9876543210";

    // Convert the expected string literal to a slice of u8 for comparison
    const expected_slice = expected_string[0..];
    try std.testing.expectEqualStrings(expected_slice, result_slice[0..]);
}

test "Uuid.toSimpleString produces correct 32-char hex string" {
    const uuid_bytes: [16]u8 = .{
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10,
    };
    const uuid = Uuid{ .bytes = uuid_bytes };

    const result = uuid.toSimpleString();
    const expected = "1234567890abcdeffedcba9876543210";

    try std.testing.expectEqualStrings(expected, &result);
}

test "Uuid.parse and Uuid.format to hyphenated work successfully" {
    // These are the various input formats we want to test.
    // Each inner array represents a set of strings that should parse to the same UUID.
    const uuid_input_formats = [_][]const u8{
        "d0cd8041-0504-40cb-ac8e-d05960d205ec",
        "urn:uuid:d0cd8041-0504-40cb-ac8e-d05960d205ec",
        "{d0cd8041-0504-40cb-ac8e-d05960d205ec}",
        "d0cd8041050440cbac8ed05960d205ec",

        "3df6f0e4-f9b1-4e34-ad70-33206069b995",
        "urn:uuid:3df6f0e4-f9b1-4e34-ad70-33206069b995",
        "{3df6f0e4-f9b1-4e34-ad70-33206069b995}",
        "3df6f0e4f9b14e34ad7033206069b995",

        "f982cf56-c4ab-4229-b23c-d17377d000be",
        "urn:uuid:f982cf56-c4ab-4229-b23c-d17377d000be",
        "{f982cf56-c4ab-4229-b23c-d17377d000be}",
        "f982cf56c4ab4229b23cd17377d000be",

        "6b9f53be-cf46-40e8-8627-6b60dc33def8",
        "urn:uuid:6b9f53be-cf46-40e8-8627-6b60dc33def8",
        "{6b9f53be-cf46-40e8-8627-6b60dc33def8}",
        "6b9f53becf4640e886276b60dc33def8",

        "c282ec76-ac18-4d4a-8a29-3b94f5c74813",
        "urn:uuid:c282ec76-ac18-4d4a-8a29-3b94f5c74813",
        "{c282ec76-ac18-4d4a-8a29-3b94f5c74813}",
        "c282ec76ac184d4a8a293b94f5c74813",

        "00000000-0000-0000-0000-000000000000",
        "urn:uuid:00000000-0000-0000-0000-000000000000",
        "{00000000-0000-0000-0000-000000000000}",
        "00000000000000000000000000000000",
    };

    // This is the expected *output* format (hyphenated) for each set of inputs.
    // Make sure these match the first entry in your original `uuids` data,
    // as that's the canonical hyphenated form.
    const expected_hyphenated_outputs = [_][]const u8{
        "d0cd8041-0504-40cb-ac8e-d05960d205ec",
        "d0cd8041-0504-40cb-ac8e-d05960d205ec", // Expected output for urn:uuid:...
        "d0cd8041-0504-40cb-ac8e-d05960d205ec", // Expected output for {...}
        "d0cd8041-0504-40cb-ac8e-d05960d205ec", // Expected output for compact

        "3df6f0e4-f9b1-4e34-ad70-33206069b995",
        "3df6f0e4-f9b1-4e34-ad70-33206069b995",
        "3df6f0e4-f9b1-4e34-ad70-33206069b995",
        "3df6f0e4-f9b1-4e34-ad70-33206069b995",

        "f982cf56-c4ab-4229-b23c-d17377d000be",
        "f982cf56-c4ab-4229-b23c-d17377d000be",
        "f982cf56-c4ab-4229-b23c-d17377d000be",
        "f982cf56-c4ab-4229-b23c-d17377d000be",

        "6b9f53be-cf46-40e8-8627-6b60dc33def8",
        "6b9f53be-cf46-40e8-8627-6b60dc33def8",
        "6b9f53be-cf46-40e8-8627-6b60dc33def8",
        "6b9f53be-cf46-40e8-8627-6b60dc33def8",

        "c282ec76-ac18-4d4a-8a29-3b94f5c74813",
        "c282ec76-ac18-4d4a-8a29-3b94f5c74813",
        "c282ec76-ac18-4d4a-8a29-3b94f5c74813",
        "c282ec76-ac18-4d4a-8a29-3b94f5c74813",

        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-0000-0000-000000000000",
    };
    for (uuid_input_formats, expected_hyphenated_outputs) |input_str, expected_output_str| {
        // Parse the input string, which can be in any of the supported formats.
        const parsed_uuid = try Uuid.parse(input_str);

        // Then format the parsed Uuid object back into a string.
        // We expect this formatted string to *always* be in the hyphenated format.
        // `expectFmt` compares the formatted value with the expected string literal.
        try std.testing.expectFmt(expected_output_str, "{f}", .{parsed_uuid});
    }
}

test "Uuid.parse returns error for invalid uuid" {
    const uuid_input_formats = [_][]const u8{
        "d0cd8041-0504-40cb-ac8e-d05960d205ecx", // Extra char at end
        "urn:uuid:d0cd8041-0504-40cb-ac8e-d05960d205ecy", // Extra char at end
        "{d0cd8041-0504-40cb-ac8e-d05960d205ec}y", // Extra char at end
        "d0cd8041050440cbac8ed05960d205ecx", // Extra char at end
        "RandomGarbage", // Completely malformed
        "", // Empty string
        "short", // Too short
        "d0cd8041-0504-40cb-ac8e-d05960d205ec-too-long-extra-stuff", // Way too long
    };

    for (uuid_input_formats) |input_str| {
        try std.testing.expectError(Error.InvalidUuid, Uuid.parse(input_str));
    }
}

test "Uuid.v1 produces correct results" {
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const node2: [6]u8 = .{ 'o', 't', 'h', 'e', 'r', 'n' };

    const uuid1 = Uuid.v1(node1);
    const uuid2 = Uuid.v1(node2);
    try std.testing.expect(!uuid1.eql(uuid2));
    try std.testing.expectEqual(Version.Mac, uuid1.getVersion.?);
    const count1 = uuid1.getCounter();
    const count2 = uuid2.getCounter();

    // Make sure counters exist
    try std.testing.expect(count1 != null);
    try std.testing.expect(count2 != null);

    // Check that the second counter is exactly one greater (mod 14-bit)
    try std.testing.expect(count2.? == ((count1.? + 1) & 0x3FFF));
    try std.testing.expect(uuid1.getNanos().? >= std.time.milliTimestamp());
}

test "Uuid.v1SetGlobalClockSeq produces correct results" {
    Uuid.v1SetGlobalClockSeq(100);
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const uuid1 = Uuid.v1(node1);
    const count1 = uuid1.getCounter();
    try std.testing.expectEqual(count1, 100);
}

test "Uuid.v1At produces correct results" {
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const uuid1 = Uuid.v1At(1_000_000_000, node1);
    const uuid2 = Uuid.v1At(1_000_000_000, node1);
    try std.testing.expect(!uuid1.eql(uuid2));
    const count1 = uuid1.getCounter();
    const count2 = uuid2.getCounter();
    try std.testing.expectEqual(count2.?, count1.? + 1);
    const nanos1 = uuid1.getNanos();
    const nanos2 = uuid2.getNanos();
    try std.testing.expectEqual(1_000_000_000, nanos1);
    try std.testing.expectEqual(1_000_000_000, nanos2);
    const millis1 = uuid1.getMillis();
    const millis2 = uuid2.getMillis();
    try std.testing.expectEqual(1_000, millis1);
    try std.testing.expectEqual(1_000, millis2);
    try std.testing.expectEqualSlices(u8, &node1, &uuid1.getNode().?);
    try std.testing.expectEqualSlices(u8, &node1, &uuid2.getNode().?);
}

test "Uuid.v1WithCount produces correct results" {
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const node2: [6]u8 = .{ 'o', 't', 'h', 'e', 'r', 'n' };
    const uuid1 = Uuid.v1WithCount(0, node1);
    const uuid2 = Uuid.v1WithCount(0, node2);
    try std.testing.expect(!uuid1.eql(uuid2));

    const count1 = uuid1.getCounter();
    const count2 = uuid2.getCounter();
    try std.testing.expectEqual(0, count1.?);
    try std.testing.expectEqual(0, count2.?);
    try std.testing.expectEqualSlices(u8, &node1, &uuid1.getNode().?);
    try std.testing.expectEqualSlices(u8, &node2, &uuid2.getNode().?);
}

test "Uuid.v1WithCountAt produces correct results" {
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const uuid1 = Uuid.v1WithCountAt(1000, 0, node1);
    const uuid2 = Uuid.v1WithCountAt(1000, 0, node1);
    try std.testing.expect(uuid1.eql(uuid2));
    try std.testing.expectEqual(1000, uuid1.getNanos().?);
    try std.testing.expectEqual(1000, uuid2.getNanos().?);
    try std.testing.expectEqual(0, uuid1.getCounter().?);
    try std.testing.expectEqual(0, uuid2.getCounter().?);
    try std.testing.expectEqualSlices(u8, &node1, &uuid1.getNode().?);
    try std.testing.expectEqualSlices(u8, &node1, &uuid2.getNode().?);
}

test "Uuid.v3 produces correct results" {
    const NAMESPACE_DNS = @import("namespace.zig").NAMESPACE_DNS;
    const NAMESPACE_URL = @import("namespace.zig").NAMESPACE_URL;
    const NAMESPACE_OID = @import("namespace.zig").NAMESPACE_OID;
    const NAMESPACE_X500 = @import("namespace.zig").NAMESPACE_X500;

    const fixtures = [_]struct {
        namespace: Uuid,
        name: []const u8,
        expected: []const u8,
    }{
        .{ .namespace = NAMESPACE_DNS, .name = "example.org", .expected = "04738bdf-b25a-3829-a801-b21a1d25095b" },
        .{ .namespace = NAMESPACE_DNS, .name = "42", .expected = "5aab6e0c-b7d3-379c-92e3-2bfbb5572511" },
        .{ .namespace = NAMESPACE_DNS, .name = "lorem ipsum", .expected = "4f8772e9-b59c-3cc9-91a9-5c823df27281" },
        .{ .namespace = NAMESPACE_URL, .name = "example.org", .expected = "39682ca1-9168-3da2-a1bb-f4dbcde99bf9" },
        .{ .namespace = NAMESPACE_URL, .name = "42", .expected = "08998a0c-fcf4-34a9-b444-f2bfc15731dc" },
        .{ .namespace = NAMESPACE_URL, .name = "lorem ipsum", .expected = "e55ad2e6-fb89-34e8-b012-c5dde3cd67f0" },
        .{ .namespace = NAMESPACE_OID, .name = "example.org", .expected = "f14eec63-2812-3110-ad06-1625e5a4a5b2" },
        .{ .namespace = NAMESPACE_OID, .name = "42", .expected = "ce6925a5-2cd7-327b-ab1c-4b375ac044e4" },
        .{ .namespace = NAMESPACE_OID, .name = "lorem ipsum", .expected = "5dd8654f-76ba-3d47-bc2e-4d6d3a78cb09" },
        .{ .namespace = NAMESPACE_X500, .name = "example.org", .expected = "64606f3f-bd63-363e-b946-fca13611b6f7" },
        .{ .namespace = NAMESPACE_X500, .name = "42", .expected = "c1073fa2-d4a6-3104-b21d-7a6bdcf39a23" },
        .{ .namespace = NAMESPACE_X500, .name = "lorem ipsum", .expected = "02f09a3f-1624-3b1d-8409-44eff7708208" },
    };

    for (fixtures) |fixture| {
        const uuid = Uuid.v3(&fixture.namespace, fixture.name);
        const uuid_str = uuid.toString();
        try std.testing.expectEqualStrings(fixture.expected, &uuid_str);
        try std.testing.expectEqual(Version.Md5, uuid.getVersion().?);
    }
}

test "Uuid.v4 produces a valid version 4 UUID" {
    const uuid1 = Uuid.v4();
    const uuid2 = Uuid.v4();

    try std.testing.expect(uuid1.getVersionNum() == 4);
    try std.testing.expect(uuid2.getVersionNum() == 4);
    try std.testing.expectEqual(Version.Random, uuid1.getVersion().?);

    try std.testing.expect(!uuid1.eql(uuid2));
    try std.testing.expectEqual(uuid1.getNanos(), null);
}

test "Uuid.v4WithRng produces a valid version 4 Uuid" {
    var prng = std.Random.DefaultPrng.init(12345);
    const rng = prng.random();

    const uuid1 = Uuid.v4WithRng(rng);
    const uuid2 = Uuid.v4WithRng(rng);

    try std.testing.expectEqualStrings("68a5f8de-828a-448d-a002-677953f97734", &uuid1.toString());
    try std.testing.expectEqualStrings("698ddbe6-fca2-4a15-906d-0cc25388ef2c", &uuid2.toString());
}

test "Uuid.v5 produces correct results" {
    const NAMESPACE_DNS = @import("namespace.zig").NAMESPACE_DNS;
    const NAMESPACE_URL = @import("namespace.zig").NAMESPACE_URL;
    const NAMESPACE_OID = @import("namespace.zig").NAMESPACE_OID;
    const NAMESPACE_X500 = @import("namespace.zig").NAMESPACE_X500;
    const fixtures = [_]struct {
        namespace: Uuid,
        name: []const u8,
        expected: []const u8,
    }{
        .{ .namespace = NAMESPACE_DNS, .name = "example.org", .expected = "aad03681-8b63-5304-89e0-8ca8f49461b5" },
        .{ .namespace = NAMESPACE_DNS, .name = "42", .expected = "7c411b5e-9d3f-50b5-9c28-62096e41c4ed" },
        .{ .namespace = NAMESPACE_DNS, .name = "lorem ipsum", .expected = "97886a05-8a68-5743-ad55-56ab2d61cf7b" },
        .{ .namespace = NAMESPACE_URL, .name = "example.org", .expected = "54a35416-963c-5dd6-a1e2-5ab7bb5bafc7" },
        .{ .namespace = NAMESPACE_URL, .name = "42", .expected = "5c2b23de-4bad-58ee-a4b3-f22f3b9cfd7d" },
        .{ .namespace = NAMESPACE_URL, .name = "lorem ipsum", .expected = "15c67689-4b85-5253-86b4-49fbb138569f" },
        .{ .namespace = NAMESPACE_OID, .name = "example.org", .expected = "34784df9-b065-5094-92c7-00bb3da97a30" },
        .{ .namespace = NAMESPACE_OID, .name = "42", .expected = "ba293c61-ad33-57b9-9671-f3319f57d789" }, //.{ .namespace = NAMESPACE_OID, .name = "lorem ipsum", .expected = "6485290d-f79e-5380-9e64-cb4312c7b4a6" },
        .{ .namespace = NAMESPACE_X500, .name = "example.org", .expected = "e3635e86-f82b-5bbc-a54a-da97923e5c76" },
        .{ .namespace = NAMESPACE_X500, .name = "42", .expected = "e4b88014-47c6-5fe0-a195-13710e5f6e27" },
        .{ .namespace = NAMESPACE_X500, .name = "lorem ipsum", .expected = "b11f79a5-1e6d-57ce-a4b5-ba8531ea03d0" },
    };

    for (fixtures) |fixture| {
        const uuid = Uuid.v5(&fixture.namespace, fixture.name);
        const uuid_str = uuid.toString();
        try std.testing.expectEqualStrings(fixture.expected, &uuid_str);
        try std.testing.expectEqual(Version.Sha1, uuid.getVersion().?);
    }
}

test "Uuid.v6 produces correct results" {
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const node2: [6]u8 = .{ 'o', 't', 'h', 'e', 'r', 'n' };
    const uuid1 = Uuid.v6(node1);
    const uuid2 = Uuid.v6(node2);
    try std.testing.expectEqual(Version.SortMac, uuid1.getVersion().?);
    try std.testing.expectEqual(6, uuid1.getVersionNum());
    try std.testing.expect(!uuid1.eql(uuid2));
    const count1 = uuid1.getCounter();
    const count2 = uuid2.getCounter();
    try std.testing.expectEqual(count1.? + 1, count2.?);
    try std.testing.expectEqualSlices(u8, &node1, &uuid1.getNode().?);
    try std.testing.expectEqualSlices(u8, &node2, &uuid2.getNode().?);
    try std.testing.expect(uuid1.getNanos().? >= std.time.milliTimestamp());
}

test "Uuid.v6SetGlobalClockSeq produces correct results" {
    Uuid.v6SetGlobalClockSeq(100);
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const uuid1 = Uuid.v6(node1);
    const count1 = uuid1.getCounter();
    try std.testing.expectEqual(count1, 100);
}

test "Uuid.v6At produces correct results" {
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const uuid1 = Uuid.v6At(1_000_000_000, node1);
    const uuid2 = Uuid.v6At(1_000_000_000, node1);
    try std.testing.expect(!uuid1.eql(uuid2));
    const count1 = uuid1.getCounter();
    const count2 = uuid2.getCounter();
    try std.testing.expectEqual(count2.?, count1.? + 1);
    const nanos1 = uuid1.getNanos();
    const nanos2 = uuid2.getNanos();
    try std.testing.expectEqual(1_000_000_000, nanos1);
    try std.testing.expectEqual(1_000_000_000, nanos2);
    const millis1 = uuid1.getMillis();
    const millis2 = uuid2.getMillis();
    try std.testing.expectEqual(1_000, millis1);
    try std.testing.expectEqual(1_000, millis2);
    try std.testing.expectEqualSlices(u8, &node1, &uuid1.getNode().?);
    try std.testing.expectEqualSlices(u8, &node1, &uuid2.getNode().?);
}

test "Uuid.v6WithCount produces correct results" {
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const node2: [6]u8 = .{ 'o', 't', 'h', 'e', 'r', 'n' };
    const uuid1 = Uuid.v6WithCount(0, node1);
    const uuid2 = Uuid.v6WithCount(0, node2);
    try std.testing.expect(!uuid1.eql(uuid2));

    const count1 = uuid1.getCounter();
    const count2 = uuid2.getCounter();
    try std.testing.expect(count1.? == 0);
    try std.testing.expect(count2.? == 0);
    try std.testing.expectEqualSlices(u8, &node1, &uuid1.getNode().?);
    try std.testing.expectEqualSlices(u8, &node2, &uuid2.getNode().?);
}

test "Uuid.v6WithCountAt produces correct results" {
    const node1: [6]u8 = .{ 's', 'o', 'm', 'e', 'n', 'o' };
    const uuid1 = Uuid.v1WithCountAt(1000, 0, node1);
    const uuid2 = Uuid.v1WithCountAt(1000, 0, node1);
    try std.testing.expect(uuid1.eql(uuid2));
    try std.testing.expectEqual(1000, uuid1.getNanos().?);
    try std.testing.expectEqual(1000, uuid2.getNanos().?);
    try std.testing.expectEqualSlices(u8, &node1, &uuid1.getNode().?);
    try std.testing.expectEqualSlices(u8, &node1, &uuid2.getNode().?);
}

test "Uuid.v7 produces unique Uuids" {
    const uuid1 = Uuid.v7();
    const uuid2 = Uuid.v7();
    try std.testing.expectEqual(Version.SortRand, uuid1.getVersion().?);
    try std.testing.expectEqual(7, uuid1.getVersionNum());
    try std.testing.expect(!uuid1.eql(uuid2));
    try std.testing.expect(uuid1.getMillis().? >= std.time.milliTimestamp());
}

test "Uuid.v7At produces correct Uuid" {
    const uuid = Uuid.v7At(1_645_557_742_000);
    try std.testing.expectEqual(uuid.getVersionNum(), 7);
    // Check timestamp prefix (first 6 bytes)
    const expected_prefix: [6]u8 = .{
        0x01, 0x7f, 0x22, 0xe2, 0x79, 0xb0, // should match fixed timestamp
    };
    try std.testing.expectEqualSlices(u8, &expected_prefix, uuid.bytes[0..6]);
    try std.testing.expectEqual(1_645_557_742_000, uuid.getMillis().?);
}

test "Uuid.v7AtWithRng produces unique Uuids" {
    var prng = std.Random.DefaultPrng.init(12345);
    const rng = prng.random();
    const uuid1 = Uuid.v7WithRng(rng);
    const uuid2 = Uuid.v7WithRng(rng);
    const uuid1_str = uuid1.toString();
    const uuid2_str = uuid2.toString();
    // Get last 12 hex digits (final 6 bytes) - this is usually at the end of the string
    const uuid1_random_suffix = uuid1_str[24..];
    const uuid2_random_suffix = uuid2_str[24..];

    try std.testing.expectEqualStrings("8a82def8a568", uuid1_random_suffix);
    try std.testing.expectEqualStrings("a2fce6db8d69", uuid2_random_suffix);
}

test "Uuid.v7AtWithRng produces correct Uuid" {
    var prng = std.Random.DefaultPrng.init(12345);
    const rng = prng.random();
    const uuid1 = Uuid.v7WithRngAt(1_645_557_742_000, rng);
    const uuid2 = Uuid.v7WithRngAt(1_645_557_742_000, rng);
    try std.testing.expectEqualStrings("017f22e2-79b0-72a0-8d94-8a82def8a568", &uuid1.toString());
    try std.testing.expectEqualStrings("017f22e2-79b0-7dd0-95ca-a2fce6db8d69", &uuid2.toString());
    try std.testing.expectEqual(1_645_557_742_000, uuid1.getMillis().?);
    try std.testing.expectEqual(1_645_557_742_000, uuid2.getMillis().?);
    try std.testing.expectEqual(1_645_557_742_000 * 1_000_000, uuid1.getNanos().?);
    try std.testing.expectEqual(1_645_557_742_000 * 1_000_000, uuid2.getNanos().?);
}

test "Uuid.v8 produces correct Uuid" {
    const expected_input: [16]u8 = [_]u8{
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF,
    };

    var uuid = Uuid.v8(expected_input);
    // Check version is set to 8
    try std.testing.expectEqual(8, uuid.getVersionNum());
    // Check variant is RFC 4122
    const variant_bits = uuid.bytes[8] >> 6;
    try std.testing.expectEqual(@as(u2, 0b10), variant_bits);
    // Check the rest of the bytes are as expected (version and variant adjusted)
    var expected = expected_input;
    // Set version 8 in byte 6 (i.e. upper 4 bits)
    expected[6] = (expected[6] & 0x0F) | 0x80;
    // Set variant RFC 4122 in byte 8 (i.e. upper 2 bits)
    expected[8] = (expected[8] & 0x3F) | 0x80;
    try std.testing.expectEqualSlices(u8, &expected, &uuid.bytes);
}
