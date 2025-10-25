const types = @import("types.zig");
pub const Uuid = types.Uuid;
pub const Version = types.Version;
pub const Variant = types.Variant;
pub const namespace = @import("namespace.zig");

test "main tests" {
    _ = types;
}
