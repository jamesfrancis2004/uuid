# UUID Library for Zig
A comprehensive UUID (Universally Unique Identifier) library for Zig, supporting all standard UUID versions (1-5) and modern extensions (6-8) as defined in RFC 4122 and the draft RFC for UUIDv6, UUIDv7, and UUIDv8.

## Features
- **All UUID Versions**: Support for UUID versions 1-8
  - **v1**: Time-based with MAC address
  - **v3**: Name-based using MD5 hashing
  - **v4**: Random UUIDs using cryptographically secure randomness
  - **v5**: Name-based using SHA-1 hashing
  - **v6**: Time-ordered with MAC address (reordered timestamp for better sorting)
  - **v7**: Time-ordered with random data (millisecond precision, sortable)
  - **v8**: Custom UUIDs with user-defined data
- **Multiple Parsing Formats**: Parse UUIDs from hyphenated, simple, braced, and URN formats
- **Flexible Formatting**: Convert UUIDs to hyphenated or simple string formats
- **Timestamp Extraction**: Extract timestamps from time-based UUIDs (v1, v6, v7)
- **Comparison Operations**: Built-in comparison methods for sorting and equality checking
- **Hash Map Support**: Includes `HashContext` for use in Zig hash maps and sets
- **Zero Dependencies**: Pure Zig implementation with no external dependencies
- **Compile-Time Safety**: Leverages Zig's compile-time features for optimal performance

## Compatibility
| UUID Library Version | Zig Version |
|---------------------|-------------|
| 0.1.0               | 0.15.x      |

## Installation

### Using Zig Package Manager (Zig 0.11+)
First, fetch the package to get the hash:

```bash
zig fetch --save https://github.com/jamesfrancis2004/uuid/archive/refs/tags/v0.1.0.tar.gz
```
This will automatically add the dependency to your `build.zig.zon` file. Alternatively, you can manually add it to your `build.zig.zon`:

```zig
.{
    .name = "your-project",
    .version = "0.1.0",
    .dependencies = .{
        .uuid = .{
            .url = "https://github.com/jamesfrancis2004/uuid/archive/refs/tags/v0.1.0.tar.gz",
            .hash = "...", // Zig will provide this hash
        },
    },
}
```

Then in your `build.zig`:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Add the uuid dependency
    const uuid = b.dependency("uuid", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "your-app",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Import the uuid module
    exe.root_module.addImport("uuid", uuid.module("uuid"));

    b.installArtifact(exe);
}
```

### Manual Installation
Clone or download this repository and include it in your project:

```zig
const uuid_module = b.addModule("uuid", .{
    .root_source_file = b.path("path/to/uuid/src/uuid.zig"),
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("uuid", uuid_module);
```

## Usage

### Basic Usage

```zig
const std = @import("std");
const uuid = @import("uuid");

pub fn main() !void {
    // Generate a random UUID (v4)
    const id = uuid.Uuid.v4();
    const id_str = id.toString();
    std.debug.print("Generated UUID: {s}\n", .{id_str});

    // Parse a UUID from string
    const parsed = try uuid.Uuid.parse("550e8400-e29b-41d4-a716-446655440000");
    std.debug.print("Parsed UUID: {s}\n", .{parsed.toString()});

    // Compare UUIDs
    if (id.eql(parsed)) {
        std.debug.print("UUIDs are equal\n", .{});
    }
}
```

### UUID Version Examples

#### Version 1 (Time-based with MAC)

```zig
const node: [6]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB };
const id_v1 = uuid.Uuid.v1(node);

// Extract timestamp (in nanoseconds since Unix epoch)
if (id_v1.getNanos()) |nanos| {
    std.debug.print("Timestamp: {d} ns\n", .{nanos});
}

// Extract timestamp (in milliseconds)
if (id_v1.getMillis()) |millis| {
    std.debug.print("Timestamp: {d} ms\n", .{millis});
}

// Extract MAC address
if (id_v1.getNode()) |mac| {
    std.debug.print("MAC: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\n", 
        .{mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]});
}

// Generate v1 UUID at specific timestamp
const id_v1_at = uuid.Uuid.v1At(1_000_000_000, node);

// Set global clock sequence
uuid.Uuid.v1SetGlobalClockSeq(100);
```

#### Version 3 & 5 (Name-based)

```zig
const namespace = @import("uuid").namespace;

// v3 uses MD5
const id_v3 = uuid.Uuid.v3(&namespace.NAMESPACE_DNS, "example.org");

// v5 uses SHA-1 (preferred over v3)
const id_v5 = uuid.Uuid.v5(&namespace.NAMESPACE_URL, "https://example.org");
```

#### Version 4 (Random)

```zig
// Using cryptographically secure random
const id_v4 = uuid.Uuid.v4();

// Using custom RNG
var prng = std.Random.DefaultPrng.init(12345);
const rng = prng.random();
const id_v4_custom = uuid.Uuid.v4WithRng(rng);
```

#### Version 6 (Sortable time-based with MAC)

```zig
const node: [6]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB };

// Generate v6 UUID (reordered v1 for better database indexing)
const id_v6 = uuid.Uuid.v6(node);

// v6 UUIDs are naturally sortable by timestamp
const id_v6_1 = uuid.Uuid.v6(node);
const id_v6_2 = uuid.Uuid.v6(node);
std.debug.print("v6_2 > v6_1: {}\n", .{id_v6_2.gt(id_v6_1)});

// Generate at specific timestamp
const id_v6_at = uuid.Uuid.v6At(1_000_000_000, node);

// Set global clock sequence
uuid.Uuid.v6SetGlobalClockSeq(200);
```

#### Version 7 (Sortable time-based with random)

```zig
// Generate v7 UUID (millisecond precision, highly sortable)
const id_v7 = uuid.Uuid.v7();

// Generate at specific timestamp (milliseconds since Unix epoch)
const id_v7_at = uuid.Uuid.v7At(1_645_557_742_000);

// Using custom RNG
var prng = std.Random.DefaultPrng.init(12345);
const rng = prng.random();
const id_v7_custom = uuid.Uuid.v7WithRng(rng);
const id_v7_custom_at = uuid.Uuid.v7WithRngAt(1_645_557_742_000, rng);
```

#### Version 8 (Custom)

```zig
// Create custom UUID with your own data
const custom_data: [16]u8 = .{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
};
const id_v8 = uuid.Uuid.v8(custom_data);
// Version and variant bits are automatically set
```

### Parsing UUIDs
```zig
// Hyphenated format (standard)
const uuid1 = try uuid.Uuid.parse("550e8400-e29b-41d4-a716-446655440000");

// Simple format (no hyphens)
const uuid2 = try uuid.Uuid.parse("550e8400e29b41d4a716446655440000");

// Braced format
const uuid3 = try uuid.Uuid.parse("{550e8400-e29b-41d4-a716-446655440000}");

// URN format
const uuid4 = try uuid.Uuid.parse("urn:uuid:550e8400-e29b-41d4-a716-446655440000");

// Explicit parsing functions
const uuid5 = try uuid.Uuid.parseHyphenated("550e8400-e29b-41d4-a716-446655440000");
const uuid6 = try uuid.Uuid.parseSimple("550e8400e29b41d4a716446655440000");
```

### Formatting UUIDs
```zig
const id = uuid.Uuid.v4();

// Hyphenated format (e.g., "550e8400-e29b-41d4-a716-446655440000")
const hyphenated = id.toString();

// Simple format (e.g., "550e8400e29b41d4a716446655440000")
const simple = id.toSimpleString();

// Using std.fmt
std.debug.print("UUID: {}\n", .{id});
```

### Comparison and Sorting
```zig
const id1 = uuid.Uuid.v7();
const id2 = uuid.Uuid.v7();

// Comparison operators
if (id1.lt(id2)) {
    std.debug.print("id1 < id2\n", .{});
}
if (id1.lte(id2)) {
    std.debug.print("id1 <= id2\n", .{});
}
if (id1.gt(id2)) {
    std.debug.print("id1 > id2\n", .{});
}
if (id1.gte(id2)) {
    std.debug.print("id1 >= id2\n", .{});
}
if (id1.eql(id2)) {
    std.debug.print("id1 == id2\n", .{});
}
```

### Using UUIDs in Hash Maps
```zig
const std = @import("std");
const uuid = @import("uuid");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var map = std.HashMap(uuid.Uuid, []const u8, uuid.Uuid.HashContext, 80).init(allocator);
    defer map.deinit();

    const id = uuid.Uuid.v4();
    try map.put(id, "some value");

    if (map.get(id)) |value| {
        std.debug.print("Found: {s}\n", .{value});
    }
}
```

### Special UUIDs

```zig
// Nil UUID (all zeros)
const nil = uuid.Uuid.nil();
std.debug.print("Is nil: {}\n", .{nil.isNil()});

// Max UUID (all ones)
const max = uuid.Uuid.max();
std.debug.print("Is max: {}\n", .{max.isMax()});
```

### UUID Metadata

```zig
const id = uuid.Uuid.v4();

// Get version
if (id.getVersion()) |version| {
    std.debug.print("Version: {}\n", .{version});
}

// Get raw version number
const version_num = id.getVersionNum();

// Get variant
const variant = id.getVariant();

// Get high/low 64-bit parts
const high = id.getHighBits();
const low = id.getLowBits();
const high_low = id.getHighLowBits(); // Returns tuple

// Access raw bytes
const bytes = id.asBytes();
```

## Running Tests
Run the test suite:

```bash
zig build test
```

## Benchmarks
This library includes a benchmark suite to measure UUID generation and parsing performance.

### Running Benchmarks
The benchmark command follows this format:

```bash
zig build bench -- <iterations> <version>
```

Where:
- `<iterations>`: Number of UUIDs to generate/parse
- `<version>`: One of: `v1`, `v3`, `v4`, `v5`, `v6`, `v7`, `parseString`

### Benchmark Examples

```bash
# Benchmark v4 (random) generation - 10 million UUIDs
zig build bench -- 10000000 v4

# Benchmark v7 (sortable) generation - 10 million UUIDs
zig build bench -- 10000000 v7

# Benchmark v1 (time-based) generation - 10 million UUIDs
zig build bench -- 10000000 v1

# Benchmark parsing from string - 10 million parses
zig build bench -- 10000000 parseString

# Benchmark v3 (MD5 name-based) - 1 million UUIDs
zig build bench -- 1000000 v3

# Benchmark v5 (SHA-1 name-based) - 1 million UUIDs
zig build bench -- 1000000 v5
```

### Example Benchmark Output
```
v7: 10000000 UUIDs in 234ms
v4: 10000000 UUIDs in 312ms
parseString: 10000000 UUIDs in 156ms
```

### Interpreting Results
The benchmarks measure raw throughput for each operation:
- **v1/v6**: Time-based generation with MAC address (includes counter management)
- **v3/v5**: Name-based hashing (MD5 and SHA-1 respectively)
- **v4**: Random UUID generation using cryptographic RNG
- **v7**: Time-ordered sortable UUIDs with random data
- **parseString**: Parsing hyphenated UUID strings

## API Reference
### Core Types
#### `Uuid`
The main UUID type, represented as 16 bytes internally.

#### `Version` (enum)
- `Nil` (0): Nil UUID
- `Mac` (1): Time-based with MAC
- `Dce` (2): DCE Security
- `Md5` (3): Name-based with MD5
- `Random` (4): Random
- `Sha1` (5): Name-based with SHA-1
- `SortMac` (6): Time-ordered with MAC
- `SortRand` (7): Time-ordered with random
- `Custom` (8): Custom
- `Max` (0xFF): Max UUID

#### `Variant` (enum)
- `Ncs`: Reserved for NCS compatibility
- `Rfc4122`: Standard RFC 4122 variant
- `Microsoft`: Reserved for Microsoft
- `Future`: Reserved for future definition

### Generation Methods
- `v1(node: [6]u8) Uuid`
- `v1At(nanos: i128, node: [6]u8) Uuid`
- `v1WithCount(count: u14, node: [6]u8) Uuid`
- `v1WithCountAt(nanos: i128, count: u14, node: [6]u8) Uuid`
- `v1SetGlobalClockSeq(clockSeq: u14) void`
- `v3(namespace: *const Uuid, name: []const u8) Uuid`
- `v4() Uuid`
- `v4WithRng(rng: std.Random) Uuid`
- `v5(namespace: *const Uuid, name: []const u8) Uuid`
- `v6(node: [6]u8) Uuid`
- `v6At(nanos: i128, node: [6]u8) Uuid`
- `v6WithCount(count: u14, node: [6]u8) Uuid`
- `v6WithCountAt(nanos: i128, count: u14, node: [6]u8) Uuid`
- `v6SetGlobalClockSeq(clockSeq: u14) void`
- `v7() Uuid`
- `v7At(millis: i64) Uuid`
- `v7WithRng(rng: std.Random) Uuid`
- `v7WithRngAt(millis: i64, rng: std.Random) Uuid`
- `v8(bytes: [16]u8) Uuid`

### Parsing Methods
- `parse(buf: []const u8) Error!Uuid`
- `parseHyphenated(buf: []const u8) Error!Uuid`
- `parseSimple(buf: []const u8) Error!Uuid`

### Formatting Methods
- `toString() [36]u8`
- `toSimpleString() [32]u8`
- `format(writer: *std.Io.Writer) !void`

### Comparison Methods
- `eql(other: Uuid) bool`
- `gt(other: Uuid) bool`
- `gte(other: Uuid) bool`
- `lt(other: Uuid) bool`
- `lte(other: Uuid) bool`

### Metadata Methods
- `getVersion() ?Version`
- `getVersionNum() u64`
- `getVariant() Variant`
- `getNanos() ?i128`
- `getMillis() ?i64`
- `getNode() ?[6]u8`
- `getCounter() ?u14`

### Utility Methods
- `nil() Uuid`
- `max() Uuid`
- `isNil() bool`
- `isMax() bool`
- `init(high: comptime_int, low: comptime_int) Uuid`
- `fromBytes(bytes: [16]u8) Uuid`
- `asBytes() *const [16]u8`
- `getHighBits() u64`
- `getLowBits() u64`
- `getHighLowBits() struct { u64, u64 }`

## Standard Namespaces
The library provides standard namespace UUIDs as defined in RFC 4122:

```zig
const namespace = @import("uuid").namespace;

// Available namespaces:
namespace.NAMESPACE_DNS   
namespace.NAMESPACE_URL   
namespace.NAMESPACE_OID   
namespace.NAMESPACE_X500  
```

## License
MIT License

## Contributing
Contributions are welcome! Please submit pull requests or open issues on the project repository.

## Resources
- [RFC 4122: A Universally Unique IDentifier (UUID) URN Namespace](https://tools.ietf.org/html/rfc4122)
- [Draft RFC: UUID Version 6, 7, and 8](https://datatracker.ietf.org/doc/html/draft-peabody-dispatch-new-uuid-format)