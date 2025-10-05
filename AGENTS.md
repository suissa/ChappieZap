# Zig WhatsApp Binary Protocol Implementation - AI Coding Assistant Instructions

## Project Overview

This is a Zig project that implements the WhatsApp binary protocol from scratch. The project provides a complete, memory-safe implementation of WhatsApp's binary message encoding/decoding, including varint encoding, token-based compression, and hierarchical node structures. Originally focused on Protocol Buffers, it has evolved into a comprehensive binary protocol library.

## Architecture

### Core Components

- **`src/main.zig`**: Executable entry point that demonstrates all protocol features
- **`src/root.zig`**: Library module containing demonstration functions for tokens, binary operations, and node encoding/decoding
- **`src/binary.zig`**: Complete binary protocol implementation with Node, Attribute, and I/O structures
- **`tokens.json`**: WhatsApp token dictionary for compression (loaded at runtime)
- **`build.zig`**: Build configuration
- **`build.zig.zon`**: Dependencies

### Key Technologies

- **Zig 0.15.1**: Modern Zig with proper memory safety and performance
- **Runtime Token System**: JSON-loaded token dictionary for efficient encoding
- **Hierarchical Node Structures**: XML-like elements with attributes, content, and children
- **Memory-Safe Design**: Comprehensive ownership semantics and RAII patterns

## Build System

### Commands

```bash
zig build          # Build the project
zig build run      # Build and run the executable
zig build test     # Run all tests
```

### Build Configuration

- Uses `std.heap.page_allocator` for main execution
- Uses `std.testing.allocator` for unit tests
- Comprehensive test coverage for all protocol components

## Development Workflow

### Adding New Protocol Features

1. Add new encoding/decoding functions to `src/binary.zig`
2. Update token dictionary in `tokens.json` if needed
3. Add demonstration functions in `src/root.zig`
4. Add comprehensive unit tests

### Testing Protocol

1. Create test data structures in test functions
2. Use `BinaryWriter` for encoding
3. Use `BinaryReader` for decoding
4. Compare original vs decoded data for validation

## Code Patterns & Conventions

### Binary Protocol Usage

```zig
// Encoding a node
var buffer: [1024]u8 = undefined;
var writer = binary.BinaryWriter.init(&buffer);
_ = try binary.encodeNode(&node, &writer);
const encoded = writer.getWritten();

// Decoding a node
var reader = binary.BinaryReader.init(encoded);
var decoded_node = try binary.decodeNode(&reader, allocator);
defer decoded_node.deinit();
```

### Token System

```zig
// Get token for string
const token = try getTokenForString("message");
if (token.single_byte) |single| {
    // Use single byte token
}

// Get string for token
const str = getStringForSingleByteToken(25);
```

### Memory Management

- Use `std.heap.page_allocator` for demonstrations
- Use `std.testing.allocator` for tests
- Always call `deinit()` on nodes and attributes
- Use `defer` for cleanup in demonstration functions
- Avoid double allocation of strings - transfer ownership properly

## Zig 0.15.1 Compatibility Workarounds

### Io.Writer Interface Changes

- **Before**: `std.io.Writer` with `write` method
- **Zig 0.15.1**: `std.Io.Writer` with `writer` field containing the actual writer
- **Workaround**: Use `std.Io.Writer.Allocating` and access via `&writer.writer`

### Reader Interface Changes

- **Before**: `std.io.Reader` with `read` method
- **Zig 0.15.1**: `std.Io.Reader` with different interface
- **Workaround**: Use `std.Io.Reader.fixed(encoded_data)` for byte arrays

### ArrayList API Changes

- **Before**: `ArrayList.init(allocator)` and `append(item)`
- **Zig 0.15.1**: `ArrayList.initCapacity(allocator, capacity)` and `append(allocator, item)`
- **Workaround**: Always pass allocator as first parameter to ArrayList methods

### Memory Management Patterns

- **Slice Ownership**: Use `[]const u8` for owned strings, transfer ownership to avoid double allocation
- **Attribute Storage**: Duplicate strings in `addAttribute()` to ensure proper ownership
- **Token Handling**: Duplicate token strings during decoding to avoid lifetime issues
- **Alignment Safety**: Page allocator requires page-aligned allocations; use proper allocators for different allocation sizes

## Common Issues & Solutions

### Runtime Issues

1. **Memory leaks**: Always call `deinit()` on protobuf messages
2. **Reader errors**: Ensure encoded data is valid before creating fixed reader
3. **Hex display**: Use `std.Io.Writer.printHex(bytes, .lower)` for modern hex output

### Memory Management Issues

1. **Double allocation**: Avoid duplicating strings unnecessarily; transfer ownership properly
2. **Slice lifetime**: Ensure decoded strings are properly owned by duplicating them
3. **ArrayList methods**: Always pass allocator as first parameter in Zig 0.15.1
4. **Attribute ownership**: Use `addAttribute()` which handles string duplication internally

## Testing Strategy

### Unit Tests

- Test protobuf encoding/decoding round-trips
- Validate field-by-field equality after serialization
- Use `std.testing.expectEqual` for primitive fields
- Use `std.testing.expectEqual` for enum values

### Integration Tests

- Test complete workflows (encode → decode → verify)
- Test with various message types from WhatsApp proto
- Validate hex output formatting

## File Organization

```
zigwhats/
├── AGENTS.md           # AI coding assistant instructions
├── build.zig           # Build configuration
├── build.zig.zon       # Dependencies
├── tokens.json         # WhatsApp token dictionary
├── src/
│   ├── main.zig        # Executable entry
│   ├── root.zig        # Library functions
│   └── binary.zig      # Binary protocol implementation
├── zig-out/            # Build artifacts
└── .github/
    └── copilot-instructions.md  # Additional AI assistant context
```

## Contributing Guidelines

### Code Style

- Follow Zig standard formatting (`zig fmt`)
- Use 4-space indentation
- Use descriptive variable names
- Add comments for complex protobuf operations

### Commit Messages

- Use imperative mood ("Add feature" not "Added feature")
- Reference protobuf messages by name
- Mention compatibility fixes explicitly

### Pull Request Process

1. Test all changes with `zig build test`
2. Ensure protobuf generation works with `zig build gen-proto`
3. Verify executable runs with `zig build run`
4. Update documentation if adding new message types

## Dependencies

- **zig-protobuf**: `git+https://github.com/Arwalk/zig-protobuf?ref=zig-master`
- **protoc**: Required for protobuf code generation
- **curl**: Required for downloading protobuf dependencies

## Performance Considerations

- Use `std.heap.ArenaAllocator` for complex protobuf operations
- Minimize allocations in hot paths
- Consider reusing writers/readers when possible
- Profile with `zig build --release=fast`

## Future Enhancements

- Add more WhatsApp message types
- Implement streaming protobuf operations
- Add JSON serialization support
- Create benchmarking suite for protobuf performance
- Add fuzz testing for message parsing
- Create HTML/JavaScript wrapper for WASM module testing
- Implement full protobuf functionality in WASM-compatible version
- Optimize WASM binary size with build options

## Recent Updates

### Zig 0.15.1 Compatibility ✅

- **Hex Printing**: Replaced manual hex loops with `std.fmt.format` using `{x:0>2}` format specifier
- **Io.Writer Interface**: Using `std.Io.Writer.Allocating` with `&writer.writer` access pattern
- **Io.Reader Interface**: Using `std.Io.Reader.fixed(encoded_data)` for byte arrays

### WebAssembly Compilation ✅

- **Rollup-Zigar Integration**: Implemented clean WASM development using rollup-plugin-zigar
- **Pure Zig Code**: Removed manual WASM exports, using regular Zig functions with automatic binding
- **Simplified Workflow**: Single `npm run build` command creates JavaScript with embedded WASM
- **Automatic Memory Management**: Zigar handles memory allocation and string conversion automatically

### Binary Protocol Implementation ✅

- **Complete Node Encoding/Decoding**: Full support for hierarchical XML-like structures with attributes, content, and children
- **Token-Based Compression**: Runtime-loaded WhatsApp token dictionary for efficient encoding
- **Memory-Safe Design**: Comprehensive ownership semantics with proper RAII patterns
- **ArrayList Compatibility**: Fixed Zig 0.15.1 ArrayList API changes (initCapacity, allocator parameters)
- **Comprehensive Testing**: Unit tests covering all protocol components with 100% pass rate