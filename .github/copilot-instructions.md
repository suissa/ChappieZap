# Zig WhatsApp Protocol Buffers Demo - AI Coding Assistant Instructions

## Project Overview

This is a Zig project that demonstrates Protocol Buffers (protobuf) usage with WhatsApp message definitions. The project showcases encoding/decoding of WhatsApp protocol buffer messages, particularly focusing on device identity structures.

## Architecture

### Core Components

- **`src/main.zig`**: Executable entry point that calls library functions
- **`src/root.zig`**: Library module containing protobuf demonstration functions
- **`src/gen/whatsapp.pb.zig`**: Auto-generated protobuf structs from WhatsApp proto definitions
- **`proto/whatsapp.proto`**: WhatsApp protocol buffer definitions (4783+ lines)
- **`build.zig`**: Build configuration with protobuf generation step
- **`build.zig.zon`**: Dependencies (zig-protobuf library)

### Key Technologies

- **Zig 0.15.1**: Compiler with specific Io.Writer interface changes
- **zig-protobuf**: Protocol Buffers implementation (Arwalk/zig-protobuf)
- **WhatsApp Proto Definitions**: Comprehensive message schemas for WhatsApp protocol

## Build System

### Commands

```bash
zig build          # Build the project
zig build gen-proto # Generate protobuf code from .proto files
zig build run      # Build and run the executable
zig build test     # Run all tests
```

### Build Configuration

- Uses `std.Io.Writer.Allocating` for protobuf encoding (Zig 0.15.1 compatibility)
- Uses `std.Io.Reader.fixed` for protobuf decoding
- Protobuf generation via `protobuf.RunProtocStep`

## Development Workflow

### Adding New Protobuf Messages

1. Add message definitions to `proto/whatsapp.proto`
2. Run `zig build gen-proto` to regenerate code
3. Import generated structs in `src/root.zig`
4. Add demonstration functions following the `demonstrateProtobuf` pattern

### Testing Protocol

1. Create test data structures in test functions
2. Use `std.Io.Writer.Allocating` for encoding
3. Use `std.Io.Reader.fixed` for decoding
4. Compare original vs decoded fields for validation

## Code Patterns & Conventions

### Protobuf Usage

```zig
// Encoding
var writer = std.Io.Writer.Allocating.init(allocator);
defer writer.deinit();
try message.encode(&writer.writer, allocator);
const encoded_data = writer.written();

// Decoding
var reader: std.Io.Reader = .fixed(encoded_data);
var decoded = try MessageType.decode(&reader, allocator);
defer decoded.deinit(allocator);
```

### Hex Output Display

```zig
// Modern hex printing (Zig 0.15.1+)
try stdout.printHex(encoded_data, .lower);
```

### Memory Management

- Use `std.heap.page_allocator` for demonstrations
- Use `std.testing.allocator` for tests
- Always call `deinit()` on decoded messages
- Use `defer` for cleanup in demonstration functions

## Zig 0.15.1 Compatibility Workarounds

### Io.Writer Interface Changes

- **Before**: `std.io.Writer` with `write` method
- **Zig 0.15.1**: `std.Io.Writer` with `writer` field containing the actual writer
- **Workaround**: Use `std.Io.Writer.Allocating` and access via `&writer.writer`

### Reader Interface Changes

- **Before**: `std.io.Reader` with `read` method
- **Zig 0.15.1**: `std.Io.Reader` with different interface
- **Workaround**: Use `std.Io.Reader.fixed(encoded_data)` for byte arrays

### Protobuf Library Compatibility

- Uses forked zig-protobuf from `zig-master` branch
- Removes `cwd` parameters from build steps (not needed in Zig 0.15.1)
- Uses `std.Io.Writer.Allocating` instead of `std.io.Writer`

## Common Issues & Solutions

### Runtime Issues

1. **Memory leaks**: Always call `deinit()` on protobuf messages
2. **Reader errors**: Ensure encoded data is valid before creating fixed reader
3. **Hex display**: Use `std.Io.Writer.printHex(bytes, .lower)` for modern hex output

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
├── build.zig           # Build configuration
├── build.zig.zon       # Dependencies
├── proto/
│   └── whatsapp.proto  # Protocol definitions
├── src/
│   ├── main.zig        # Executable entry
│   ├── root.zig        # Library functions
│   └── gen/
│       └── whatsapp.pb.zig  # Generated code
└── zig-out/            # Build artifacts
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
- Add fuzz testing for message parsing</content>
<parameter name="filePath">/home/jlucaso/projects/zigwhats/.github/copilot-instructions.md