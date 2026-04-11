const std = @import("std");
const binary = @import("binary");
const signal = @import("signal");

/// Build the <iq type="set" xmlns="encrypt"> node for uploading prekeys.
pub fn buildUploadIq(
    allocator: std.mem.Allocator,
    iq_id: []const u8,
    identity: signal.keys.IdentityKeyPair,
    signed_prekey: signal.keys.SignedPreKey,
    prekeys: []const signal.keys.PreKey,
    registration_id: u32,
) !binary.Node {
    var iq = binary.Node.initBorrowed(allocator, "iq");
    errdefer iq.deinit();
    try iq.ensureAttributeCapacity(4);
    try iq.ensureChildCapacity(5);

    try iq.addAttributeBorrowed("id", iq_id);
    try iq.addAttributeBorrowed("type", "set");
    try iq.addAttributeBorrowed("xmlns", "encrypt");
    try iq.addAttributeBorrowed("to", "s.whatsapp.net");

    // <registration>[4-byte BE u32]</registration>
    var reg = binary.Node.initBorrowed(allocator, "registration");
    defer reg.deinit();
    var reg_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &reg_bytes, registration_id, .big);
    try reg.setContentBytes(&reg_bytes);
    try iq.addChild(&reg);

    // <type>[0x05]</type>
    var type_node = binary.Node.initBorrowed(allocator, "type");
    defer type_node.deinit();
    try type_node.setContentBytesBorrowed(&[_]u8{0x05});
    try iq.addChild(&type_node);

    // <identity>[32 bytes]</identity>
    var id_node = binary.Node.initBorrowed(allocator, "identity");
    defer id_node.deinit();
    try id_node.setContentBytes(&identity.key_pair.public);
    try iq.addChild(&id_node);

    // <skey><id/><value/><signature/></skey>
    var skey = binary.Node.initBorrowed(allocator, "skey");
    defer skey.deinit();
    try skey.ensureChildCapacity(3);
    {
        var sid = binary.Node.initBorrowed(allocator, "id");
        defer sid.deinit();
        try sid.setContentBytes(&encodePreKeyId(signed_prekey.id));
        try skey.addChild(&sid);

        var sval = binary.Node.initBorrowed(allocator, "value");
        defer sval.deinit();
        try sval.setContentBytes(&signed_prekey.key_pair.public);
        try skey.addChild(&sval);

        var ssig = binary.Node.initBorrowed(allocator, "signature");
        defer ssig.deinit();
        try ssig.setContentBytes(&signed_prekey.signature);
        try skey.addChild(&ssig);
    }
    try iq.addChild(&skey);

    // <list><key>...</key>...</list>
    var list = binary.Node.initBorrowed(allocator, "list");
    defer list.deinit();
    try list.ensureChildCapacity(prekeys.len);
    for (prekeys) |*pk| {
        var key_node = binary.Node.initBorrowed(allocator, "key");
        defer key_node.deinit();
        try key_node.ensureChildCapacity(2);

        var kid = binary.Node.initBorrowed(allocator, "id");
        defer kid.deinit();
        try kid.setContentBytes(&encodePreKeyId(pk.id));
        try key_node.addChild(&kid);

        var kval = binary.Node.initBorrowed(allocator, "value");
        defer kval.deinit();
        try kval.setContentBytesBorrowed(&pk.key_pair.public);
        try key_node.addChild(&kval);

        try list.addChild(&key_node);
    }
    try iq.addChild(&list);

    return iq;
}

/// Encode a prekey ID as 3-byte big-endian (drop MSB of u32).
fn encodePreKeyId(id: u32) [3]u8 {
    const be = std.mem.toBytes(std.mem.nativeToBig(u32, id));
    return be[1..4].*;
}

/// Parse prekey bundle from server response node.
/// The <user> node contains registration, identity, skey, key children.
pub const PreKeyBundle = struct {
    registration_id: u32,
    identity_key: [32]u8,
    signed_prekey_id: u32,
    signed_prekey_public: [32]u8,
    signed_prekey_signature: [64]u8,
    prekey_id: ?u32,
    prekey_public: ?[32]u8,
};

pub fn parsePreKeyBundle(user_node: *const binary.Node) !PreKeyBundle {
    var bundle = PreKeyBundle{
        .registration_id = 0,
        .identity_key = [_]u8{0} ** 32,
        .signed_prekey_id = 0,
        .signed_prekey_public = [_]u8{0} ** 32,
        .signed_prekey_signature = [_]u8{0} ** 64,
        .prekey_id = null,
        .prekey_public = null,
    };
    var saw_registration_id = false;
    var saw_identity_key = false;
    var saw_signed_prekey_id = false;
    var saw_signed_prekey_public = false;
    var saw_signed_prekey_signature = false;

    const children = user_node.getContentNodes() orelse return error.EmptyBundle;

    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, "registration")) {
            if (child.getContentBytes()) |bytes| {
                if (bytes.len >= 4) {
                    bundle.registration_id = std.mem.readInt(u32, bytes[0..4], .big);
                    saw_registration_id = true;
                }
            }
        } else if (std.mem.eql(u8, child.tag, "identity")) {
            if (child.getContentBytes()) |bytes| {
                if (bytes.len >= 32) {
                    bundle.identity_key = bytes[0..32].*;
                    saw_identity_key = true;
                }
            }
        } else if (std.mem.eql(u8, child.tag, "skey")) {
            if (child.getContentNodes()) |skey_children| {
                for (skey_children) |*sc| {
                    if (std.mem.eql(u8, sc.tag, "id")) {
                        if (sc.getContentBytes()) |bytes| {
                            bundle.signed_prekey_id = decodePreKeyId(bytes);
                            saw_signed_prekey_id = true;
                        }
                    } else if (std.mem.eql(u8, sc.tag, "value")) {
                        if (sc.getContentBytes()) |bytes| {
                            if (bytes.len >= 32) {
                                bundle.signed_prekey_public = bytes[0..32].*;
                                saw_signed_prekey_public = true;
                            }
                        }
                    } else if (std.mem.eql(u8, sc.tag, "signature")) {
                        if (sc.getContentBytes()) |bytes| {
                            if (bytes.len >= 64) {
                                bundle.signed_prekey_signature = bytes[0..64].*;
                                saw_signed_prekey_signature = true;
                            }
                        }
                    }
                }
            }
        } else if (std.mem.eql(u8, child.tag, "key")) {
            if (child.getContentNodes()) |key_children| {
                for (key_children) |*kc| {
                    if (std.mem.eql(u8, kc.tag, "id")) {
                        if (kc.getContentBytes()) |bytes| {
                            bundle.prekey_id = decodePreKeyId(bytes);
                        }
                    } else if (std.mem.eql(u8, kc.tag, "value")) {
                        if (kc.getContentBytes()) |bytes| {
                            if (bytes.len >= 32) bundle.prekey_public = bytes[0..32].*;
                        }
                    }
                }
            }
        }
    }

    if (!saw_registration_id or !saw_identity_key or !saw_signed_prekey_id or !saw_signed_prekey_public or !saw_signed_prekey_signature) {
        return error.IncompletePreKeyBundle;
    }
    return bundle;
}

fn decodePreKeyId(bytes: []const u8) u32 {
    if (bytes.len >= 4) return std.mem.readInt(u32, bytes[0..4], .big);
    if (bytes.len == 3) return (@as(u32, bytes[0]) << 16) | (@as(u32, bytes[1]) << 8) | @as(u32, bytes[2]);
    return 0;
}
