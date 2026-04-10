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
    var iq = try binary.Node.init(allocator, "iq");
    errdefer iq.deinit();

    try iq.addAttribute("id", iq_id);
    try iq.addAttribute("type", "set");
    try iq.addAttribute("xmlns", "encrypt");
    try iq.addAttribute("to", "s.whatsapp.net");

    // <registration>[4-byte BE u32]</registration>
    var reg = try binary.Node.init(allocator, "registration");
    defer reg.deinit();
    var reg_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &reg_bytes, registration_id, .big);
    try reg.setContentBytes(&reg_bytes);
    try iq.addChild(&reg);

    // <type>[0x05]</type>
    var type_node = try binary.Node.init(allocator, "type");
    defer type_node.deinit();
    try type_node.setContentBytes(&[_]u8{0x05});
    try iq.addChild(&type_node);

    // <identity>[32 bytes]</identity>
    var id_node = try binary.Node.init(allocator, "identity");
    defer id_node.deinit();
    try id_node.setContentBytes(&identity.key_pair.public);
    try iq.addChild(&id_node);

    // <skey><id/><value/><signature/></skey>
    var skey = try binary.Node.init(allocator, "skey");
    defer skey.deinit();
    {
        var sid = try binary.Node.init(allocator, "id");
        defer sid.deinit();
        try sid.setContentBytes(&encodePreKeyId(signed_prekey.id));
        try skey.addChild(&sid);

        var sval = try binary.Node.init(allocator, "value");
        defer sval.deinit();
        try sval.setContentBytes(&signed_prekey.key_pair.public);
        try skey.addChild(&sval);

        var ssig = try binary.Node.init(allocator, "signature");
        defer ssig.deinit();
        try ssig.setContentBytes(&signed_prekey.signature);
        try skey.addChild(&ssig);
    }
    try iq.addChild(&skey);

    // <list><key>...</key>...</list>
    var list = try binary.Node.init(allocator, "list");
    defer list.deinit();
    for (prekeys) |*pk| {
        var key_node = try binary.Node.init(allocator, "key");
        defer key_node.deinit();

        var kid = try binary.Node.init(allocator, "id");
        defer kid.deinit();
        try kid.setContentBytes(&encodePreKeyId(pk.id));
        try key_node.addChild(&kid);

        var kval = try binary.Node.init(allocator, "value");
        defer kval.deinit();
        try kval.setContentBytes(&pk.key_pair.public);
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
        .identity_key = undefined,
        .signed_prekey_id = 0,
        .signed_prekey_public = undefined,
        .signed_prekey_signature = undefined,
        .prekey_id = null,
        .prekey_public = null,
    };

    const children = user_node.getContentNodes() orelse return error.EmptyBundle;

    for (children) |*child| {
        if (std.mem.eql(u8, child.tag, "registration")) {
            if (child.getContentBytes()) |bytes| {
                if (bytes.len >= 4) bundle.registration_id = std.mem.readInt(u32, bytes[0..4], .big);
            }
        } else if (std.mem.eql(u8, child.tag, "identity")) {
            if (child.getContentBytes()) |bytes| {
                if (bytes.len >= 32) bundle.identity_key = bytes[0..32].*;
            }
        } else if (std.mem.eql(u8, child.tag, "skey")) {
            if (child.getContentNodes()) |skey_children| {
                for (skey_children) |*sc| {
                    if (std.mem.eql(u8, sc.tag, "id")) {
                        if (sc.getContentBytes()) |bytes| {
                            bundle.signed_prekey_id = decodePreKeyId(bytes);
                        }
                    } else if (std.mem.eql(u8, sc.tag, "value")) {
                        if (sc.getContentBytes()) |bytes| {
                            if (bytes.len >= 32) bundle.signed_prekey_public = bytes[0..32].*;
                        }
                    } else if (std.mem.eql(u8, sc.tag, "signature")) {
                        if (sc.getContentBytes()) |bytes| {
                            if (bytes.len >= 64) bundle.signed_prekey_signature = bytes[0..64].*;
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

    return bundle;
}

fn decodePreKeyId(bytes: []const u8) u32 {
    if (bytes.len >= 4) return std.mem.readInt(u32, bytes[0..4], .big);
    if (bytes.len == 3) return (@as(u32, bytes[0]) << 16) | (@as(u32, bytes[1]) << 8) | @as(u32, bytes[2]);
    return 0;
}
