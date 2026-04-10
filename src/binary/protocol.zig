const node_codec = @import("node_codec.zig");
const jid_wire = @import("jid_wire.zig");

pub const writeString = jid_wire.writeString;
pub const encodeString = jid_wire.encodeString;
pub const decodeString = jid_wire.decodeString;
pub const encodeJid = jid_wire.encodeJid;
pub const decodeJid = jid_wire.decodeJid;
pub const encodeJidStruct = jid_wire.encodeJidStruct;
pub const decodeJidStruct = jid_wire.decodeJidStruct;
pub const isJidAttributeKey = jid_wire.isJidAttributeKey;

pub const encodeNode = node_codec.encodeNode;
pub const decodeNode = node_codec.decodeNode;
pub const decodeNodeBorrowingInput = node_codec.decodeNodeBorrowingInput;
pub const encodeNodeList = node_codec.encodeNodeList;
pub const decodeNodeList = node_codec.decodeNodeList;
pub const decodeNodeListBorrowingInput = node_codec.decodeNodeListBorrowingInput;
