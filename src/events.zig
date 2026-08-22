const binary = @import("binary");

/// Events dispatched to the user's event handler.
pub const Event = union(enum) {
    /// QR code ready to display for pairing.
    qr_code: QrCode,
    /// 8-character pairing code for phone number linking.
    pairing_code: PairingCode,
    /// Device successfully paired.
    pair_success: PairSuccess,
    /// Client fully connected and ready.
    connected: Connected,
    /// Incoming message.
    message: Message,
    /// Client disconnected.
    disconnected: void,
    /// Login failed.
    login_failed: void,

    pub const QrCode = struct {
        /// Comma-separated: ref,noise_pub_b64,identity_pub_b64,adv_secret_b64
        code: []const u8,
    };

    pub const PairingCode = struct {
        /// 8-character raw pairing code (e.g. "ABCDEFGH")
        code: []const u8,
        /// Formatted code (e.g. "ABCD-EFGH")
        formatted_code: []const u8,
        /// Phone number linked
        phone: []const u8,
    };

    pub const PairSuccess = struct {
        phone_jid: []const u8,
        lid: []const u8,
    };

    pub const Connected = struct {
        phone_jid: []const u8,
        lid: []const u8,
    };

    pub const Message = struct {
        /// Sender's JID
        from: []const u8,
        /// Chat JID. For self-sent device echoes this comes from `recipient`.
        chat: []const u8,
        /// Message ID
        id: []const u8,
        /// The full message node (user can inspect children)
        node: *const binary.Node,
        /// Decrypted text body (null if not decrypted or no text content)
        body: ?[]const u8 = null,

        /// Get text body: decrypted body if available, otherwise raw node content
        pub fn getBody(self: Message) ?[]const u8 {
            if (self.body) |b| return b;
            return self.node.getContentBytes();
        }
    };
};

/// Event handler function type.
/// Called for each event with a pointer to the client for sending replies.
pub const EventHandler = *const fn (event: Event, ctx: *anyopaque) void;
