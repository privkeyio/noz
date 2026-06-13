const std = @import("std");
const nostr = @import("nostr");
const Io = std.Io;

const usage =
    \\noz - Nostr On Zig
    \\
    \\Usage: noz <command> [args]
    \\
    \\Commands:
    \\  key public <seckey>   Derive the hex public key from a hex/nsec secret key
    \\  key generate          Generate a new keypair (hex sec + pub)
    \\  event <url> ...       (todo) sign and publish an event
    \\  req <url> ...         (todo) subscribe and print matching events
    \\  count <url> ...       (todo) count matching events
    \\  relay <url>           (todo) print the NIP-11 relay information document
    \\  sync <src> <dst> ...  (todo) NIP-77 reconcile src into dst
    \\
;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var out_buf: [4096]u8 = undefined;
    var out_w = Io.File.stdout().writer(io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};

    if (args.len < 2) {
        try out.writeAll(usage);
        return;
    }

    const cmd = args[1];
    const rest = args[2..];

    if (std.mem.eql(u8, cmd, "key")) {
        try cmdKey(out, rest);
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        try out.writeAll(usage);
    } else {
        try out.print("unknown command: {s}\n\n{s}", .{ cmd, usage });
    }
}

fn cmdKey(out: *Io.Writer, args: []const [:0]const u8) !void {
    if (args.len >= 1 and std.mem.eql(u8, args[0], "generate")) {
        try nostr.init();
        defer nostr.cleanup();
        var kp = nostr.Keypair.generate();
        defer kp.deinit();
        var sk_hex: [64]u8 = undefined;
        var pk_hex: [64]u8 = undefined;
        nostr.hex.encode(&kp.secret_key, &sk_hex);
        nostr.hex.encode(&kp.public_key, &pk_hex);
        try out.print("sec  {s}\npub  {s}\n", .{ sk_hex, pk_hex });
        return;
    }

    if (args.len >= 2 and std.mem.eql(u8, args[0], "public")) {
        try nostr.init();
        defer nostr.cleanup();
        var sk: [32]u8 = undefined;
        decodeSecret(args[1], &sk) catch {
            try out.print("invalid secret key: {s}\n", .{args[1]});
            return;
        };
        var pk: [32]u8 = undefined;
        try nostr.crypto.getPublicKey(&sk, &pk);
        var pk_hex: [64]u8 = undefined;
        nostr.hex.encode(&pk, &pk_hex);
        try out.print("{s}\n", .{pk_hex});
        return;
    }

    try out.writeAll("usage: noz key <public <seckey> | generate>\n");
}

// Accept a 64-char hex secret key or an nsec1 bech32 string.
fn decodeSecret(input: []const u8, out: *[32]u8) !void {
    if (input.len == 64) {
        try nostr.hex.decode(input, out);
        return;
    }
    if (std.mem.startsWith(u8, input, "nsec1")) {
        var hrp: [8]u8 = undefined;
        var data: [40]u8 = undefined;
        const r = try nostr.bech32.decode(input, &hrp, &data);
        if (r.data_len != 32) return error.InvalidKey;
        @memcpy(out, data[0..32]);
        return;
    }
    return error.InvalidKey;
}

test decodeSecret {
    var sk: [32]u8 = undefined;
    try decodeSecret("0000000000000000000000000000000000000000000000000000000000000001", &sk);
    try std.testing.expectEqual(@as(u8, 1), sk[31]);
    try std.testing.expectError(error.InvalidKey, decodeSecret("xyz", &sk));
}
