const std = @import("std");
const nostr = @import("nostr");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const usage =
    \\noz - Nostr On Zig
    \\
    \\Usage: noz <command> [args]
    \\
    \\Commands:
    \\  key public <seckey>          Derive the hex public key from a hex/nsec secret
    \\  key generate                 Generate a new keypair (hex sec + pub)
    \\  event <url> --sec <k> [..]   Sign and publish an event, print it
    \\  req <url> [filters..]        Subscribe, print matching events, exit at EOSE
    \\  count <url> [filters..]      Count matching events (NIP-45)
    \\  relay <url>                  Print the NIP-11 relay information document
    \\
    \\event flags: --sec <hex|nsec>  -c <content>  -k <kind>  --ts <unix>
    \\             -t <name[=value]> (repeatable)  -p <pubkey> (repeatable)
    \\req/count flags: -k <kind>  -a <author>  -i <id>  -l <limit>  -t <name=value>
    \\
;

const read_timeout_ms = 10000;
const max_req_events = 100000;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var out_buf: [65536]u8 = undefined;
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
    } else if (std.mem.eql(u8, cmd, "event")) {
        try cmdEvent(arena, out, rest);
    } else if (std.mem.eql(u8, cmd, "req")) {
        try cmdReq(arena, out, rest);
    } else if (std.mem.eql(u8, cmd, "count")) {
        try cmdCount(arena, out, rest);
    } else if (std.mem.eql(u8, cmd, "relay")) {
        try cmdRelay(arena, out, rest);
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
        defer std.crypto.secureZero(u8, &sk);
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

fn cmdEvent(arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !void {
    var sec: ?[]const u8 = null;
    var content: []const u8 = "";
    var kind: i32 = 1;
    var ts: ?i64 = null;
    var url: ?[]const u8 = null;
    var tags: std.ArrayListUnmanaged([]const []const u8) = .empty;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--sec")) {
            i += 1;
            sec = next(args, i) orelse return missing(out, "--sec");
        } else if (std.mem.eql(u8, a, "-c")) {
            i += 1;
            content = next(args, i) orelse return missing(out, "-c");
        } else if (std.mem.eql(u8, a, "-k")) {
            i += 1;
            const kv = next(args, i) orelse return missing(out, "-k");
            kind = std.fmt.parseInt(i32, kv, 10) catch return out.print("invalid kind: {s}\n", .{kv});
        } else if (std.mem.eql(u8, a, "--ts")) {
            i += 1;
            const tv = next(args, i) orelse return missing(out, "--ts");
            ts = std.fmt.parseInt(i64, tv, 10) catch return out.print("invalid timestamp: {s}\n", .{tv});
        } else if (std.mem.eql(u8, a, "-t")) {
            i += 1;
            const spec = next(args, i) orelse return missing(out, "-t");
            try tags.append(arena, try tagFromSpec(arena, spec));
        } else if (std.mem.eql(u8, a, "-p")) {
            i += 1;
            const pk = next(args, i) orelse return missing(out, "-p");
            try tags.append(arena, try arena.dupe([]const u8, &.{ "p", pk }));
        } else {
            url = a;
        }
    }

    const relay_url = url orelse return missing(out, "relay url");
    const sec_str = sec orelse return missing(out, "--sec");

    try nostr.init();
    defer nostr.cleanup();

    var sk: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &sk);
    decodeSecret(sec_str, &sk) catch return out.print("invalid secret key\n", .{});
    var pk: [32]u8 = undefined;
    try nostr.crypto.getPublicKey(&sk, &pk);
    var kp = nostr.Keypair{ .secret_key = sk, .public_key = pk };
    defer kp.deinit();

    var builder = nostr.EventBuilder{};
    _ = builder.setKind(kind);
    _ = builder.setContent(content);
    _ = builder.setCreatedAt(ts orelse nostr.io.timestamp());
    if (tags.items.len > 0) _ = builder.setTags(tags.items);
    try builder.sign(&kp);

    var ev_buf: [65536]u8 = undefined;
    const ev_json = try builder.serialize(&ev_buf);

    var relay = try nostr.relay.Relay.init(arena, relay_url, .{ .read_timeout_ms = read_timeout_ms });
    defer relay.deinit();
    try relay.connect();
    defer relay.disconnect();

    var event = try nostr.Event.parse(ev_json);
    defer event.deinit();
    try relay.publish(&event);

    // Wait for the OK before exiting so the publish actually lands.
    var tries: usize = 0;
    while (tries < 100) : (tries += 1) {
        var msg = (try relay.receive()) orelse break;
        defer msg.deinit();
        if (msg.msg_type == .ok) break;
    }

    try out.print("{s}\n", .{ev_json});
}

const Query = struct { url: []const u8, filter: nostr.Filter };

// Parse the filter flags (-k/-a/-i/-l/-t) shared by req and count, plus the
// positional relay URL. Returns null (after printing) if the URL is missing.
fn parseQuery(arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !?Query {
    var url: ?[]const u8 = null;
    var limit: i32 = 0;
    var kinds: std.ArrayListUnmanaged(i32) = .empty;
    var authors: std.ArrayListUnmanaged([32]u8) = .empty;
    var ids: std.ArrayListUnmanaged([32]u8) = .empty;
    var tag_filters: std.ArrayListUnmanaged(nostr.FilterTagEntry) = .empty;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-k")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-k");
            const k = std.fmt.parseInt(i32, v, 10) catch return invalidNull(out, "kind", v);
            try kinds.append(arena, k);
        } else if (std.mem.eql(u8, a, "-l")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-l");
            limit = std.fmt.parseInt(i32, v, 10) catch return invalidNull(out, "limit", v);
        } else if (std.mem.eql(u8, a, "-a")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-a");
            var b: [32]u8 = undefined;
            nostr.hex.decode(v, &b) catch return invalidNull(out, "author", v);
            try authors.append(arena, b);
        } else if (std.mem.eql(u8, a, "-i")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-i");
            var b: [32]u8 = undefined;
            nostr.hex.decode(v, &b) catch return invalidNull(out, "id", v);
            try ids.append(arena, b);
        } else if (std.mem.eql(u8, a, "-t")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-t");
            const tf = tagFilterFromSpec(arena, v) catch return invalidNull(out, "tag", v);
            try tag_filters.append(arena, tf);
        } else {
            url = a;
        }
    }

    const relay_url = url orelse {
        try missing(out, "relay url");
        return null;
    };

    return .{
        .url = relay_url,
        .filter = .{
            .allocator = arena,
            .kinds_slice = if (kinds.items.len > 0) kinds.items else null,
            .authors_bytes = if (authors.items.len > 0) authors.items else null,
            .ids_bytes = if (ids.items.len > 0) ids.items else null,
            .limit_val = limit,
            .tag_filters = if (tag_filters.items.len > 0) tag_filters.items else null,
        },
    };
}

fn cmdReq(arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !void {
    const q = (try parseQuery(arena, out, args)) orelse return;

    try nostr.init();
    defer nostr.cleanup();

    var relay = try nostr.relay.Relay.init(arena, q.url, .{ .read_timeout_ms = read_timeout_ms });
    defer relay.deinit();
    try relay.connect();
    defer relay.disconnect();

    try relay.subscribe("noz", &.{q.filter});

    var seen: usize = 0;
    while (seen < max_req_events) {
        var msg = (try relay.receive()) orelse break;
        defer msg.deinit();
        switch (msg.msg_type) {
            // Extract the event object straight from the raw message text so
            // braces inside content cannot throw off the bounds.
            .event => {
                try printEventObject(out, msg.raw);
                seen += 1;
            },
            .eose, .closed => break,
            else => {},
        }
    }
}

fn cmdCount(arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !void {
    const q = (try parseQuery(arena, out, args)) orelse return;

    try nostr.init();
    defer nostr.cleanup();

    var relay = try nostr.relay.Relay.init(arena, q.url, .{ .read_timeout_ms = read_timeout_ms });
    defer relay.deinit();
    try relay.connect();
    defer relay.disconnect();

    try relay.count("noz", &.{q.filter});

    while (true) {
        var msg = (try relay.receive()) orelse break;
        defer msg.deinit();
        switch (msg.msg_type) {
            .count => {
                try out.print("{d}\n", .{msg.count orelse 0});
                break;
            },
            .closed => break,
            else => {},
        }
    }
}

// "name=value" -> ["name","value"]; "name" -> ["name"].
fn tagFromSpec(arena: Allocator, spec: []const u8) ![]const []const u8 {
    if (std.mem.indexOfScalar(u8, spec, '=')) |eq| {
        return arena.dupe([]const u8, &.{ spec[0..eq], spec[eq + 1 ..] });
    }
    return arena.dupe([]const u8, &.{spec});
}

// "t=value" -> tag filter #t with ["value"]. A single-letter name is required.
fn tagFilterFromSpec(arena: Allocator, spec: []const u8) !nostr.FilterTagEntry {
    const eq = std.mem.indexOfScalar(u8, spec, '=') orelse spec.len;
    const name = spec[0..eq];
    if (name.len != 1 or !std.ascii.isAlphabetic(name[0])) return error.InvalidTagFilter;
    const value = if (eq < spec.len) spec[eq + 1 ..] else "";
    const values = try arena.alloc(nostr.TagValue, 1);
    values[0] = .{ .string = value };
    return .{ .letter = name[0], .values = values };
}

fn cmdRelay(arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !void {
    const url = if (args.len >= 1) args[0] else return missing(out, "relay url");
    const doc = nostr.nip11.fetchDocument(arena, url) catch |e| {
        try out.print("failed to fetch relay info: {s}\n", .{@errorName(e)});
        return;
    };
    try printSanitized(out, doc);
}

// Extract and print the event object from a ["EVENT","sub",{...}] message. The
// event object is the outermost {...}, so first-brace to last-brace is exact
// even when the content contains braces.
fn printEventObject(out: *Io.Writer, raw: []const u8) !void {
    const start = std.mem.indexOfScalar(u8, raw, '{') orelse return;
    const end = std.mem.lastIndexOfScalar(u8, raw, '}') orelse return;
    if (end < start) return;
    try printSanitized(out, raw[start .. end + 1]);
}

// Print relay-supplied bytes followed by a newline. On a TTY, escape C0/C1
// control characters (keeping normal whitespace) so a hostile relay cannot
// inject terminal escape sequences.
fn printSanitized(out: *Io.Writer, bytes: []const u8) !void {
    if (std.posix.isatty(std.posix.STDOUT_FILENO)) {
        for (bytes) |c| {
            if (isControlByte(c)) {
                try out.print("\\x{x:0>2}", .{c});
            } else {
                try out.writeByte(c);
            }
        }
        try out.writeByte('\n');
    } else {
        try out.print("{s}\n", .{bytes});
    }
}

fn isControlByte(c: u8) bool {
    return switch (c) {
        '\n', '\t', '\r' => false,
        else => c < 0x20 or (c >= 0x7f and c <= 0x9f),
    };
}

fn next(args: []const [:0]const u8, i: usize) ?[]const u8 {
    if (i >= args.len) return null;
    return args[i];
}

fn missing(out: *Io.Writer, what: []const u8) !void {
    try out.print("missing required argument: {s}\n", .{what});
}

fn missingNull(out: *Io.Writer, what: []const u8) !?Query {
    try missing(out, what);
    return null;
}

fn invalidNull(out: *Io.Writer, what: []const u8, val: []const u8) !?Query {
    try out.print("invalid {s}: {s}\n", .{ what, val });
    return null;
}

// Accept a 64-char hex secret key or an nsec1 bech32 string.
fn decodeSecret(input: []const u8, out: *[32]u8) !void {
    if (input.len == 64) {
        try nostr.hex.decode(input, out);
        return;
    }
    if (std.mem.startsWith(u8, input, "nsec1")) {
        if (input.len > 200) return error.InvalidKey;
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

test tagFromSpec {
    const t = try tagFromSpec(std.testing.allocator, "t=wisptag");
    defer std.testing.allocator.free(t);
    try std.testing.expectEqualStrings("t", t[0]);
    try std.testing.expectEqualStrings("wisptag", t[1]);
    const p = try tagFromSpec(std.testing.allocator, "-");
    defer std.testing.allocator.free(p);
    try std.testing.expectEqual(@as(usize, 1), p.len);
    try std.testing.expectEqualStrings("-", p[0]);
}
