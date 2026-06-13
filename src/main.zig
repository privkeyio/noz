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
    \\  sync <src> <dst> [filters..] NIP-77 reconcile src's events into dst
    \\
    \\event flags: --sec <hex|nsec>  -c <content>  -k <kind>  --ts <unix>  --pow <bits>  --auth
    \\             -t <name[=value]>  -p <pubkey>  -e <id>  -d <value> (all repeatable)  (no url = sign only)
    \\req/count flags: -k <kind>  -a <author>  -i <id>  -l <limit>  -t <name=value>  -p/-e/-d <value>  -s <since>  -u <until>  --search <text>
    \\
    \\The secret for key/event can also be set via NOSTR_SECRET_KEY instead of --sec/<seckey>.
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
    const env_sec = init.environ_map.get("NOSTR_SECRET_KEY");

    if (std.mem.eql(u8, cmd, "key")) {
        try cmdKey(env_sec, out, rest);
    } else if (std.mem.eql(u8, cmd, "event")) {
        try cmdEvent(env_sec, arena, out, rest);
    } else if (std.mem.eql(u8, cmd, "req")) {
        try cmdReq(io, arena, out, rest);
    } else if (std.mem.eql(u8, cmd, "count")) {
        try cmdCount(arena, out, rest);
    } else if (std.mem.eql(u8, cmd, "relay")) {
        try cmdRelay(io, arena, out, rest);
    } else if (std.mem.eql(u8, cmd, "sync")) {
        try cmdSync(arena, out, rest);
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "--help")) {
        try out.writeAll(usage);
    } else {
        try out.print("unknown command: {s}\n\n{s}", .{ cmd, usage });
    }
}

fn cmdKey(env_sec: ?[]const u8, out: *Io.Writer, args: []const [:0]const u8) !void {
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

    if (args.len >= 1 and std.mem.eql(u8, args[0], "public")) {
        const explicit: ?[]const u8 = if (args.len >= 2) args[1] else null;
        const sec_str = explicit orelse env_sec orelse {
            try out.writeAll("usage: noz key public <seckey> (or set NOSTR_SECRET_KEY)\n");
            return;
        };
        try nostr.init();
        defer nostr.cleanup();
        var sk: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &sk);
        decodeSecret(sec_str, &sk) catch {
            try out.print("invalid secret key: {s}\n", .{sec_str});
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

fn cmdEvent(env_sec: ?[]const u8, arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !void {
    var sec: ?[]const u8 = null;
    var content: []const u8 = "";
    var kind: i32 = 1;
    var ts: ?i64 = null;
    var pow: ?u8 = null;
    var do_auth = false;
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
            kind = std.fmt.parseInt(i32, kv, 10) catch return invalid(out, "kind", kv);
        } else if (std.mem.eql(u8, a, "--ts")) {
            i += 1;
            const tv = next(args, i) orelse return missing(out, "--ts");
            ts = std.fmt.parseInt(i64, tv, 10) catch return invalid(out, "timestamp", tv);
        } else if (std.mem.eql(u8, a, "-t")) {
            i += 1;
            const spec = next(args, i) orelse return missing(out, "-t");
            try tags.append(arena, try tagFromSpec(arena, spec));
        } else if (std.mem.eql(u8, a, "-p")) {
            i += 1;
            const pk = next(args, i) orelse return missing(out, "-p");
            try tags.append(arena, try arena.dupe([]const u8, &.{ "p", pk }));
        } else if (std.mem.eql(u8, a, "-e")) {
            i += 1;
            const id = next(args, i) orelse return missing(out, "-e");
            try tags.append(arena, try arena.dupe([]const u8, &.{ "e", id }));
        } else if (std.mem.eql(u8, a, "-d")) {
            i += 1;
            const d = next(args, i) orelse return missing(out, "-d");
            try tags.append(arena, try arena.dupe([]const u8, &.{ "d", d }));
        } else if (std.mem.eql(u8, a, "--pow")) {
            i += 1;
            const v = next(args, i) orelse return missing(out, "--pow");
            pow = std.fmt.parseInt(u8, v, 10) catch return invalid(out, "pow difficulty", v);
            if (pow.? > 32) return invalid(out, "pow difficulty", v);
        } else if (std.mem.eql(u8, a, "--auth")) {
            do_auth = true;
        } else {
            url = a;
        }
    }

    const sec_str = sec orelse env_sec orelse return missing(out, "--sec");

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
    if (pow) |p| {
        _ = builder.mine(&kp, p) catch return out.print("pow mining failed\n", .{});
    } else {
        try builder.sign(&kp);
    }

    var ev_buf: [65536]u8 = undefined;
    const ev_json = try builder.serialize(&ev_buf);

    // No relay URL: sign-only. Print the event (e.g. to build a NIP-98 header).
    const relay_url = url orelse {
        try out.print("{s}\n", .{ev_json});
        return;
    };

    var relay = try nostr.relay.Relay.init(arena, relay_url, .{ .read_timeout_ms = read_timeout_ms });
    defer relay.deinit();
    try relay.connect();
    defer relay.disconnect();

    var event = try nostr.Event.parse(ev_json);
    defer event.deinit();

    const ok_success = publishWithAuth(&relay, &event, relay_url, &kp, do_auth);

    try out.print("{s}\n", .{ev_json});
    std.debug.print("{s}\n", .{if (ok_success) "success" else "rejected"});
}

// Publish, handling NIP-42 when do_auth: an auth-required relay sends the
// challenge proactively, while an open relay sends it only after a protected
// event is rejected. Either way: authenticate when a challenge appears, then
// re-publish once. Returns the relay's final OK success flag.
fn publishWithAuth(relay: *nostr.relay.Relay, event: *const nostr.Event, url: []const u8, kp: *const nostr.Keypair, do_auth: bool) bool {
    relay.publish(event) catch return false;

    var id_hex: [65]u8 = undefined;
    event.idHex(&id_hex);

    var authed = false;
    var republished = false;
    var saw_reject = false;
    var tries: usize = 0;
    while (tries < 200) : (tries += 1) {
        var msg = (relay.receive() catch return false) orelse return false;
        defer msg.deinit();
        switch (msg.msg_type) {
            .auth => {
                if (do_auth and !authed) {
                    if (msg.subscription_id) |challenge| {
                        // Only mark authed once the auth event is actually sent; a
                        // protected publish cannot succeed without it.
                        sendAuth(relay, url, kp, challenge) catch return false;
                        authed = true;
                        // Open relay: the protected event was already rejected, so
                        // nothing else will prompt a retry. Re-publish now.
                        if (saw_reject and !republished) {
                            relay.publish(event) catch return false;
                            republished = true;
                        }
                    }
                }
            },
            .ok => {
                // For OK, subscription_id holds the event id. Ignore OKs for other
                // events (e.g. the relay's ack of our kind-22242 auth event).
                if (msg.subscription_id) |ok_id| {
                    if (!std.mem.eql(u8, ok_id, id_hex[0..64])) continue;
                }
                if (msg.success) return true;
                saw_reject = true;
                if (authed and !republished) {
                    // Auth-required relay: the challenge came first, so this is the
                    // unauthenticated publish being rejected. Retry now authed.
                    relay.publish(event) catch return false;
                    republished = true;
                } else if (do_auth and !authed and authRequired(msg.message)) {
                    // Open relay: an auth-required rejection is followed by an AUTH
                    // challenge, so keep waiting for it instead of giving up.
                    continue;
                } else {
                    return false;
                }
            },
            else => {},
        }
    }
    return false;
}

// A NIP-42 rejection carries the "auth-required:" reason prefix; treat a missing
// reason as auth-required too, since --auth signals the relay is expected to gate.
fn authRequired(message: ?[]const u8) bool {
    const m = message orelse return true;
    return std.mem.startsWith(u8, m, "auth-required:");
}

// NIP-42: sign and send a kind-22242 auth event binding the challenge and URL.
fn sendAuth(relay: *nostr.relay.Relay, url: []const u8, kp: *const nostr.Keypair, challenge: []const u8) !void {
    var b = nostr.EventBuilder{};
    _ = b.setKind(22242);
    _ = b.setContent("");
    _ = b.setCreatedAt(nostr.io.timestamp());
    const auth_tags = [_][]const []const u8{
        &.{ "relay", url },
        &.{ "challenge", challenge },
    };
    _ = b.setTags(&auth_tags);
    try b.sign(kp);

    var buf: [4096]u8 = undefined;
    const ev_json = try b.serialize(&buf);
    var ev = try nostr.Event.parse(ev_json);
    defer ev.deinit();
    try relay.authenticate(&ev);
}

const Query = struct { url: []const u8, filter: nostr.Filter };

// Parse the filter flags (-k/-a/-i/-l/-t) shared by req and count, plus the
// positional relay URL. Returns null (after printing) if the URL is missing.
fn parseQuery(arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !?Query {
    var url: ?[]const u8 = null;
    var limit: i32 = 0;
    var since: i64 = 0;
    var until: i64 = 0;
    var search: ?[]const u8 = null;
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
        } else if (std.mem.eql(u8, a, "-p")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-p");
            try tag_filters.append(arena, try singleTagFilter(arena, 'p', v));
        } else if (std.mem.eql(u8, a, "-e")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-e");
            try tag_filters.append(arena, try singleTagFilter(arena, 'e', v));
        } else if (std.mem.eql(u8, a, "-d")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-d");
            try tag_filters.append(arena, try singleTagFilter(arena, 'd', v));
        } else if (std.mem.eql(u8, a, "-s")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-s");
            since = std.fmt.parseInt(i64, v, 10) catch return invalidNull(out, "since", v);
        } else if (std.mem.eql(u8, a, "-u")) {
            i += 1;
            const v = next(args, i) orelse return missingNull(out, "-u");
            until = std.fmt.parseInt(i64, v, 10) catch return invalidNull(out, "until", v);
        } else if (std.mem.eql(u8, a, "--search")) {
            i += 1;
            search = next(args, i) orelse return missingNull(out, "--search");
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
            .since_val = since,
            .until_val = until,
            .search_str = search,
            .tag_filters = if (tag_filters.items.len > 0) tag_filters.items else null,
        },
    };
}

fn cmdReq(io: Io, arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !void {
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
                try printEventObject(io, out, msg.raw);
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
    return singleTagFilter(arena, name[0], value);
}

// A #<letter> tag filter with a single string value (e.g. -p/-e/-d).
fn singleTagFilter(arena: Allocator, letter: u8, value: []const u8) !nostr.FilterTagEntry {
    const values = try arena.alloc(nostr.TagValue, 1);
    values[0] = .{ .string = value };
    return .{ .letter = letter, .values = values };
}

fn cmdRelay(io: Io, arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !void {
    const url = if (args.len >= 1) args[0] else return missing(out, "relay url");
    const doc = nostr.nip11.fetchDocument(arena, url) catch |e| {
        try out.print("failed to fetch relay info: {s}\n", .{@errorName(e)});
        return;
    };
    try printSanitized(io, out, doc);
}

// Extract and print the event object from a ["EVENT","sub",{...}] message. The
// event object is the outermost {...}, so first-brace to last-brace is exact
// even when the content contains braces.
fn printEventObject(io: Io, out: *Io.Writer, raw: []const u8) !void {
    const start = std.mem.indexOfScalar(u8, raw, '{') orelse return;
    const end = std.mem.lastIndexOfScalar(u8, raw, '}') orelse return;
    if (end < start) return;
    try printSanitized(io, out, raw[start .. end + 1]);
}

// Print relay-supplied bytes followed by a newline. On a TTY, escape C0/C1
// control characters (keeping normal whitespace) so a hostile relay cannot
// inject terminal escape sequences.
fn printSanitized(io: Io, out: *Io.Writer, bytes: []const u8) !void {
    if (try Io.File.stdout().isTty(io)) {
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
        else => c < 0x20 or c == 0x7f,
    };
}

fn cmdSync(arena: Allocator, out: *Io.Writer, args: []const [:0]const u8) !void {
    var src: ?[]const u8 = null;
    var dst: ?[]const u8 = null;
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
            const v = next(args, i) orelse return missing(out, "-k");
            const k = std.fmt.parseInt(i32, v, 10) catch return invalid(out, "kind", v);
            try kinds.append(arena, k);
        } else if (std.mem.eql(u8, a, "-l")) {
            i += 1;
            const v = next(args, i) orelse return missing(out, "-l");
            limit = std.fmt.parseInt(i32, v, 10) catch return invalid(out, "limit", v);
        } else if (std.mem.eql(u8, a, "-a")) {
            i += 1;
            const v = next(args, i) orelse return missing(out, "-a");
            var b: [32]u8 = undefined;
            nostr.hex.decode(v, &b) catch return invalid(out, "author", v);
            try authors.append(arena, b);
        } else if (std.mem.eql(u8, a, "-i")) {
            i += 1;
            const v = next(args, i) orelse return missing(out, "-i");
            var b: [32]u8 = undefined;
            nostr.hex.decode(v, &b) catch return invalid(out, "id", v);
            try ids.append(arena, b);
        } else if (std.mem.eql(u8, a, "-t")) {
            i += 1;
            const v = next(args, i) orelse return missing(out, "-t");
            const tf = tagFilterFromSpec(arena, v) catch return invalid(out, "tag", v);
            try tag_filters.append(arena, tf);
        } else if (std.mem.startsWith(u8, a, "-")) {
            return invalid(out, "flag", a);
        } else if (src == null) {
            src = a;
        } else if (dst == null) {
            dst = a;
        } else {
            return invalid(out, "argument", a);
        }
    }

    const s = src orelse return missing(out, "source relay url");
    const d = dst orelse return missing(out, "destination relay url");

    const filter = nostr.Filter{
        .allocator = arena,
        .kinds_slice = if (kinds.items.len > 0) kinds.items else null,
        .authors_bytes = if (authors.items.len > 0) authors.items else null,
        .ids_bytes = if (ids.items.len > 0) ids.items else null,
        .limit_val = limit,
        .tag_filters = if (tag_filters.items.len > 0) tag_filters.items else null,
    };

    if (kinds.items.len == 0 and authors.items.len == 0 and ids.items.len == 0 and tag_filters.items.len == 0) {
        try out.writeAll("syncing full relay (no filter)\n");
    }

    try nostr.init();
    defer nostr.cleanup();

    const n = nostr.sync.syncRelays(arena, s, d, &filter) catch |e| {
        try out.print("sync failed: {s}\n", .{@errorName(e)});
        return;
    };
    try out.print("synced {d} events\n", .{n});
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

fn invalid(out: *Io.Writer, what: []const u8, val: []const u8) !void {
    try out.print("invalid {s}: {s}\n", .{ what, val });
}

fn invalidNull(out: *Io.Writer, what: []const u8, val: []const u8) !?Query {
    try invalid(out, what, val);
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
