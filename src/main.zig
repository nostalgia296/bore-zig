const std = @import("std");
const c = std.c;

const CONTROL_PORT: u16 = 7835;
const MAX_FRAME_LENGTH: usize = 256;
const NETWORK_TIMEOUT_MS: c_int = 3000;
const Socket = c.fd_t;
const Allocator = std.mem.Allocator;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const ClientMessage = union(enum) {
    authenticate: []const u8,
    hello: u16,
    accept: [16]u8,
};

const ServerMessage = union(enum) {
    challenge: [16]u8,
    hello: u16,
    heartbeat,
    connection: [16]u8,
    error_message: []const u8,
};

const Authenticator = struct {
    key: [32]u8,

    fn init(secret: []const u8) Authenticator {
        var result: Authenticator = undefined;
        std.crypto.hash.sha2.Sha256.hash(secret, &result.key, .{});
        return result;
    }

    fn answer(self: Authenticator, challenge: [16]u8) [64]u8 {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&mac, &challenge, &self.key);
        return hexEncode(&mac);
    }

    fn validate(self: Authenticator, challenge: [16]u8, tag: []const u8) bool {
        if (tag.len != 64) return false;
        var decoded: [32]u8 = undefined;
        for (0..decoded.len) |i| {
            const hi = hexNibble(tag[i * 2]) orelse return false;
            const lo = hexNibble(tag[i * 2 + 1]) orelse return false;
            decoded[i] = (hi << 4) | lo;
        }
        var expected: [32]u8 = undefined;
        HmacSha256.create(&expected, &challenge, &self.key);
        return std.crypto.timing_safe.eql([32]u8, expected, decoded);
    }
};

const ServerState = struct {
    allocator: Allocator,
    min_port: u16,
    max_port: u16,
    bind_addr: []const u8,
    bind_tunnels: []const u8,
    auth: ?Authenticator,
    mutex: c.pthread_mutex_t = c.PTHREAD_MUTEX_INITIALIZER,
    connections: std.AutoHashMapUnmanaged([16]u8, Socket) = .empty,
};

fn log(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("bore: " ++ fmt ++ "\n", args);
}

fn writeAll(fd: Socket, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.send(fd, bytes[offset..].ptr, bytes.len - offset, c.MSG.NOSIGNAL);
        if (n < 0) return error.WriteFailed;
        if (n == 0) return error.WriteFailed;
        offset += @intCast(n);
    }
}

fn readByte(fd: Socket, byte: *u8) !bool {
    while (true) {
        const n = c.read(fd, @ptrCast(byte), 1);
        if (n == 0) return false;
        if (n == 1) return true;
        if (n < 0) return error.ReadFailed;
    }
}

fn readFrame(fd: Socket, buffer: *[MAX_FRAME_LENGTH]u8) !?[]const u8 {
    var len: usize = 0;
    while (true) {
        var byte: u8 = undefined;
        if (!try readByte(fd, &byte)) {
            if (len == 0) return null;
            return error.UnexpectedEof;
        }
        if (byte == 0) return buffer[0..len];
        if (len == buffer.len) return error.FrameTooLong;
        buffer[len] = byte;
        len += 1;
    }
}

fn sendFrame(fd: Socket, json: []const u8) !void {
    if (json.len > MAX_FRAME_LENGTH) return error.FrameTooLong;
    try writeAll(fd, json);
    try writeAll(fd, &.{0});
}

fn stringifyString(allocator: Allocator, value: []const u8) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

fn sendStringVariant(allocator: Allocator, fd: Socket, name: []const u8, value: []const u8) !void {
    const quoted = try stringifyString(allocator, value);
    defer allocator.free(quoted);
    const json = try std.fmt.allocPrint(allocator, "{{\"{s}\":{s}}}", .{ name, quoted });
    defer allocator.free(json);
    try sendFrame(fd, json);
}

fn sendNumberVariant(allocator: Allocator, fd: Socket, name: []const u8, value: u16) !void {
    const json = try std.fmt.allocPrint(allocator, "{{\"{s}\":{d}}}", .{ name, value });
    defer allocator.free(json);
    try sendFrame(fd, json);
}

fn formatUuid(allocator: Allocator, bytes: [16]u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}-{s}-{s}-{s}-{s}", .{
        std.fmt.bytesToHex(bytes[0..4], .lower),
        std.fmt.bytesToHex(bytes[4..6], .lower),
        std.fmt.bytesToHex(bytes[6..8], .lower),
        std.fmt.bytesToHex(bytes[8..10], .lower),
        std.fmt.bytesToHex(bytes[10..16], .lower),
    });
}

fn sendUuidVariant(allocator: Allocator, fd: Socket, name: []const u8, uuid: [16]u8) !void {
    const text = try formatUuid(allocator, uuid);
    defer allocator.free(text);
    try sendStringVariant(allocator, fd, name, text);
}

fn sendClientMessage(allocator: Allocator, fd: Socket, message: ClientMessage) !void {
    switch (message) {
        .authenticate => |tag| try sendStringVariant(allocator, fd, "Authenticate", tag),
        .hello => |port| try sendNumberVariant(allocator, fd, "Hello", port),
        .accept => |id| try sendUuidVariant(allocator, fd, "Accept", id),
    }
}

fn sendServerMessage(allocator: Allocator, fd: Socket, message: ServerMessage) !void {
    switch (message) {
        .challenge => |id| try sendUuidVariant(allocator, fd, "Challenge", id),
        .hello => |port| try sendNumberVariant(allocator, fd, "Hello", port),
        .heartbeat => try sendFrame(fd, "\"Heartbeat\""),
        .connection => |id| try sendUuidVariant(allocator, fd, "Connection", id),
        .error_message => |text| try sendStringVariant(allocator, fd, "Error", text),
    }
}

fn uuidFromString(text: []const u8) ![16]u8 {
    if (text.len != 36 or text[8] != '-' or text[13] != '-' or text[18] != '-' or text[23] != '-') return error.InvalidUuid;
    var result: [16]u8 = undefined;
    var source: usize = 0;
    for (0..result.len) |i| {
        if (source == 8 or source == 13 or source == 18 or source == 23) source += 1;
        const hi = hexNibble(text[source]) orelse return error.InvalidUuid;
        const lo = hexNibble(text[source + 1]) orelse return error.InvalidUuid;
        result[i] = (hi << 4) | lo;
        source += 2;
    }
    return result;
}

fn parseClientMessage(allocator: Allocator, frame: []const u8) !ClientMessage {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, frame, .{});
    defer parsed.deinit();
    return switch (parsed.value) {
        .object => |obj| blk: {
            var iterator = obj.iterator();
            const entry = iterator.next() orelse return error.InvalidMessage;
            if (iterator.next() != null) return error.InvalidMessage;
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            if (std.mem.eql(u8, key, "Hello")) break :blk .{ .hello = switch (value) { .integer => |n| std.math.cast(u16, n) orelse return error.InvalidMessage, else => return error.InvalidMessage } };
            if (std.mem.eql(u8, key, "Authenticate")) break :blk .{ .authenticate = switch (value) { .string => |s| try allocator.dupe(u8, s), else => return error.InvalidMessage } };
            if (std.mem.eql(u8, key, "Accept")) break :blk .{ .accept = try uuidFromString(switch (value) { .string => |s| s, else => return error.InvalidMessage }) };
            return error.InvalidMessage;
        },
        else => error.InvalidMessage,
    };
}

fn parseServerMessage(allocator: Allocator, frame: []const u8) !ServerMessage {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, frame, .{});
    defer parsed.deinit();
    switch (parsed.value) {
        .string => |s| {
            if (std.mem.eql(u8, s, "Heartbeat")) return .heartbeat;
            return error.InvalidMessage;
        },
        .object => |obj| {
            var iterator = obj.iterator();
            const entry = iterator.next() orelse return error.InvalidMessage;
            if (iterator.next() != null) return error.InvalidMessage;
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;
            if (std.mem.eql(u8, key, "Hello")) return .{ .hello = switch (value) { .integer => |n| std.math.cast(u16, n) orelse return error.InvalidMessage, else => return error.InvalidMessage } };
            if (std.mem.eql(u8, key, "Challenge")) return .{ .challenge = try uuidFromString(switch (value) { .string => |s| s, else => return error.InvalidMessage }) };
            if (std.mem.eql(u8, key, "Connection")) return .{ .connection = try uuidFromString(switch (value) { .string => |s| s, else => return error.InvalidMessage }) };
            if (std.mem.eql(u8, key, "Error")) return .{ .error_message = try allocator.dupe(u8, switch (value) { .string => |s| s, else => return error.InvalidMessage }) };
            return error.InvalidMessage;
        },
        else => return error.InvalidMessage,
    }
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn hexEncode(bytes: []const u8) [64]u8 {
    const digits = "0123456789abcdef";
    var result: [64]u8 = undefined;
    for (bytes, 0..) |byte, i| {
        result[i * 2] = digits[byte >> 4];
        result[i * 2 + 1] = digits[byte & 0x0f];
    }
    return result;
}

fn randomBytes(bytes: []u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.getrandom(bytes[offset..].ptr, bytes.len - offset, 0);
        if (n <= 0) return error.RandomUnavailable;
        offset += @intCast(n);
    }
}

fn newUuid() ![16]u8 {
    var result: [16]u8 = undefined;
    try randomBytes(&result);
    result[6] = (result[6] & 0x0f) | 0x40;
    result[8] = (result[8] & 0x3f) | 0x80;
    return result;
}

fn setSocketTimeout(fd: Socket, milliseconds: c_int) void {
    const timeout = c.timeval{
        .sec = @divTrunc(milliseconds, 1000),
        .usec = @mod(milliseconds, 1000) * 1000,
    };
    _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.RCVTIMEO, &timeout, @sizeOf(c.timeval));
    _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.SNDTIMEO, &timeout, @sizeOf(c.timeval));
}

fn closeSocket(fd: Socket) void {
    _ = c.close(fd);
}

fn socketFromAddressList(host: []const u8, port: u16, passive: bool, connecting: bool, allocator: Allocator) !Socket {
    const host_z = try allocator.dupeSentinel(u8, host, 0);
    defer allocator.free(host_z);
    const service = try std.fmt.allocPrintSentinel(allocator, "{d}", .{port}, 0);
    defer allocator.free(service);

    var hints: c.addrinfo = .{
        .flags = .{ .PASSIVE = passive, .NUMERICHOST = passive },
        .family = c.AF.UNSPEC,
        .socktype = c.SOCK.STREAM,
        .protocol = 0,
        .addrlen = 0,
        .canonname = null,
        .addr = null,
        .next = null,
    };
    var addresses: ?*c.addrinfo = null;
    const rc = c.getaddrinfo(host_z, service, &hints, &addresses);
    if (@intFromEnum(rc) != 0) return error.AddressResolutionFailed;
    defer c.freeaddrinfo(addresses.?);

    var current = addresses;
    while (current) |entry| : (current = entry.next) {
        const address = entry.addr orelse continue;
        const fd = c.socket(@intCast(entry.family), @intCast(entry.socktype), @intCast(entry.protocol));
        if (fd < 0) continue;

        if (connecting) {
            if (connectTimeout(fd, address, entry.addrlen)) {
                setSocketTimeout(fd, NETWORK_TIMEOUT_MS);
                return fd;
            }
            closeSocket(fd);
        } else {
            const yes: c_int = 1;
            _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.REUSEADDR, &yes, @sizeOf(c_int));
            if (c.bind(fd, address, entry.addrlen) == 0 and c.listen(fd, 128) == 0) return fd;
            closeSocket(fd);
        }
    }
    return if (connecting) error.ConnectionFailed else error.BindFailed;
}

fn connectTimeout(fd: Socket, address: *const c.sockaddr, address_len: c.socklen_t) bool {
    const old_flags = c.fcntl(fd, c.F.GETFL);
    if (old_flags < 0) return false;
    const nonblocking: c_int = @bitCast(c.O{ .NONBLOCK = true });
    if (c.fcntl(fd, c.F.SETFL, old_flags | nonblocking) < 0) return false;

    const connected = c.connect(fd, address, address_len) == 0;
    var success = connected;
    if (!connected) {
        var descriptor = c.pollfd{ .fd = fd, .events = c.POLL.OUT, .revents = 0 };
        var ready: c_int = 0;
        while (ready == 0) {
            ready = c.poll(@ptrCast(&descriptor), 1, NETWORK_TIMEOUT_MS);
            if (ready < 0) break;
            if (ready == 0) break;
        }
        if (ready > 0) {
            var socket_error: c_int = 0;
            var error_size: c.socklen_t = @sizeOf(c_int);
            success = c.getsockopt(fd, c.SOL.SOCKET, c.SO.ERROR, &socket_error, &error_size) == 0 and socket_error == 0;
        }
    }
    _ = c.fcntl(fd, c.F.SETFL, old_flags);
    return success;
}

fn connectTo(allocator: Allocator, host: []const u8, port: u16) !Socket {
    return socketFromAddressList(host, port, false, true, allocator);
}

fn bindListener(allocator: Allocator, host: []const u8, port: u16) !Socket {
    return socketFromAddressList(host, port, true, false, allocator);
}

fn listenerPort(fd: Socket) !u16 {
    var address: c.sockaddr = undefined;
    var address_len: c.socklen_t = @sizeOf(c.sockaddr);
    if (c.getsockname(fd, &address, &address_len) != 0) return error.SocketOptionFailed;
    if (address.family == c.AF.INET) {
        const ipv4: *align(@alignOf(c.sockaddr.in)) const c.sockaddr.in = @ptrCast(@alignCast(&address));
        return std.mem.readInt(u16, @ptrCast(&ipv4.port), .big);
    }
    const ipv6: *align(@alignOf(c.sockaddr.in6)) const c.sockaddr.in6 = @ptrCast(@alignCast(&address));
    return std.mem.readInt(u16, @ptrCast(&ipv6.port), .big);
}

fn readClientMessage(allocator: Allocator, fd: Socket) !?ClientMessage {
    var buffer: [MAX_FRAME_LENGTH]u8 = undefined;
    const frame = (try readFrame(fd, &buffer)) orelse return null;
    return try parseClientMessage(allocator, frame);
}

fn readServerMessage(allocator: Allocator, fd: Socket) !?ServerMessage {
    var buffer: [MAX_FRAME_LENGTH]u8 = undefined;
    const frame = (try readFrame(fd, &buffer)) orelse return null;
    return try parseServerMessage(allocator, frame);
}

fn clientHandshake(allocator: Allocator, fd: Socket, auth: Authenticator) !void {
    const challenge = switch (try readServerMessage(allocator, fd) orelse return error.UnexpectedEof) {
        .challenge => |id| id,
        else => return error.ExpectedChallenge,
    };
    const tag = auth.answer(challenge);
    try sendClientMessage(allocator, fd, .{ .authenticate = &tag });
}

fn serverHandshake(allocator: Allocator, fd: Socket, auth: Authenticator) !void {
    const challenge = try newUuid();
    try sendServerMessage(allocator, fd, .{ .challenge = challenge });
    switch (try readClientMessage(allocator, fd) orelse return error.UnexpectedEof) {
        .authenticate => |tag| {
            defer allocator.free(tag);
            if (!auth.validate(challenge, tag)) return error.InvalidSecret;
        },
        else => return error.MissingSecret,
    }
}

fn copyOneWay(src: Socket, dst: Socket) void {
    var buffer: [16384]u8 = undefined;
    while (true) {
        const n = c.read(src, &buffer, buffer.len);
        if (n <= 0) break;
        writeAll(dst, buffer[0..@intCast(n)]) catch break;
    }
    _ = c.shutdown(dst, c.SHUT.WR);
}

const CopyArgs = struct { src: Socket, dst: Socket };

fn copyThread(args: CopyArgs) void {
    copyOneWay(args.src, args.dst);
}

fn proxyBidirectional(first: Socket, second: Socket) !void {
    const thread = try std.Thread.spawn(.{}, copyThread, .{CopyArgs{ .src = first, .dst = second }});
    copyOneWay(second, first);
    thread.join();
}

fn lock(mutex: *c.pthread_mutex_t) void {
    _ = c.pthread_mutex_lock(mutex);
}

fn unlock(mutex: *c.pthread_mutex_t) void {
    _ = c.pthread_mutex_unlock(mutex);
}

fn takeConnection(state: *ServerState, id: [16]u8) ?Socket {
    lock(&state.mutex);
    defer unlock(&state.mutex);
    const removed = state.connections.fetchRemove(id) orelse return null;
    return removed.value;
}

fn expireConnection(state: *ServerState, id: [16]u8) void {
    const ts = c.timespec{ .sec = 10, .nsec = 0 };
    _ = c.nanosleep(&ts, null);
    if (takeConnection(state, id)) |fd| {
        log("removed stale connection {s}", .{formatUuid(state.allocator, id) catch "?"});
        closeSocket(fd);
    }
}

fn serverError(state: *ServerState, fd: Socket, message: []const u8) void {
    sendServerMessage(state.allocator, fd, .{ .error_message = message }) catch {};
}

fn chooseTunnelListener(state: *ServerState, requested_port: u16) !Socket {
    if (requested_port > 0) {
        if (requested_port < state.min_port or requested_port > state.max_port) return error.PortOutOfRange;
        return bindListener(state.allocator, state.bind_tunnels, requested_port);
    }
    const width: u32 = @as(u32, state.max_port) - state.min_port + 1;
    for (0..150) |_| {
        var random: [4]u8 = undefined;
        try randomBytes(&random);
        const sample = std.mem.readInt(u32, &random, .little);
        const selected: u16 = @intCast(@as(u32, state.min_port) + sample % width);
        if (bindListener(state.allocator, state.bind_tunnels, selected)) |fd| return fd else |_| {}
    }
    return error.NoAvailablePort;
}

fn handleControl(state: *ServerState, fd: Socket) void {
    defer closeSocket(fd);
    setSocketTimeout(fd, NETWORK_TIMEOUT_MS);

    if (state.auth) |auth| {
        serverHandshake(state.allocator, fd, auth) catch |err| {
            log("authentication failed: {s}", .{@errorName(err)});
            serverError(state, fd, @errorName(err));
            return;
        };
    }

    const request = readClientMessage(state.allocator, fd) catch |err| {
        log("invalid control request: {s}", .{@errorName(err)});
        return;
    } orelse return;
    switch (request) {
        .hello => |requested_port| {
            const tunnel_fd = chooseTunnelListener(state, requested_port) catch |err| {
                const message: []const u8 = if (err == error.PortOutOfRange) "client port number not in allowed range" else if (err == error.NoAvailablePort) "failed to find an available port" else "failed to bind to port";
                serverError(state, fd, message);
                return;
            };
            defer closeSocket(tunnel_fd);
            const port = listenerPort(tunnel_fd) catch {
                serverError(state, fd, "failed to read assigned port");
                return;
            };
            _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.RCVTIMEO, &c.timeval{ .sec = 0, .usec = 0 }, @sizeOf(c.timeval));
            log("new client on port {d}", .{port});
            sendServerMessage(state.allocator, fd, .{ .hello = port }) catch return;
            tunnelControlLoop(state, fd, tunnel_fd, port);
        },
        .accept => |id| {
            if (takeConnection(state, id)) |incoming| {
                defer closeSocket(incoming);
                log("forwarding connection {s}", .{formatUuid(state.allocator, id) catch "?"});
                proxyBidirectional(fd, incoming) catch {};
            } else {
                log("missing connection id", .{});
            }
        },
        .authenticate => |tag| {
            state.allocator.free(tag);
            log("unexpected authenticate message", .{});
        },
    }
}

const ControlArgs = struct { state: *ServerState, fd: Socket };

fn controlThread(args: ControlArgs) void {
    handleControl(args.state, args.fd);
}

const ExpireArgs = struct { state: *ServerState, id: [16]u8 };

fn expireThread(args: ExpireArgs) void {
    expireConnection(args.state, args.id);
}

fn tunnelControlLoop(state: *ServerState, control_fd: Socket, tunnel_fd: Socket, port: u16) void {
    while (true) {
        sendServerMessage(state.allocator, control_fd, .heartbeat) catch return;
        var descriptors = [_]c.pollfd{
            .{ .fd = tunnel_fd, .events = c.POLL.IN, .revents = 0 },
            .{ .fd = control_fd, .events = c.POLL.IN, .revents = 0 },
        };
        const ready = c.poll(&descriptors, descriptors.len, 500);
        if (ready < 0) return;
        const control_events = descriptors[1].revents;
        if ((control_events & (c.POLL.HUP | c.POLL.ERR | c.POLL.NVAL)) != 0) return;
        if ((descriptors[0].revents & c.POLL.IN) == 0) continue;

        var peer: c.sockaddr = undefined;
        var peer_len: c.socklen_t = @sizeOf(c.sockaddr);
        const incoming = c.accept(tunnel_fd, &peer, &peer_len);
        if (incoming < 0) continue;
        const id = newUuid() catch {
            closeSocket(incoming);
            continue;
        };
        lock(&state.mutex);
        const put_result = state.connections.put(state.allocator, id, incoming);
        unlock(&state.mutex);
        put_result catch {
            closeSocket(incoming);
            continue;
        };
        const expiry = std.Thread.spawn(.{}, expireThread, .{ExpireArgs{ .state = state, .id = id }}) catch {
            _ = takeConnection(state, id);
            closeSocket(incoming);
            continue;
        };
        expiry.detach();
        sendServerMessage(state.allocator, control_fd, .{ .connection = id }) catch {
            if (takeConnection(state, id)) |fd| closeSocket(fd);
            return;
        };
        log("new connection for tunnel port {d}", .{port});
    }
}

fn runServer(allocator: Allocator, min_port: u16, max_port: u16, bind_addr: []const u8, bind_tunnels: []const u8, secret: ?[]const u8) !void {
    if (min_port > max_port) return error.EmptyPortRange;
    var state = ServerState{
        .allocator = allocator,
        .min_port = min_port,
        .max_port = max_port,
        .bind_addr = bind_addr,
        .bind_tunnels = bind_tunnels,
        .auth = if (secret) |s| Authenticator.init(s) else null,
    };
    defer state.connections.deinit(allocator);

    const listener = try bindListener(allocator, bind_addr, CONTROL_PORT);
    log("server listening on {s}:{d}", .{ bind_addr, CONTROL_PORT });
    while (true) {
        const fd = c.accept(listener, null, null);
        if (fd < 0) continue;
        const thread = std.Thread.spawn(.{}, controlThread, .{ControlArgs{ .state = &state, .fd = fd }}) catch {
            closeSocket(fd);
            continue;
        };
        thread.detach();
    }
}

const ClientState = struct {
    allocator: Allocator,
    server: []const u8,
    local_host: []const u8,
    local_port: u16,
    auth: ?Authenticator,
};

fn handleClientConnection(state: *ClientState, id: [16]u8) void {
    const remote_fd = connectTo(state.allocator, state.server, CONTROL_PORT) catch |err| {
        log("could not connect for incoming stream: {s}", .{@errorName(err)});
        return;
    };
    defer closeSocket(remote_fd);
    if (state.auth) |auth| clientHandshake(state.allocator, remote_fd, auth) catch return;
    sendClientMessage(state.allocator, remote_fd, .{ .accept = id }) catch return;

    const local_fd = connectTo(state.allocator, state.local_host, state.local_port) catch |err| {
        log("could not connect to local service: {s}", .{@errorName(err)});
        return;
    };
    defer closeSocket(local_fd);
    _ = c.setsockopt(remote_fd, c.SOL.SOCKET, c.SO.RCVTIMEO, &c.timeval{ .sec = 0, .usec = 0 }, @sizeOf(c.timeval));
    _ = c.setsockopt(remote_fd, c.SOL.SOCKET, c.SO.SNDTIMEO, &c.timeval{ .sec = 0, .usec = 0 }, @sizeOf(c.timeval));
    proxyBidirectional(local_fd, remote_fd) catch {};
}

const ClientConnectionArgs = struct { state: *ClientState, id: [16]u8 };

fn clientConnectionThread(args: ClientConnectionArgs) void {
    handleClientConnection(args.state, args.id);
}

fn runClient(allocator: Allocator, local_host: []const u8, local_port: u16, server: []const u8, requested_port: u16, secret: ?[]const u8) !void {
    const control_fd = try connectTo(allocator, server, CONTROL_PORT);
    defer closeSocket(control_fd);
    const auth = if (secret) |s| Authenticator.init(s) else null;
    if (auth) |a| try clientHandshake(allocator, control_fd, a);
    try sendClientMessage(allocator, control_fd, .{ .hello = requested_port });
    const response = try readServerMessage(allocator, control_fd) orelse return error.UnexpectedEof;
    const remote_port = switch (response) {
        .hello => |port| port,
        .error_message => |message| {
            log("server error: {s}", .{message});
            return error.ServerReportedError;
        },
        .challenge => return error.ServerRequiresAuthentication,
        else => return error.UnexpectedServerMessage,
    };
    log("connected to server; listening at {s}:{d}", .{ server, remote_port });

    var state = ClientState{
        .allocator = allocator,
        .server = server,
        .local_host = local_host,
        .local_port = local_port,
        .auth = auth,
    };
    _ = c.setsockopt(control_fd, c.SOL.SOCKET, c.SO.RCVTIMEO, &c.timeval{ .sec = 0, .usec = 0 }, @sizeOf(c.timeval));
    while (true) {
        const message = try readServerMessage(allocator, control_fd) orelse return;
        switch (message) {
            .hello, .challenge => log("unexpected control message", .{}),
            .heartbeat => {},
            .connection => |id| {
                const thread = std.Thread.spawn(.{}, clientConnectionThread, .{ClientConnectionArgs{ .state = &state, .id = id }}) catch continue;
                thread.detach();
            },
            .error_message => |text| log("server error: {s}", .{text}),
        }
    }
}

fn parsePort(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10) catch error.InvalidPort;
}

fn env(name: [*:0]const u8) ?[]const u8 {
    const value = c.getenv(name) orelse return null;
    return std.mem.span(value);
}

fn optionValue(args: []const []const u8, index: *usize) ![]const u8 {
    index.* += 1;
    if (index.* >= args.len) return error.MissingOptionValue;
    return args[index.*];
}

fn printHelp() void {
    const text =
        "bore - TCP tunnel\n\n" ++
        "Usage:\n" ++
        "  bore local <LOCAL_PORT> --to <HOST> [OPTIONS]\n" ++
        "  bore server [OPTIONS]\n\n" ++
        "Local options:\n" ++
        "  -l, --local-host <HOST>   Local host to expose [default: localhost]\n" ++
        "  -t, --to <HOST>           Bore server address [env: BORE_SERVER]\n" ++
        "  -p, --port <PORT>         Requested remote port [default: 0]\n" ++
        "  -s, --secret <SECRET>     Authentication secret [env: BORE_SECRET]\n\n" ++
        "Server options:\n" ++
        "      --min-port <PORT>     Minimum tunnel port [env: BORE_MIN_PORT] [default: 1024]\n" ++
        "      --max-port <PORT>     Maximum tunnel port [env: BORE_MAX_PORT] [default: 65535]\n" ++
        "  -s, --secret <SECRET>     Authentication secret [env: BORE_SECRET]\n" ++
        "      --bind-addr <IP>      Control and default tunnel bind IP [default: 0.0.0.0]\n" ++
        "      --bind-tunnels <IP>   Tunnel listener bind IP\n\n" ++
        "  -h, --help                Print help\n" ++
        "  -V, --version             Print version\n";
    _ = c.write(1, text.ptr, text.len);
}

fn run(allocator: Allocator, args: []const []const u8) !void {
    if (args.len == 0 or std.mem.eql(u8, args[0], "help") or std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")) {
        printHelp();
        return;
    }
    if (std.mem.eql(u8, args[0], "--version") or std.mem.eql(u8, args[0], "-V")) {
        log("0.1.0", .{});
        return;
    }
    if (std.mem.eql(u8, args[0], "server")) {
        var min_port: u16 = if (env("BORE_MIN_PORT")) |s| try parsePort(s) else 1024;
        var max_port: u16 = if (env("BORE_MAX_PORT")) |s| try parsePort(s) else 65535;
        var bind_addr: []const u8 = "0.0.0.0";
        var bind_tunnels: ?[]const u8 = null;
        var secret = env("BORE_SECRET");
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return printHelp();
            if (std.mem.eql(u8, arg, "--min-port")) min_port = try parsePort(try optionValue(args, &i)) else if (std.mem.eql(u8, arg, "--max-port")) max_port = try parsePort(try optionValue(args, &i)) else if (std.mem.eql(u8, arg, "--bind-addr")) bind_addr = try optionValue(args, &i) else if (std.mem.eql(u8, arg, "--bind-tunnels")) bind_tunnels = try optionValue(args, &i) else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--secret")) secret = try optionValue(args, &i) else return error.UnknownOption;
        }
        try runServer(allocator, min_port, max_port, bind_addr, bind_tunnels orelse bind_addr, secret);
        return;
    }
    if (std.mem.eql(u8, args[0], "local")) {
        if (args.len < 2) return error.MissingLocalPort;
        const local_port = try parsePort(args[1]);
        var local_host: []const u8 = "localhost";
        var server = env("BORE_SERVER");
        var requested_port: u16 = 0;
        var secret = env("BORE_SECRET");
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return printHelp();
            if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--local-host")) local_host = try optionValue(args, &i) else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--to")) server = try optionValue(args, &i) else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) requested_port = try parsePort(try optionValue(args, &i)) else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--secret")) secret = try optionValue(args, &i) else return error.UnknownOption;
        }
        try runClient(allocator, local_host, local_port, server orelse return error.MissingServer, requested_port, secret);
        return;
    }
    return error.UnknownCommand;
}

pub fn main(init: std.process.Init) !void {
    var iterator = std.process.Args.Iterator.init(init.minimal.args);
    _ = iterator.next();
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(init.gpa);
    while (iterator.next()) |arg| try args.append(init.gpa, arg);
    run(init.gpa, args.items) catch |err| {
        log("{s}", .{@errorName(err)});
        printHelp();
        return err;
    };
}

test "authentication answer matches HMAC-SHA256 over UUID bytes" {
    const auth = Authenticator.init("secret");
    const challenge: [16]u8 = @splat(0);
    const answer = auth.answer(challenge);
    try std.testing.expect(auth.validate(challenge, &answer));
    try std.testing.expect(!auth.validate(challenge, "invalid"));
}

test "UUID round trip" {
    const id = [_]u8{ 0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00 };
    const rendered = try formatUuid(std.testing.allocator, id);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqual(id, try uuidFromString(rendered));
}

test "serde compatible client and server message frames" {
    const allocator = std.testing.allocator;
    const hello = try parseClientMessage(allocator, "{\"Hello\":8000}");
    try std.testing.expectEqual(@as(u16, 8000), hello.hello);
    const heartbeat = try parseServerMessage(allocator, "\"Heartbeat\"");
    try std.testing.expect(heartbeat == .heartbeat);
}
