// File: 08_ebpf_packet_filter.zig
// Topic: Systems Security - High-Performance Packet Inspector & Protocol Analyzer
// Language: Zig (0.11.0+)
// Description: Implements a low-level packet buffer parser, IPv4/TCP header verification,
//              and deterministic packet filtering rules for network defense engines.

const std = @import("std");
const net = std.net;
const print = std.debug.print;

pub const PacketAction = enum {
    Pass,
    Drop,
    Inspect,
    Alert,
};

pub const ProtocolType = enum(u8) {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Unknown = 255,
};

pub const IPv4Header = struct {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source_ip: u32,
    dest_ip: u32,

    pub fn getHeaderLength(self: IPv4Header) usize {
        return @as(usize, self.version_ihl & 0x0F) * 4;
    }

    pub fn getProtocol(self: IPv4Header) ProtocolType {
        return switch (self.protocol) {
            1 => .ICMP,
            6 => .TCP,
            17 => .UDP,
            else => .Unknown,
        };
    }
};

pub const TCPHeader = struct {
    src_port: u16,
    dest_port: u16,
    sequence: u32,
    ack_number: u32,
    data_offset_reserved: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,

    pub fn getDataOffset(self: TCPHeader) usize {
        return @as(usize, (self.data_offset_reserved >> 4) & 0x0F) * 4;
    }
};

pub const PacketInspector = struct {
    allocator: std.mem.Allocator,
    total_packets: u64,
    dropped_packets: u64,
    passed_packets: u64,

    pub fn init(allocator: std.mem.Allocator) PacketInspector {
        return PacketInspector{
            .allocator = allocator,
            .total_packets = 0,
            .dropped_packets = 0,
            .passed_packets = 0,
        };
    }

    pub fn inspectPacket(self: *PacketInspector, raw_frame: []const u8) !PacketAction {
        self.total_packets += 1;

        if (raw_frame.len < @sizeOf(IPv4Header)) {
            print("[WARN] Frame shorter than minimum IPv4 header size ({d} bytes)\n", .{raw_frame.len});
            self.dropped_packets += 1;
            return PacketAction.Drop;
        }

        // Parse IPv4 Header safely using memory slice cast
        const ip_header = @ptrCast(*const IPv4Header, @alignCast(@alignOf(IPv4Header), raw_frame.ptr)).*;

        const ip_hdr_len = ip_header.getHeaderLength();
        if (raw_frame.len < ip_hdr_len) {
            print("[WARN] Frame length less than declared IP header length\n", .{});
            self.dropped_packets += 1;
            return PacketAction.Drop;
        }

        const proto = ip_header.getProtocol();
        const payload_slice = raw_frame[ip_hdr_len..];

        // Perform Rule Filtering
        if (proto == .TCP) {
            if (payload_slice.len < @sizeOf(TCPHeader)) {
                self.dropped_packets += 1;
                return PacketAction.Drop;
            }

            const tcp_hdr = @ptrCast(*const TCPHeader, @alignCast(@alignOf(TCPHeader), payload_slice.ptr)).*;
            const dest_port = std.mem.bigToNative(u16, tcp_hdr.dest_port);

            // Filter rule: Drop blocked ports (e.g., 23 Telnet, 445 SMB)
            if (dest_port == 23 or dest_port == 445) {
                print("[RULE FILTER] Dropping TCP packet targeting blocked port {d}\n", .{dest_port});
                self.dropped_packets += 1;
                return PacketAction.Drop;
            }
        }

        // Integrity Rule: Check TTL boundary anomalies
        if (ip_header.ttl < 5) {
            print("[RULE FILTER] Dropping packet with suspicious TTL value ({d})\n", .{ip_header.ttl});
            self.dropped_packets += 1;
            return PacketAction.Drop;
        }

        self.passed_packets += 1;
        return PacketAction.Pass;
    }

    pub fn printMetrics(self: *const PacketInspector) void {
        print("\n=======================================================\n", .{});
        print("      PACKET INSPECTOR & FILTER METRIC SUMMARY        \n", .{});
        print("=======================================================\n", .{});
        print("Total Packets Examined : {d}\n", .{self.total_packets});
        print("Packets Passed         : {d}\n", .{self.passed_packets});
        print("Packets Dropped        : {d}\n", .{self.dropped_packets});
        print("=======================================================\n\n", .{});
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var inspector = PacketInspector.init(allocator);

    print("Starting Low-Level Packet Filter Engine...\n\n", .{});

    // Mock RAW IPv4/TCP Frame (Synthesized valid packet bytes)
    var mock_frame = [_u8]{
        0x45, 0x00, 0x00, 0x3C, // Version/IHL, TOS, Total Length (60)
        0x1C, 0x46, 0x40, 0x00, // ID, Flags/Fragment
        0x40, 0x06, 0xB1, 0xE6, // TTL (64), Protocol (TCP=6), Checksum
        0xC0, 0xA8, 0x01, 0x64, // Src IP: 192.168.1.100
        0x0A, 0x00, 0x00, 0x01, // Dst IP: 10.0.0.1
        // TCP Header
        0x04, 0xD2, 0x00, 0x50, // Src Port (1234), Dst Port (80)
        0x00, 0x00, 0x00, 0x01, // Seq Num
        0x00, 0x00, 0x00, 0x00, // Ack Num
        0x50, 0x02, 0x72, 0x10, // Offset/Flags, Window Size
        0x00, 0x00, 0x00, 0x00, // Checksum, Urgent Ptr
    };

    // Test Case 1: Valid Packet
    const action1 = try inspector.inspectPacket(&mock_frame);
    print("Packet 1 Action: {s}\n", .{@tagName(action1)});

    // Test Case 2: Alter Frame to Target Blocked Port 23 (Telnet)
    mock_frame[21] = 23; // Modify Dst Port LSB to 23
    const action2 = try inspector.inspectPacket(&mock_frame);
    print("Packet 2 Action: {s}\n", .{@tagName(action2)});

    // Test Case 3: Alter Frame TTL to zero
    mock_frame[8] = 2; // Set TTL = 2
    const action3 = try inspector.inspectPacket(&mock_frame);
    print("Packet 3 Action: {s}\n", .{@tagName(action3)});

    inspector.printMetrics();
}