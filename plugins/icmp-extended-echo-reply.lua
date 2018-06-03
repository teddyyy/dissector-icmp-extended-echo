--
--    Wireshark Plugin for ICMP Extended Echo Reply Message
--
--    0                   1                   2                   3
--    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--    |     Type      |     Code      |          Checksum             |
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--    |           Identifier          |Sequence Number|State|Res|A|4|6|
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--

local icmp_ext_echo_reply_proto = Proto("ICMP_Extended_Echo_Reply", "ICMP Extended Echo Reply")
local f = icmp_ext_echo_reply_proto.fields
local icmp_type_f = Field.new("icmp.type")
local icmpv6_type_f = Field.new("icmpv6.type")

local type = {
    [0x2b] = "ICMP Extended Echo Reply", -- For IPv4
    [0xa1] = "ICMP Extended Echo Reply" -- For IPv6
}

local code = {
    [0] = "No Error",
    [1] = "Malformed Query",
    [2] = "No Such Interface",
    [3] = "No Such Table Entry",
    [4] = "Multiple Interfaces Satisfy Query"
}

local state = {
    [0] = "Reserved",
    [1] = "Incomplete",
    [2] = "Reachable",
    [3] = "Stale",
    [4] = "Delay",
    [5] = "Probe",
    [6] = "Failed"
}

local is_active = {[0] = "Inactive", [1] = "Active"}
local is_IPv4 = {[0] = "Inactive", [1] = "IPv4"}
local is_IPv6 = {[0] = "Inactive", [1] = "IPv6"}

f.type = ProtoField.new("Type", "icmp.ext.echo.reply.type", ftypes.UINT8, type, base.DEC)
f.code = ProtoField.new("Code", "icmp.ext.echo.reply.code", ftypes.UINT8, code, base.DEC)
f.checksum = ProtoField.new("Checksum", "icmp.ext.echo.reply.checksum", ftypes.UINT16, nil, base.HEX)
f.identifier = ProtoField.new("Identifier", "icmp.ext.echo.reply.identifier", ftypes.UINT16, nil, base.HEX)
f.sequence = ProtoField.new("Sequence Number", "icmp.ext.echo.reply.seq", ftypes.UINT8, nil, base.DEC)
f.reserved = ProtoField.new("Reserved", "icmp.ext.echo.req.rsrvd", ftypes.UINT8, nil, base.HEX)
f.state = ProtoField.new("State", "icmp.ext.echo.reply.state", ftypes.UINT8, state, base.HEX, 0xE0)
f.res = ProtoField.new("Res", "icmp.ext.echo.reply.res", ftypes.UINT8, nil, base.HEX, 0x18)
f.active_flag = ProtoField.new("Active", "icmp.ext.echo.reply.active_flag", ftypes.UINT8, is_active, base.HEX, 0x04)
f.IPv4_flag = ProtoField.new("IPv4", "icmp.ext.echo.reply.ipv4_flag", ftypes.UINT8, is_IPv4, base.HEX, 0x02)
f.IPv6_flag = ProtoField.new("IPv6", "icmp.ext.echo.reply.ipv6_flag", ftypes.UINT8, is_IPv6, base.HEX, 0x01)

function display_icmp_ext_echo_reply_proto_subtree(buffer, pinfo, tree, base_ptr)
    pinfo.cols.info = "ICMP Extended Echo Reply"
    local subtree = tree:add(icmp_ext_echo_reply_proto, buffer(base_ptr, 8))

    subtree:add(f.type, buffer(base_ptr, 1))
    subtree:add(f.code, buffer(base_ptr + 1, 1))
    subtree:add(f.checksum, buffer(base_ptr + 2, 2))
    subtree:add(f.identifier, buffer(base_ptr + 4, 2))
    subtree:add(f.sequence, buffer(base_ptr + 6, 1))

    local subflagtree = subtree:add(f.reserved, buffer(base_ptr + 7, 1), buffer(base_ptr + 7, 1):uint())
    subflagtree:add(f.state, buffer(base_ptr + 7, 1))
    subflagtree:add(f.res, buffer(base_ptr + 7, 1))
    subflagtree:add(f.active_flag, buffer(base_ptr + 7, 1))
    subflagtree:add(f.IPv4_flag, buffer(base_ptr + 7, 1))
    subflagtree:add(f.IPv6_flag, buffer(base_ptr + 7, 1))
end

function icmp_ext_echo_reply_proto.dissector(buffer, pinfo, tree)
    local icmp_ptr = 0
    if icmp_type_f() then
        if icmp_type_f().value == 43 then
            icmp_ptr = 34 -- ethernet header + IPv4 header
            display_icmp_ext_echo_reply_proto_subtree(buffer, pinfo, tree, icmp_ptr)
        end
    end
    if icmpv6_type_f() then
        if icmpv6_type_f().value == 161 then
            icmp_ptr = 54 -- ethernet header + IPv6 header
            display_icmp_ext_echo_reply_proto_subtree(buffer, pinfo, tree, icmp_ptr)
        end
    end
end

register_postdissector(icmp_ext_echo_reply_proto)