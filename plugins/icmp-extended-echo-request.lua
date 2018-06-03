-- 
--    Wireshark Plugin for ICMP Extended Echo Request Message
--
--    0                   1                   2                   3
--    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--    |     Type      |     Code      |          Checksum             |
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--    |           Identifier          |Sequence Number|   Reserved  |L|
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- 

local icmp_ext_echo_req_proto = Proto("ICMP_Extended_Echo_Request", "ICMP Extended Echo Request")
local f = icmp_ext_echo_req_proto.fields
local icmp_type_f = Field.new("icmp.type")
local icmpv6_type_f = Field.new("icmpv6.type")

local type = {
    [0x2a] = "ICMP Extended Echo Request", -- For IPv4
    [0xa0] = "ICMP Extended Echo Request" -- For IPv6
}

local local_mode = {[0] = "False", [1] = "True"}

f.type = ProtoField.new("Type", "icmp.ext.echo.req.type", ftypes.UINT8, type, base.DEC)
f.code = ProtoField.new("Code", "icmp.ext.echo.req.code", ftypes.UINT8, nil, base.DEC)
f.checksum = ProtoField.new("Checksum", "icmp.ext.echo.req.checksum", ftypes.UINT16, nil, base.HEX)
f.identifier = ProtoField.new("Identifier", "icmp.ext.echo.req.identifier", ftypes.UINT16, nil, base.HEX)
f.sequence = ProtoField.new("Sequence Number", "icmp.ext.echo.req.seq", ftypes.UINT8, nil, base.DEC)
f.reserved = ProtoField.new("Reserved", "icmp.ext.echo.req.rsrvd", ftypes.UINT8, nil, base.HEX)
f.local_flag = ProtoField.new("Local Mode", "icmp.ext.echo.req.local_flag", ftypes.UINT8, local_mode, base.HEX, 0x01)

function display_icmp_ext_echo_req_proto_subtree(buffer, pinfo, tree, base_ptr)
	pinfo.cols.info = "ICMP Extended Echo Request"
	local subtree = tree:add(icmp_ext_echo_req_proto, buffer(base_ptr, 8))

	subtree:add(f.type, buffer(base_ptr, 1))
	subtree:add(f.code, buffer(base_ptr + 1, 1))
	subtree:add(f.checksum, buffer(base_ptr + 2, 2))
	subtree:add(f.identifier, buffer(base_ptr + 4, 2))
	subtree:add(f.sequence, buffer(base_ptr + 6, 1))

	local subflagtree = subtree:add(f.reserved, buffer(base_ptr + 7, 1), buffer(base_ptr + 7, 1):uint())
	subflagtree:add(f.local_flag, buffer(base_ptr + 7, 1))
end

function icmp_ext_echo_req_proto.dissector(buffer, pinfo, tree)
	local icmp_ptr = 0
	if icmp_type_f() then
		if icmp_type_f().value == 42 then
			icmp_ptr = 34 -- ethernet header + IPv4 header
			display_icmp_ext_echo_req_proto_subtree(buffer, pinfo, tree, icmp_ptr)
		end
	end
	if icmpv6_type_f() then
		if icmpv6_type_f().value == 160 then
			icmp_ptr = 54 -- ethernet header + IPv6 header
			display_icmp_ext_echo_req_proto_subtree(buffer, pinfo, tree, icmp_ptr)
		end
	end
end

register_postdissector(icmp_ext_echo_req_proto)

