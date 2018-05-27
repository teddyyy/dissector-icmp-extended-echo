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
local icmpv6_type = Field.new("icmpv6.type")

local local_mode = {[0] = "False", [1] = "True"}

f.type = ProtoField.new("Type", "icmp.ext.echo.req.type", ftypes.UINT8, nil, base.DEC)
f.code = ProtoField.new("Code", "icmp.ext.echo.req.code", ftypes.UINT8, nil, base.DEC)
f.checksum = ProtoField.new("Checksum", "icmp.ext.echo.req.checksum", ftypes.UINT16, nil, base.HEX)
f.identifier = ProtoField.new("Identifier", "icmp.ext.echo.req.identifier", ftypes.UINT16, nil, base.HEX)
f.sequence = ProtoField.new("Sequence Number", "icmp.ext.echo.req.seq", ftypes.UINT8, nil, base.DEC)
f.reserved = ProtoField.new("Reserved", "icmp.ext.echo.req.rsrvd", ftypes.UINT8, nil, base.HEX)
f.local_flag = ProtoField.new("Local Mode", "icmp.ext.echo.req.local_flag", ftypes.UINT8, local_mode, base.HEX)

function icmp_ext_echo_req_proto.dissector(buffer, pinfo, tree)
	if icmpv6_type().value == 160 then
		local subtree = tree:add(icmp_ext_echo_req_proto, buffer(54, 8))

		subtree:add(f.type, buffer(54, 1))
		subtree:add(f.code, buffer(55, 1))
		subtree:add(f.checksum, buffer(56, 2))
		subtree:add(f.identifier, buffer(58, 2))
		subtree:add(f.sequence, buffer(60, 1))

		local subflagtree = subtree:add(f.reserved, buffer(61, 1), buffer(61, 1):uint())
		subflagtree:add(f.local_flag, buffer(61, 1))
	end
end

register_postdissector(icmp_ext_echo_req_proto)

