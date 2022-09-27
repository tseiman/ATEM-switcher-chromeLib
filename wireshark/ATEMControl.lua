atemctrl_protocol = Proto("ATEMControl",  "Black Magic ATEM Control Protocol")



-- ========== HEADER  =============
flags = ProtoField.uint8("atemcontrol.flags", "flags", base.HEX, nil, 0xf8)
packet_len = ProtoField.uint24("atemcontrol.length", "length", base.DEC)
session_id = ProtoField.uint16("atemcontrol.session_id", "session id", base.HEX)
ack_no = ProtoField.uint16("atemcontrol.ack_no", "ack_no", base.DEC)
unknown_id = ProtoField.uint16("atemcontrol.unknown_id", "unknown_id", base.DEC)
remote_seq_id = ProtoField.uint16("atemcontrol.remote_seq_id", "remote sequence id", base.HEX)
local_seq_id = ProtoField.uint16("atemcontrol.local_seq_id", "local sequence id", base.HEX)

-- ========== Command ===========
command_len = ProtoField.uint16("atemcontrol.command_length", "command length", base.DEC)
command_check = ProtoField.uint16("atemcontrol.command_check", "command check?", base.HEX)
command_name = ProtoField.string("atemcontrol.command_name", "command name", base.HEX)


cmdDecode_field__ver_major = ProtoField.uint16("atemcontrol._ver.major_version", "Major version", base.DEC)
cmdDecode_field__ver_minor = ProtoField.uint16("atemcontrol._ver.minor_version", "Minor version", base.DEC)

cmdDecode_field__pin = ProtoField.string("atemcontrol._ver.product_name", "Product name", base.NONE)

  -- local child, value = maintree:add_packet_field(cmdDecode_field__ver_major,buffer(offset + 8,2), ENC_UTF_8 + ENC_STRING)


-- ==============================


atemctrl_protocol.fields = {
  flags,
  packet_len,
  session_id,
  ack_no,
  unknown_id,
  remote_seq_id,
  local_seq_id,
  command_name,
  command_len,
  command_check,
  cmdDecode_field__ver_major,
  cmdDecode_field__ver_minor,
  cmdDecode_field__pin
}


-- ================= command decoding Functions ==============

function cmdDecode__ver(tree,buffer,len,offset)
  tree:add(cmdDecode_field__ver_major,buffer(offset + 8,2))
  tree:add(cmdDecode_field__ver_minor,buffer(offset + 10,2))
end

function cmdDecode__pin(tree,buffer,len,offset)
  tree:add(cmdDecode_field__pin,buffer(offset + 8,44))
end



command_decoder_lookup = {
  ["_ver"] = cmdDecode__ver,
  ["_pin"] = cmdDecode__pin
}

-- ================= dissector function ==============


function atemctrl_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = atemctrl_protocol.name


  local flags_number = bit.band(buffer(0,1):le_uint(), 0xf8)
  flags_number = bit.rshift(flags_number, 3)

  local flags_description =  get_flag_description(flags_number)
  local subtree = tree:add(atemctrl_protocol, buffer(), "ATEMControl Protocol Data (" .. flags_description .. ")" )
  local flagstree = subtree:add_le(flags, buffer(0,1))
  set_flag_description(flags_number, flagstree)


  local packet_len_number =  bit.band(buffer(0,3):uint(), 0x7FF00)
  packet_len_number = bit.rshift(packet_len_number, 8)
  subtree:add_le(packet_len, buffer(0,3), packet_len_number)

    local session_id_number =  bit.band(buffer(2,2):uint(), 0xffff)
  -- session_id_number = bit.rshift(packet_len_number, 8)
  subtree:add_le(session_id, buffer(2,2), session_id_number)

-- print("buffer length: " .. packet_len_number)

  local ack_no_number =  bit.band(buffer(4,2):uint(), 0xffff)
  subtree:add_le(ack_no, buffer(4,2), ack_no_number)

  local unknown_id_number =  bit.band(buffer(6,2):uint(), 0xffff)
  subtree:add_le(unknown_id, buffer(6,2), unknown_id_number)

  local remote_seq_id_number =  bit.band(buffer(8,2):uint(), 0xffff)
  subtree:add_le(remote_seq_id, buffer(8,2), remote_seq_id_number)

  local local_seq_id_number =  bit.band(buffer(10,2):uint(), 0xffff)
  subtree:add_le(local_seq_id, buffer(10,2), local_seq_id_number)

  if(packet_len_number <= 12) then return end

  
  local commadstree = subtree:add("Commands", buffer(12,packet_len_number - 12))


  pinfo.cols.info:set("Flags: (" .. flags_description .. ")" )


  local command_name_str = buffer(16,4):string()
  if buffer(16,1):uint() == 0 then 
    command_name_str = "--EMPTY--"
    local command_len_number =  bit.band(buffer(12,2):uint(), 0xffff)
  --  commadstree:add("[" .. command_name_str .."]", buffer(12,command_len_number)) 
    return
  end

  local command_offset = 12;

  local commands_string = "";

-- print("-------------------")

  while command_offset < packet_len_number do
 --   if buffer(command_offset + 2,1) :uint() == 0 then 
  --    command_name_str = buffer(command_offset + 5,4):string()
  --  else
      command_name_str = buffer(command_offset + 4,4):string()
      if commands_string:len() == 0 then
        commands_string = command_name_str
      else
        commands_string = commands_string .. ", " .. command_name_str
      end
  --  end

    
    local command_len_number =  bit.band(buffer(command_offset,2):uint(), 0xffff)
    local command_check_number =  bit.band(buffer(command_offset + 2,2):uint(), 0xffff)

    local cmdtree = commadstree:add("[" .. command_name_str .."]", buffer(command_offset,command_len_number)) 
    cmdtree:add(command_len,buffer(command_offset, 2), command_len_number)
    cmdtree:add(command_check,buffer(command_offset + 2, 2), command_check_number)
    cmdtree:add(command_name,buffer(command_offset + 4,4))

    local cmd_decoder = command_decoder_lookup[command_name_str];

    if cmd_decoder ~= nil then
      cmd_decoder(cmdtree,buffer,command_len_number,command_offset)
    end


    command_offset = command_offset + command_len_number
  end


  pinfo.cols.info:set("Flags: (" .. flags_description .. "); Commands: [" .. commands_string .. "]")
--  local command_len_number =  bit.band(buffer(12,2):uint(), 0xffff)
 -- local cmdtree = commadstree:add("[" .. command_name_str .."]", buffer(12,command_len_number)) 

-- local command_name_str = buffer(16,4):string()

  -- [" .. command_name_str .."]")

 



end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(9910, atemctrl_protocol)



-- ================= general Functions ==============


function set_flag_description(flags, ftree)

  if bit.band(flags, 1)   == 1  then ftree:add("Reliable: ................. Yes") else ftree:add("Reliable: ................. No") end 
  if bit.band(flags, 2)   == 2  then ftree:add("SYN: ...................... Yes") else ftree:add("SYN: ...................... No") end 
  if bit.band(flags, 4)   == 4  then ftree:add("Retransmission: ........... Yes") else ftree:add("Retransmission: ........... No") end 
  if bit.band(flags, 8)   == 8  then ftree:add("Request retransmission: ... Yes") else ftree:add("Request retransmission: ... No") end 
  if bit.band(flags, 16)  == 16 then ftree:add("ACK: ...................... Yes") else ftree:add("ACK: ...................... No") end 

end

function get_flag_description(flags)

  local flag_description = "";
  if bit.band(flags, 1)   == 1  then flag_description = flag_description .. "Reliable, " end 
  if bit.band(flags, 2)   == 2  then flag_description = flag_description .. "SYN, " end 
  if bit.band(flags, 4)   == 4  then flag_description = flag_description .. "Retransmission, " end 
  if bit.band(flags, 8)   == 8  then flag_description = flag_description .. "Request retransmission, " end 
  if bit.band(flags, 16)  == 16 then flag_description = flag_description .. "ACK, " end 

  flag_description = flag_description:sub(0, flag_description:len() - 2)

  return flag_description
end




