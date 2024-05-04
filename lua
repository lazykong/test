-- Lua script for Wireshark
-- This script receives packet information from C code and displays it in the Wireshark console

-- Define a function to receive packet information from C code
function packet_info(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload)
    -- Display packet information
    print("Src MAC: " .. src_mac .. ", Dst MAC: " .. dst_mac)
    print("Src IP: " .. src_ip .. ", Dst IP: " .. dst_ip)
    print("Src Port: " .. src_port .. ", Dst Port: " .. dst_port)
    print("Payload: " .. payload)
end

-- Register the function as a dissector for the custom protocol
register_postdissector("packet_info")

-- Declare the dissector function
function packet_info(buffer, pinfo, tree)
    -- Extract packet information
    src_mac = buffer(0, 6):string()
    dst_mac = buffer(6, 6):string()
    src_ip = buffer(26, 4):ipv4()
    dst_ip = buffer(30, 4):ipv4()
    src_port = buffer(34, 2):uint()
    dst_port = buffer(36, 2):uint()
    payload = buffer(54):string()

    -- Call the function to display packet information
    packet_info(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload)
end
