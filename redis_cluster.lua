-- Redis Cluster Protocol Dissector
-- Protocol Constants
local CLUSTER_NAMELEN = 40  -- Typical Redis cluster name length
local NET_IP_STR_LEN = 46   -- Length for IP string storage
local CLUSTER_SLOTS = 16384 -- Number of hash slots in Redis Cluster

-- Protocol Definition
local redis_cluster = Proto("redis_cluster", "Redis Cluster Protocol")

-- Based on redis github, the parsing logic is taken from https://github.com/redis/redis/blob/684077682e5826ab658da975c9536df1584b425f/src/cluster_legacy.c#L2731

-- Header Fields
local fields = redis_cluster.fields
fields.signature = ProtoField.string("redis_cluster.signature", "Signature")
fields.total_length = ProtoField.uint32("redis_cluster.totlen", "Total Length", base.DEC)
fields.version = ProtoField.uint16("redis_cluster.version", "Version", base.DEC)
fields.port = ProtoField.uint16("redis_cluster.port", "Primary Port", base.DEC)
fields.msg_type = ProtoField.uint16("redis_cluster.type", "Message Type", base.DEC)
fields.count = ProtoField.uint16("redis_cluster.count", "Count", base.DEC)
fields.current_epoch = ProtoField.uint64("redis_cluster.current_epoch", "Current Epoch", base.DEC)
fields.config_epoch = ProtoField.uint64("redis_cluster.config_epoch", "Config Epoch", base.DEC)
fields.offset = ProtoField.uint64("redis_cluster.offset", "Replication Offset", base.DEC)
fields.sender = ProtoField.string("redis_cluster.sender", "Sender Node")
fields.myslots = ProtoField.bytes("redis_cluster.myslots", "My Slots")
fields.slaveof = ProtoField.string("redis_cluster.slaveof", "Slave Of")
fields.myip = ProtoField.string("redis_cluster.myip", "Sender IP")
fields.extensions = ProtoField.uint16("redis_cluster.extensions", "Extensions", base.DEC)
fields.pport = ProtoField.uint16("redis_cluster.pport", "Secondary Port", base.DEC)
fields.cport = ProtoField.uint16("redis_cluster.cport", "Cluster Bus Port", base.DEC)
fields.flags = ProtoField.uint16("redis_cluster.flags", "Flags", base.HEX)
fields.state = ProtoField.uint8("redis_cluster.state", "Cluster State", base.DEC)
fields.mflags = ProtoField.bytes("redis_cluster.mflags", "Message Flags")

-- Data Fields (for clusterMsgData)
fields.data_nodename = ProtoField.string("redis_cluster.data.nodename", "Node Name")
fields.data_ping_sent = ProtoField.uint32("redis_cluster.data.ping_sent", "Ping Sent", base.DEC)
fields.data_pong_received = ProtoField.uint32("redis_cluster.data.pong_received", "Pong Received", base.DEC)
fields.data_ip = ProtoField.string("redis_cluster.data.ip", "IP Address")
fields.data_port = ProtoField.uint16("redis_cluster.data.port", "Port", base.DEC)
fields.data_cport = ProtoField.uint16("redis_cluster.data.cport", "Cluster Port", base.DEC)
fields.data_flags = ProtoField.uint16("redis_cluster.data.flags", "Flags", base.HEX)
fields.data_pport = ProtoField.uint16("redis_cluster.data.pport", "Secondary Port", base.DEC)

-- Message Types
local MESSAGE_TYPES = {
    [0] = "Ping",
    [1] = "Pong",
    [2] = "Meet",
    [3] = "Fail",
    [4] = "Publish",
    [5] = "Failover Auth Request",
    [6] = "Failover Auth Ack",
    [7] = "Update",
    [8] = "MFStart",
    [9] = "Module",
    [10] = "PublishShard"
}

-- Node Flags
local CLUSTER_NODE_FLAGS = {
    [1] = "Master",
    [2] = "Slave",
    [4] = "PFAIL",
    [8] = "FAIL",
    [16] = "Myself",
    [32] = "Handshake",
    [64] = "No Address",
    [128] = "Meet",
    [256] = "Migrate To",
    [512] = "No Failover",
    [1024] = "Extensions Supported"
}

-- Dissector function
function redis_cluster.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 4 then return end

    -- Check signature
    local signature = buffer(0,4):string()
    if signature ~= "RCmb" then return end

    pinfo.cols.protocol = redis_cluster.name

    local subtree = tree:add(redis_cluster, buffer(), "Redis Cluster Protocol")

    -- Dissect header fields
    subtree:add(fields.signature, buffer(0,4))
    subtree:add(fields.total_length, buffer(4,4))
    subtree:add(fields.version, buffer(8,2))
    subtree:add(fields.port, buffer(10,2))
    local msg_type = buffer(12,2):uint()
    subtree:add(fields.msg_type, buffer(12,2)):append_text(" (" .. (MESSAGE_TYPES[msg_type] or "Unknown") .. ")")
    subtree:add(fields.count, buffer(14,2))
    subtree:add(fields.current_epoch, buffer(16,8))
    subtree:add(fields.config_epoch, buffer(24,8))
    subtree:add(fields.offset, buffer(32,8))
    subtree:add(fields.sender, buffer(40,CLUSTER_NAMELEN))
    subtree:add(fields.myslots, buffer(40+CLUSTER_NAMELEN,CLUSTER_SLOTS/8))
    subtree:add(fields.slaveof, buffer(40+CLUSTER_NAMELEN+CLUSTER_SLOTS/8,CLUSTER_NAMELEN))
    subtree:add(fields.myip, buffer(40+2*CLUSTER_NAMELEN+CLUSTER_SLOTS/8,NET_IP_STR_LEN))

    local offset = 40+2*CLUSTER_NAMELEN+CLUSTER_SLOTS/8+NET_IP_STR_LEN
    subtree:add(fields.extensions, buffer(offset,2))
    offset = offset + 32  -- Skip notused1[30] + extensions

    subtree:add(fields.pport, buffer(offset,2))
    subtree:add(fields.cport, buffer(offset+2,2))
    subtree:add(fields.flags, buffer(offset+4,2))
    subtree:add(fields.state, buffer(offset+6,1))
    subtree:add(fields.mflags, buffer(offset+7,3))

    -- Dissect data section based on message type
    offset = offset + 10
    if msg_type == 0 or msg_type == 1 or msg_type == 2 then  -- Ping, Pong, Meet
        local count = buffer(14,2):uint()
        local data_tree = subtree:add(redis_cluster, buffer(offset), "Gossip Data")
        for i = 0, count - 1 do
            local gossip_offset = offset + (i * 104)
            local gossip_end = gossip_offset + 72
            if gossip_end > buffer:len() then break end
            local gossip_tree = data_tree:add(redis_cluster, buffer(gossip_offset, 72), "Gossip Entry " .. (i + 1))
            gossip_tree:add(fields.data_nodename, buffer(gossip_offset, CLUSTER_NAMELEN))
            gossip_tree:add(fields.data_ping_sent, buffer(gossip_offset + CLUSTER_NAMELEN, 4))
            gossip_tree:add(fields.data_pong_received, buffer(gossip_offset + CLUSTER_NAMELEN + 4, 4))
            gossip_tree:add(fields.data_ip, buffer(gossip_offset + CLUSTER_NAMELEN + 8, NET_IP_STR_LEN))
            gossip_tree:add(fields.data_port, buffer(gossip_offset + CLUSTER_NAMELEN + 8 + NET_IP_STR_LEN, 2))
            gossip_tree:add(fields.data_cport, buffer(gossip_offset + CLUSTER_NAMELEN + 8 + NET_IP_STR_LEN + 2, 2))
            local flags_value = buffer(gossip_offset + CLUSTER_NAMELEN + 8 + NET_IP_STR_LEN + 4, 2):uint()
            local flags_text = ""
            for flag, name in pairs(CLUSTER_NODE_FLAGS) do
                if bit.band(flags_value, flag) ~= 0 then
                    flags_text = flags_text .. name .. ", "
                end
            end
            if #flags_text > 0 then
                flags_text = flags_text:sub(1, -3) -- Remove trailing comma and space
            else
                flags_text = "None"
            end
            gossip_tree:add(fields.data_flags, buffer(gossip_offset + CLUSTER_NAMELEN + 8 + NET_IP_STR_LEN + 4, 2)):append_text(" (" .. flags_text .. ")")
            gossip_tree:add(fields.data_pport, buffer(gossip_offset + CLUSTER_NAMELEN + 8 + NET_IP_STR_LEN + 6, 2))
        end
    elseif msg_type == 4 or msg_type == 10 then  -- Publish, PublishShard
        subtree:add(fields.data_nodename, buffer(offset, CLUSTER_NAMELEN))
    elseif msg_type == 7 then  -- Update
        subtree:add(fields.data_nodename, buffer(offset, CLUSTER_NAMELEN))
    end
end

-- Registration
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(16379, redis_cluster) -- Redis Cluster bus port
