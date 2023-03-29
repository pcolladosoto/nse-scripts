-- Be sure to check https://nmap.org/book/nse.html for a complete
-- overview on NSE and what we can do with it.

-- You can read up on functions provided by the different modules
-- over at https://nmap.org/nsedoc/lib/

-- Check the `Packet` module (https://nmap.org/nsedoc/lib/packet.html)
-- for packet crafting goodies.

-- Check the `ipOps` packet for IP-related tasks and manipulations.

-- We are using the NSE script over at https://svn.nmap.org/nmap/scripts/ipidseq.nse
-- as a guide to grow accustomed to raw sockets within NSE :)


-- Check https://nmap.org/book/nse-api.html#nse-api-networkio for information on
-- networking I/O withiin NSE.

-- Interface with Nmap internals (https://nmap.org/nsedoc/lib/nmap.html).
local nmap = require("nmap")

-- Misc NSE goodies (https://nmap.org/nsedoc/lib/stdnse.html)
local stdnse = require("stdnse")

-- The standard `string` library (https://www.lua.org/manual/5.3/manual.html#6.4)
local string = require("string")

-- The standard `table` library (https://www.lua.org/manual/5.3/manual.html#6.6)
local table = require("table")

-- Packet crafting goodies (https://nmap.org/nsedoc/lib/packet.html)
local packet = require("packet")

-- Just a brief summary of what the script does.
description = [[
A simple `ping` implementation running within the NSE.

It was an excuse to play around with the NSE really...
]]

-- This is NSEDoc's information. Be sure to take a look at
-- https://nmap.org/book/nse-tutorial.html#nse-tutorial-head and
-- https://nmap.org/book/nsedoc.html for more information.

---
-- @output
-- Host script results:
-- |_ sniffer-detect: Likely in promiscuous mode (tests: "11111111")

-- Not really used by NSE though.
author = "Pablo Collado Soto"

-- This one's the default and recommended one.
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- Check https://nmap.org/book/nse-usage.html#nse-categories for more
-- info on what categories are and what they can be.
categories = {"discovery", "safe"}

-- We need a rule allowing us to tell NSE whether our script should run or not.
-- We'll always run it: it's a ping after all... Be sure to check
-- https://nmap.org/book/nse-tutorial.html#nse-tutorial-rule for more info.
hostrule = function(host) return true end

-- Compute the internet checksum of a given packet.
-- This function has already been implemented on module
-- `Packet`(https://github.com/nmap/nmap/blob/master/nselib/packet.luai#L66) as
-- function `in_cksum` (https://nmap.org/nsedoc/lib/packet.html#in_cksum),
-- but we preferred to play around with it to get familiar with how Lua
-- handles raw binary representation.
-- @param pkt string Binary representation of the packet whose checksum we have to compute.
	-- The checksum filed should be zeroed out.
-- @returns int A 16-bit integer containing the checksum itself.
local chksum = function(pkt)
	local acc, tmp = 0, 0

	for i = 1, #pkt - 1, 2 do
		stdnse.debug(1, "Adding bytes %#02x and %#02x -> %#02x", string.byte(pkt, i), string.byte(pkt, i+1),
			string.byte(pkt, i) << 8 | string.byte(pkt, i+1))
		tmp = acc + (string.byte(pkt, i) << 8 | string.byte(pkt, i+1))
		if tmp > 0x10000 then
			tmp = tmp + 1
		end
		acc = tmp & 0xFFFF
		stdnse.debug(1, "Current cksum accumulator: %#02x", acc)
	end

	-- Accommodate for packets not aligned to 16-bits. We could have
	-- also padded the packet with "\0" though...
	if #pkt % 2 ~= 0 then
		stdnse.debug(3, "We had an odd number of bytes: adding %#02x -> %#02x", string.byte(pkt, #pkt),
			string.byte(pkt, #pkt) << 8)
		acc = acc + (string.byte(pkt, #pkt) << 8)
		if acc > 0x10000 then
			acc = acc + 1
		end
	end
	stdnse.debug(3, "Done! Returning %#02x", (~acc) & 0xFFFF)
	return (~acc) & 0xFFFF
end

-- Build an ICMP echo request with the provided payload.
-- This can already be accomplished by the implemented `packet.Packet:build_icmp_echo_request()`
-- method (https://nmap.org/nsedoc/lib/packet.html#Packet:build_icmp_echo_request). We wanted to
-- craft the request ourselves though: it's great practice for dealing with binary representations
-- in Lua.
-- @param host table Host information provided by Nmap offering the source and destination IPv4 addresses.
-- @param payload string Payload to embed into the request.
-- @return packet.Packet The built ICMP Echo Request.
local buildICMPPacket = function(host, payload)
	stdnse.debug(1, "building the ICMP Echo request...")

	-- Check https://www.rfc-editor.org/rfc/rfc792 for info on an ICMP message's
	-- header structure. This is an ICMP Echo Request with ID 0xabcd and Sequence
	-- Number 0x0123. The checksum is initialized to 0x0000 so that we can compute it
	-- afterwards. Be sure to check https://nmap.org/nsedoc/lib/stdnse.html#fromhex for
	-- more info on how we translate the initial header into a binary string through the
	-- call to `stdnse.fromhex()`.
	local pkt = stdnse.fromhex("0800 0000 abcd 0123") .. payload

	-- Let's print the ICMP Echo Request before we compute the checksum to see if
	-- everything looks good. This call makes heavy use of several string manipulation
	-- functions documented on Lua's reference over at https://www.lua.org/manual/5.3/manual.html#6.4
	stdnse.debug(1, "Built packet (| byte |): | %s", string.gsub(pkt, ".", function(b)
		return string.format("%x", string.byte(b)) .. " | " end)
	)

	-- Embed the computed checksum in the resulting packet. Be sure to check Lua's Reference section
	-- 6.4 on string manipulation for a ton of information on weird stuff such as the `">I2"` magic
	-- string. It's actually specifying a big-endian (i.e. Internet-compatible) format where data
	-- will be treated as 16-bit (i.e. 2-byte) unsigned quantities.
	pkt = string.sub(pkt, 1, 2) .. string.pack(">I2", chksum(pkt)) .. string.sub(pkt, 5)

	-- The above can be easily accomplished by invoking the `packet.in_cksum()` function documented
	-- at https://nmap.org/nsedoc/lib/packet.html#in_cksum and whose source code implementation proved
	-- to be extremely useful. It's over at https://github.com/nmap/nmap/blob/master/nselib/packet.lua#L66.
	-- pkt = string.sub(pkt, 1, 2) .. string.pack(">I2", packet.in_cksum(pkt)) .. string.sub(pkt, 5)

	-- Let's make sure the checksum was embedded successfully...
	stdnse.debug(1, "Added the checksum (| byte |): | %s", string.gsub(pkt, ".", function(b)
		return string.format("%x", string.byte(b)) .. " | " end)
	)

	-- Up to this point we've been just crafting the 'raw' ICMP request. We'll now embed that into an
	-- IPv4 datagram. However, the `packet` module expects us to first instantiate a packet through the
	-- `packet.Packet:new()` method, so let's get that out of the way. You can find more inforation
	-- on the method at https://nmap.org/nsedoc/lib/packet.html#Packet:new.
	local builtPkt = packet.Packet:new(pkt, #pkt)

	-- Time to build the IPv4 datagram as documented on https://nmap.org/nsedoc/lib/packet.html#Packet:build_ip_packet.
	-- Once the 'generic' packet is instantiated we can populate it with our payload. This also requires
	-- adding information for IPv4's headers, such as the Protocol Number (i.e. 1 for ICMP) and the
	-- TTL (i.e. 64). You can find more information on the header's cotents on IPv4's RFC 791, which you
	-- can find at https://www.rfc-editor.org/rfc/rfc791. Bear in mind we're also making use of the
	-- source and destination IPv4 addresses provided by Nmap itself through the `host` argument relayed
	-- by the action.
	builtPkt:build_ip_packet(host.bin_ip_src, host.bin_ip, pkt, 0, 0xabcd, 0x0, 0x0, 64, 1)

	-- Once the packet is built we just need to give it back. Bear in mind that the `build_ip_packet()` method
	-- returns nothing (i.e. nil); it modifies the packet instance on which it's called in place.
	return builtPkt
end

-- What we're trying to do really. Check https://nmap.org/book/nse-tutorial.html#nse-tutorial-action
-- for more info on the action itself. Bear in mind the `host` argument is provided to us by Nmap
-- itself. Be sure to check https://nmap.org/book/nse-api.html for more info on what information
-- we can count on.
action = function(host)
	-- We'll be using calls to `stdnse.debug` to make tracking the script's progress a bit easier.
	-- More information on all this can be found over at https://nmap.org/nsedoc/lib/stdnse.html#debug.
	stdnse.debug(1, "beginning ping `action`")

	-- Extracting arguments passed through the `--script-args` flag.
	-- More info over at https://nmap.org/nsedoc/lib/stdnse.html#get_script_args.
	-- If no arg os provided the call evaluates to `nil`, so we can initialise it
	-- to the right hand side member passed to the `or` logical operator.
	local payload = stdnse.get_script_args('nping.payload') or "Hello there!"
	local nPings = stdnse.get_script_args('nping.npings') or 3

	-- Time to open a `dnet` object to send raw packets. More info
	-- over at https://nmap.org/nsedoc/lib/nmap.html#new_dnet.
	local dnet = nmap.new_dnet()

	-- We'll be sending IPv4 packets, so we'd better initialise the `dnet` object.
	-- More info over at https://nmap.org/nsedoc/lib/nmap.html#ip_open.
	dnet:ip_open()

	stdnse.debug(1, "opened the raw IP socket")

	-- We need to craft the ICMP request we are to send!
	local icmpPkt = buildICMPPacket(host, payload)

	stdnse.debug(1, "built the ICMP Echo Request")

	-- Time to actually send something :)
	for _ = 0, nPings - 1 do
		-- Time to send the echo request. Note we need to send the packet's raw buffer,
		-- hence the call to `:raw()`. You can find more info on both calls
		-- here https://nmap.org/nsedoc/lib/packet.html#Packet:raw and
		-- here https://nmap.org/nsedoc/lib/nmap.html#ip_send, respectively.
		dnet:ip_send(icmpPkt:raw(), host.ip)

		-- We can print messages based on verbosity instead of debugging levels.
		-- More info over at https://nmap.org/nsedoc/lib/stdnse.html#verbose
		stdnse.verbose(1, "sent the first echo request...")

		-- We don't want to overwhelm the receiving host... More info over
		-- at https://nmap.org/nsedoc/lib/stdnse.html#sleep.
		stdnse.sleep(1)
	end

	-- Closing the IPv4-enabled socket to leave things celan and tidy.
	-- More onfo over at https://nmap.org/nsedoc/lib/nmap.html#ip_close.
	dnet:ip_close()

	-- We'll signal the action's success and print a nice looking message along with
	-- it. Bear in mind we can also play with pretty structured output as seen
	-- here https://nmap.org/book/nse-api.html#nse-structured-output, but that's a
	-- task for another day :P
	return true, "Pinged stuff successfully!"
end
