-- Pinging Machines from NSE

-- We recommend reading https://nmap.org/book/man-nse.html for an introduction
-- to NSE and, maybe more importantly, how to use this script. It'll need privileges
-- given it uses raw sockets...

-- Be sure to check https://nmap.org/book/nse.html for a complete
-- overview on NSE and what we can do with it. You can also find a list of available
-- modules over at https://nmap.org/nsedoc/lib/. Even though we haven't included it, we
-- found `ipOps` to be really handy for a ton of tasks. You can find more info on it over at
-- https://nmap.org/nsedoc/lib/ipOps.html. For stuff regarding Networking I/O and NSE as a
-- whole really be sure to check https://nmap.org/book/nse-api.html#nse-api-networkio. Finally,
-- this script has been built largely thanks to peeking at the implementation of the `ipdseq`
-- script. More information is available at https://nmap.org/nsedoc/scripts/ipidseq.html and
-- the implementation can be seen at https://svn.nmap.org/nmap/scripts/ipidseq.nse.

--------------------
-- Module Imports --
--------------------

-- Interface with Nmap's internals. More info at https://nmap.org/nsedoc/lib/nmap.html.
local nmap = require("nmap")

-- Misc NSE goodies. More info at https://nmap.org/nsedoc/lib/stdnse.html.
local stdnse = require("stdnse")

-- The standard `string` library. More info at https://www.lua.org/manual/5.3/manual.html#6.4.
local string = require("string")

-- The standard `table` library. More info at https://www.lua.org/manual/5.3/manual.html#6.6.
local table = require("table")

-- Packet crafting goodies. More info at https://nmap.org/nsedoc/lib/packet.html.
local packet = require("packet")

-----------------
-- Script Body --
-----------------

-- The following specifies the script's action and metadata. Be sure to check
-- https://nmap.org/book/nse-tutorial.html for a high-level overview on what we
-- need to include. The good thing is most of them are rather self-explainatory.

-- Just a brief summary of what the script does. It's show when running `nmap --script-help ...`.
description = [[
A simple ping implementation running within the NSE. It doesn't receive anytihing yet O_o

It was an excuse to play around with the NSE really... It will send as many ICMP Echo Requests as
specified though the arguments and embed the specified payload into the messages. You can run
the script with:

	$ sudo nmap --script nping.nse [--script-args nping.payload=<string>,nping.npings=<uint>] <target>

The arguments are:
	+ nping.payload: The payload to embed on ICMP Echo Requests. Be sure to quote as needed.
	+ nping.npings:  The number of ping messages to send to the target.
]]

-- This is NSEDoc's information. Be sure to take a look at
-- https://nmap.org/book/nse-tutorial.html#nse-tutorial-head and
-- https://nmap.org/book/nsedoc.html for more information. On the
-- expected format.

---
-- @usage
-- sudo nmap --script nping.nse [--script-args nping.payload=<string>,nping.npings=<uint>] <target>
-- @args nping.payload The payload to embed on ICMP Echo Requests. Be sure to quote as needed.
-- @args nping.npings The number of ping messages to send to the target.
-- @output
-- Host script results:
-- Host script results:
-- |_nping: Pinged stuff successfully!

-- Not really used by NSE though. It's basically used to credit and/or blame script
-- authors :)
author = "Pablo Collado Soto"

-- This one's the default and recommended one. We can also specify other licenses
-- if we deem it appropriate to do so.
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- Let's specify the characteristics of this script as a table.
-- Check https://nmap.org/book/nse-usage.html#nse-categories for more
-- info on what categories are and what they can be.
categories = {"discovery", "safe"}

-- We need a rule allowing us to tell NSE whether our script should run or not.
-- We'll always run it: it's a ping after all... Be sure to check
-- https://nmap.org/book/nse-tutorial.html#nse-tutorial-rule for more info.
-- Bear in mind this rule MUST be a `hostrule`. If it were a `prerule` the
-- `host` table would evaluate to `nil`... You can also get a high-level overview
-- of the rule at https://nmap.org/book/nse-script-format.html.
hostrule = function(host) return true end

-- Compute the internet checksum of a given packet.
-- This function has already been implemented on module
-- `Packet`(https://github.com/nmap/nmap/blob/master/nselib/packet.luai#L66) as
-- function `in_cksum` (https://nmap.org/nsedoc/lib/packet.html#in_cksum),
-- but we preferred to play around with it to get familiar with how Lua
-- handles raw binary representation. Be sure to check https://en.wikipedia.org/wiki/Internet_checksum
-- and RFC 1071 (https://www.rfc-editor.org/rfc/rfc1071.html) for information on
-- how the checksum is ti be computed.
-- @param pkt string Binary representation of the packet whose checksum we have to compute.
	-- The checksum filed should be zeroed out.
-- @returns int A 16-bit integer containing the checksum itself.
local chksum = function(pkt)
	-- Let's initialise the total checksum addition to 0. We'll be continuously adding
	-- new concatenated bytes onto this accumulator.
	local acc = 0

	-- Let's iterate over the packets bytes. Bear in mind we won't be working with the trailing
	-- byte on packets with an odd number of bytes. This is accounted for right aftwerwards.
	-- By the way, the `#` operator returns a string's length.
	for i = 1, #pkt - 1, 2 do
		-- Let's show the bytes we'll be working on on this itreration as well as how
		-- they look when concatenated. The entire loop makes heavy use of string manipulation
		-- functions provided by Lua's standard library as seen on section 6.4 of its reference.
		-- Links to this section are included further down as comments; the same goes for
		-- functions not explicitly documented here. Also bear in mind Lua begins indexing at
		-- 1 instead of 0 :( By they way, `stdnse.debug()'s format string specifiers are identical
		-- to C's. However, `stdnse.debug()` does add a trailing newline (i.e. `\n`).
		stdnse.debug(1, "checksum: iteration %d; adding bytes %#02x and %#02x -> %#02x", i,
			string.byte(pkt, i), string.byte(pkt, i+1), string.byte(pkt, i) << 8 | string.byte(pkt, i+1))

		-- Time to increment the total count by the concatenation of the current bytes.
		acc = acc + (string.byte(pkt, i) << 8 | string.byte(pkt, i+1))

		-- As defined in the Internet Checksum computation procedure we need to recirculate the carry
		-- if the result doesn't fit into 16-bits (i.e. 0xFFFF)
		if acc > 0x10000 then
			acc = acc + 1
		end

		-- Let's truncate the current count so we're sure things keep on working
		-- as expected.
		acc = acc & 0xFFFF

		-- Time to show the current accumulator so that we can debug every iteration
		-- of the computation procedure.
		stdnse.debug(1, "checksum: current checksum accumulator: %#02x", acc)
	end

	-- Accommodate for packets not aligned to 16-bits. We could have
	-- also padded the packet with "\0" before entering the loop above.
	-- However, we feel this is a bit clearer. Bear in mind Lua's 'not equal'
	-- operator is `~=` instead of C's `!=`.
	if #pkt % 2 ~= 0 then
		-- Let's signal we are dealing with the dangling byte.
		stdnse.debug(1, "checksum: we had an odd number of bytes: adding %#02x -> %#02x", string.byte(pkt, #pkt),
			string.byte(pkt, #pkt) << 8)

		-- We just need to add the trailing byte 'as if' we had an additional 0 byte. This basically
		-- ammounts to shifting the trailing byte by 8 and addint it to the accumulator.
		acc = acc + (string.byte(pkt, #pkt) << 8)

		-- We still need to be weary of recirculating the carry.
		if acc > 0x10000 then
			acc = acc + 1
		end
	end

	-- Time to check the checksum is correct. Remember we need to invert
	-- the accumulator and truncate it to 16-bits.
	stdnse.debug(1, "checksum: done -> %#02x", (~acc) & 0xFFFF)

	-- We just need to return the result and that's that :)
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
	for i = 0, nPings - 1 do
		-- Time to send the echo request. Note we need to send the packet's raw buffer,
		-- hence the call to `:raw()`. You can find more info on both calls
		-- here https://nmap.org/nsedoc/lib/packet.html#Packet:raw and
		-- here https://nmap.org/nsedoc/lib/nmap.html#ip_send, respectively.
		dnet:ip_send(icmpPkt:raw(), host.ip)

		-- We can print messages based on verbosity instead of debugging levels.
		-- More info over at https://nmap.org/nsedoc/lib/stdnse.html#verbose
		stdnse.verbose(1, "sent ICMP Echo Request %d...", i)

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
