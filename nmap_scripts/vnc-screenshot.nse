-- This file is part of IVRE.
-- Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
--
-- IVRE is free software: you can redistribute it and/or modify it
-- under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- IVRE is distributed in the hope that it will be useful, but WITHOUT
-- ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
-- License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with IVRE. If not, see <http://www.gnu.org/licenses/>.

local match = require "match"
local math = require "math"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[

Gets a screenshot from a VNC server.

Imagemagick's `convert` tool must me installed somewhere in $PATH.

This script requires Lua 5.3, which means at least Nmap 7.25BETA2.

]]

author = "Pierre Lalet"
license = "GPLv3"
categories = {"discovery", "safe", "screenshot"}

---
-- @usage
-- nmap -n -p 5900 --script vnc-screenshot 1.2.3.4
--
-- @output
-- PORT     STATE SERVICE
-- 5900/tcp open  http
-- |_http-screenshot: Saved to screenshot-1.2.3.4-5900.jpg

portrule = shortport.port_or_service(5900, "vnc")

local function read_bytes(socket, nbytes)
  local status, result
  for retry = 1, 3 do
    status, result = socket:receive_buf(match.numbytes(nbytes), true)
    if status then
      goto ret
    elseif result == "TIMEOUT" then
      stdnse.debug1("Socket error on receive: TIMEOUT (%d).", retry)
    else
      stdnse.debug1("Socket error on receive: %s.", result)
      goto close
    end
  end
  stdnse.debug1("Socket error on receive: TIMEOUT (giving up).")
  ::close::
  socket:close()
  ::ret::
  return status, result
end

local function missing_data(buffer, fb)
  for i=1, fb.height do
    for j=1, fb.width do
      if buffer[i][j] == nil then return true end
    end
  end
  return false
end

local function has_data(buffer, fb)
  for i=1, fb.height do
    for j=1, fb.width do
      if buffer[i][j] ~= nil then return true end
    end
  end
  return false
end

local function read_pixel(socket, fb)
  local status, data
  local pix = {}
  status, data = read_bytes(socket, fb.bytes_per_pixel)
  if not status then return end
  data = ("%sI%d"):format(fb.big_endian == 0 and "<" or ">",
                          fb.bytes_per_pixel):unpack(data)
  for _, col in pairs({"red", "green", "blue"}) do
    pix[col] = ((data >> fb.shift[col]) % (fb.max[col] + 1)) * 255 // fb.max[col]
  end
  return ("BBB"):pack(pix.red, pix.green, pix.blue)
end


action = function(host, port)
  local socket = nmap.new_socket()
  local status, result, version
  local fname = ("screenshot-%s-%d.jpg"):format(host.ip, port.number)

  socket:connect(host, port)

  status, result = socket:receive_buf("\n", false)

  if not (status and result:match("^RFB %d%d%d.%d%d%d$")) then
    if status then
      stdnse.debug1('FAIL: invalid banner.')
    else
      stdnse.debug1('FAIL: socket error: %s.', result)
    end
    socket:close()
    return
  end
  stdnse.debug1('Banner: %s.', result)

  version = result:sub(5)

  if version < "003.007" then
    version = "003.003"
  elseif version == "003.007" then
    version = "003.007"
  else
    version = "003.008"
  end

  socket:send(("RFB %s\n"):format(version))

  if version == "003.003" then
    status, result = read_bytes(socket, 4)
    if not status or result ~= "\000\000\000\001" then
      if status then
        stdnse.debug1('FAIL: authentication required.')
        socket:close()
      end
      return
    end
  else
    status, result = read_bytes(socket, 1)
    if not status then return end
    status, result = read_bytes(socket, result:byte())
    if not status then return end
    socket:send("\001")
    if version == "003.008" then
      status, result = read_bytes(socket, 4)
      if not status or result ~= "\000\000\000\000" then
        if status then
          stdnse.debug1('FAIL: authentication required.')
          socket:close()
        end
        return
      end
    end
  end

  socket:send("\001")
  status, result = read_bytes(socket, 24)
  if not status then return end
  local fb = {}
  fb.max = {}
  fb.shift = {}

  fb.width, fb.height, fb.bytes_per_pixel, fb.depth, fb.big_endian,
  fb.true_color, fb.max.red, fb.max.green, fb.max.blue, fb.shift.red,
  fb.shift.green, fb.shift.blue, _,
  fb.desktop_name_len = (">I2I2BBBBI2I2I2BBBc3I4"):unpack(result)
  fb.bytes_per_pixel = fb.bytes_per_pixel // 8
  status, fb.desktop_name = read_bytes(socket, fb.desktop_name_len)
  if not status then return end

  socket:send('\000\000\000\000' .. result:sub(5, 17) .. '\000\000\000' ..
                '\002\000\000\002\000\000\000\000\000\000\000\005\005\000' ..
                '\000\000\000\000')

  stdnse.sleep(2)
  socket:send('\005\000\000\012\000\012')
  stdnse.sleep(2)

  socket:send('\003\000\000\000\000\000' .. result:sub(1, 4))

  local buffer = {}
  for i = 1, fb.height do
    buffer[i] = {}
    for j = 1, fb.width do
      buffer[i][j] = nil
    end
  end

  while missing_data(buffer, fb) do
    status, result = read_bytes(socket, 4)
    if not status then goto draw end
    if result:sub(1, 1) == '\001' then
      status, result = read_bytes(socket, 2)
      if not status then goto draw end
      status, _ = socket:receive_buf(match.numbytes(6 * (">I2"):unpack(result)), true)
      if not status then goto draw end
      goto next
    end
    if result:sub(1, 1) ~= '\000' then
      socket:close()
      goto draw
    end
    local count = (">I2"):unpack(result:sub(3))
    for ir = 1, count do
      status, result = read_bytes(socket, 12)
      if not status then goto draw end
      local rect = {}
      rect.xpos, rect.ypos, rect.width, rect.height, rect.encoding = (">I2I2I2I2I4"):unpack(result)
      if buffer[rect.ypos + 1][rect.xpos + 1] ~= nil then
        stdnse.debug1("Overwriting data: screenshot complete?")
        socket:close()
        goto draw
      end
      if rect.encoding == 0 then
        local pixel
        for ih = 1, rect.height do
          for iw = 1, rect.width do
            pixel = read_pixel(socket, fb)
            if pixel == nil then
              goto draw
            end
            buffer[rect.ypos + ih][rect.xpos + iw] = pixel
          end
        end
      elseif rect.encoding == 5 then
        local flags, tx, ty, back_col, fore_col, nsubrects, pix, subr_x, subr_y, subr_w, subr_h
        for ty = 0, math.ceil(rect.height / 16) - 1 do
          for tx = 0, math.ceil(rect.width / 16) - 1 do
            status, data = read_bytes(socket, 1)
            if not status then goto draw end
            flags = data:byte()
            if flags & 1 == 1 then
              for ih = 1, math.min(rect.height - ty * 16, 16) do
                for iw = 1, math.min(rect.width - tx * 16, 16) do
                  buffer[rect.ypos + ty * 16 + ih][rect.xpos + tx * 16 + iw] = read_pixel(socket, fb)
                end
              end
              goto nexttile
            end
            if flags & 2 == 2 then
              back_col = read_pixel(socket, fb)
            end
            if flags & 4 == 4 then
              fore_col = read_pixel(socket, fb)
            end
            for ih = 1, math.min(rect.height - ty * 16, 16) do
              for iw = 1, math.min(rect.width - tx * 16, 16) do
                if buffer[rect.ypos + ty * 16 + ih][rect.xpos + tx * 16 + iw] == nil then
                  buffer[rect.ypos + ty * 16 + ih][rect.xpos + tx * 16 + iw] = back_col
                end
              end
            end
            if flags & 8 == 8 then
              status, nsubrects = read_bytes(socket, 1)
              if not status then goto draw end
              nsubrects = nsubrects:byte()
              for _ = 1, nsubrects do
                pix = (flags & 16) == 16 and read_pixel(socket, fb) or fore_col
                status, data = read_bytes(socket, 1)
                if not status then goto draw end
                subr_x = data:byte()
                subr_y = subr_x % 16
                subr_x = subr_x >> 4
                status, data = read_bytes(socket, 1)
                if not status then goto draw end
                subr_w = data:byte()
                subr_h = (subr_w % 16) + 1
                subr_w = (subr_w >> 4) + 1
                for ih = 1, subr_h do
                  for iw = 1, subr_w do
                    buffer[rect.ypos + ty * 16 + subr_y + ih][rect.xpos + tx * 16 + subr_x + iw] = pix
                  end
                end
              end
            end
            ::nexttile::
          end
        end
      else
        stdnse.debug1("Unsupported encoding (%d)", rect.encoding)
        socket:close()
        goto draw
      end
    end
    ::next::
  end

  socket:close()
  ::draw::
  if has_data(buffer, fb) then
    local f = assert(io.popen(("convert -size %dx%d -depth 8 RGB:- %s"):format(
                         fb.width, fb.height, fname), "w"
    ))
    local pixel
    for i = 1, fb.height do
      for j = 1, fb.width do
        pixel = buffer[i][j]
        if pixel == nil then
          f:write("\000\000\000")
        else
          f:write(buffer[i][j])
        end
      end
    end
    f:close()
    if os.rename(fname, fname) then
      return ("Saved to %s"):format(fname)
    end
  else
    stdnse.debug1("No data: empty screenshot discarded")
  end
end
