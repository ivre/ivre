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

local shortport = require "shortport"
local match = require "match"

description = [[

Gets a screenshot from a VNC server.

Imagemagick's convert tool must me installed somewhere in $PATH.

]]

author = "Pierre LALET <pierre@droids-corp.org>"
license = "GPLv3"
categories = {"discovery", "safe"}

---
-- @usage
-- nmap -n -p 5900 --script vnc-screenshot 1.2.3.4
--
-- @output
-- PORT   STATE SERVICE
-- 5900/tcp open  http
-- |_http-screenshot: Saved to screenshot-1.2.3.4-5900.jpg

portrule = shortport.port_or_service(5900, "vnc")

local function missing_data(buffer, fb)
   for i=1, fb.height do
      for j=1, fb.width do
         if buffer[i][j] == nil then return true end
      end
   end
   return false
end

local function read_pixel(socket, fb)
  local status, data
  local pix = {}
  status, data = socket:receive_buf(match.numbytes(fb.bytes_per_pixel), true)
  if not status then
    return
  end
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
    stdnse.debug1('FAIL: invalid banner.')
    socket:close()
    return
  end

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
    status, result = socket:receive_buf(match.numbytes(4), true)
    if not status or result ~= "\000\000\000\001" then
      stdnse.debug1('FAIL: socket error or authentication required.')
      socket:close()
      return
    end
  else
    status, result = socket:receive_buf(match.numbytes(1), true)
    if not status then
      stdnse.debug1('FAIL: socket error.')
      socket:close()
      return
    end
    status, result = socket:receive_buf(match.numbytes(result:byte()), true)
    if not status then
      socket:close()
      return
    end
    socket:send("\001")
    if version == "003.008" then
      status, result = socket:receive_buf(match.numbytes(4), true)
      if not status or result ~= "\000\000\000\000" then
        socket:close()
        return
      end
    end
  end

  socket:send("\001")
  status, result = socket:receive_buf(match.numbytes(24), true)
  if not status then
    socket:close()
    return
  end
  local fb = {}
  fb.max = {}
  fb.shift = {}

  fb.width, fb.height, fb.bytes_per_pixel, fb.depth, fb.big_endian,
  fb.true_color, fb.max.red, fb.max.green, fb.max.blue, fb.shift.red,
  fb.shift.green, fb.shift.blue, _,
  fb.desktop_name_len = (">I2I2BBBBI2I2I2BBBc3I4"):unpack(result)
  fb.bytes_per_pixel = fb.bytes_per_pixel // 8
  status, fb.desktop_name = socket:receive_buf(match.numbytes(fb.desktop_name_len), true)

  socket:send('\000\000\000\000' .. result:sub(5, 17) .. '\000\000\000' ..
                '\002\000\000\001\000\000\000\000\003\000\000\000\000\000' ..
                 result:sub(1, 4))

  local buffer = {}
  for i = 1, fb.height do
    buffer[i] = {}
    for j = 1, fb.width do
      buffer[i][j] = nil
    end
  end

  while missing_data(buffer, fb) do
    status, result = socket:receive_buf(match.numbytes(4), true)
    if result:sub(1, 1) == '\001' then
      status, result = socket:receive_buf(match.numbytes(2), true)
      if not status then
        goto draw
      end
      status, _ = socket:receive_buf(match.numbytes(6 * (">I2"):unpack(result)), true)
      if not status then
        goto draw
      end
      goto next
    end
    if result:sub(1, 1) ~= '\000' then
      goto draw
    end
    local count = (">I2"):unpack(result:sub(3))
    for ir = 1, count do
      status, result = socket:receive_buf(match.numbytes(12), true)
      if not status then
        goto draw
      end
      local rect = {}
      rect.xpos, rect.ypos, rect.width, rect.height, encoding = (">I2I2I2I2I4"):unpack(result)
      if encoding ~= 0 then
        goto draw
      end
      for ih = 1, rect.height do
        for iw = 1, rect.width do
          pixel = read_pixel(socket, fb)
          if pixel == nil then
            goto draw
          end
          buffer[rect.ypos + ih][rect.xpos + iw] = pixel
        end
      end
    end
    ::next::
  end

  ::draw::
  socket:close()
  local f = assert(io.popen(
     ("convert -size %dx%d -depth 8 RGB:- %s"):format(
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
end
