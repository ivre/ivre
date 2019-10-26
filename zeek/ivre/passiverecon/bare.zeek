# This file is part of IVRE.
# Copyright 2011 - 2019 Pierre LALET <pierre.lalet@cea.fr>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.

# Use "zeek -b [options] /path/to/thisfile.zeek"

@load ./

event zeek_init() {
    # Let's disable standards outputs
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(FTP::LOG);
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(SSH::LOG);
    Log::disable_stream(SSL::LOG);
    Log::disable_stream(Conn::LOG);
    Log::disable_stream(Files::LOG);
    Log::disable_stream(Notice::LOG);
    Log::disable_stream(Reporter::LOG);
    Log::disable_stream(Tunnel::LOG);
    Log::disable_stream(Weird::LOG);
    Log::disable_stream(X509::LOG);

    local filter = Log::get_filter(PassiveRecon::LOG, "default");
    filter$path = getenv("LOG_PATH") == "" ? "/dev/stdout" : getenv("LOG_PATH");
    filter$interv = getenv("LOG_ROTATE") == "" ? Log::default_rotation_interval : double_to_interval(to_double(getenv("LOG_ROTATE")));
    Log::add_filter(PassiveRecon::LOG, filter);
}
