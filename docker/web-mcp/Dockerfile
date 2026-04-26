# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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

ARG TAG=latest
FROM ivre/base:${TAG}
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

# The `mcp` Python package is an optional IVRE dependency (`[mcp]`
# extra). The base image has already purged pip, so reinstall it just
# long enough to fetch `mcp`, then clean up again.
#
# `nmap-common` ships the Nmap data files under /usr/share/nmap/
# (nmap-service-probes, nmap-services, scripts/*.nse, ...). The MCP
# `nmap_service_values` tool reads those files to enumerate known
# service_name / service_product values; without them
# `config.NMAP_SHARE_PATH` resolves to None and the tool fails. Keep
# `nmap-common` installed in the final image (only `python3-pip` is
# autoremoved).
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install python3-pip nmap-common && \
    pip3 install --break-system-packages mcp && \
    apt-get -qy --purge autoremove python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# The MCP HTTP transport must listen on a non-loopback address so the
# `ivreweb` container can reach it. `--allow-anonymous` is passed by
# default because the port is only published on the internal Docker
# network (no `ports:` mapping in docker-compose.yml).
#
# For a production deployment, enable the IVRE Web auth backend (set
# `WEB_AUTH_ENABLED = True` in ivre.conf and create an API key via the
# Web UI) and override the CMD in docker-compose.yml to drop the
# `--allow-anonymous` flag.

USER nobody
EXPOSE 9100
CMD ["ivre", "mcp-server", "--http", \
     "--bind", "0.0.0.0", \
     "--port", "9100", \
     "--path", "/mcp", \
     "--allow-anonymous"]
