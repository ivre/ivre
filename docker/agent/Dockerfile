# This file is part of IVRE.
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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

FROM debian:stable
MAINTAINER Pierre LALET <pierre.lalet@cea.fr>

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -q update
RUN apt-get -qy install nmap screen bzip2

ADD https://raw.githubusercontent.com/cea-sec/ivre/master/agent/agent \
    /usr/bin/agent
RUN chmod +x /usr/bin/agent
ADD runagent /usr/bin/runagent

RUN chmod 777 /var/run/screen

VOLUME /var/lib/ivre-agent
WORKDIR /var/lib/ivre-agent
CMD exec /usr/bin/runagent
