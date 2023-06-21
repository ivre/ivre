# This file is part of IVRE.
# Copyright 2011 - 2023 Pierre LALET <pierre@droids-corp.org>
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

FROM debian:12 AS builder

ENV DEBIAN_FRONTEND noninteractive

# Install pip then install IVRE
ADD ivre.tar ./
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install python3-pip && \
    pip3 install --break-system-packages /ivre


FROM debian:12
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

ENV DEBIAN_FRONTEND noninteractive

# Install Python
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install python3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/etc/bash_completion.d/ivre /usr/local/etc/bash_completion.d/ivre
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin/ivre /usr/local/bin/ivre
COPY --from=builder /usr/local/share/doc/ivre /usr/local/share/doc/ivre
COPY --from=builder /usr/local/share/ivre /usr/local/share/ivre

# Fix version
RUN sed -ri 's#$#-docker#' /usr/local/lib/python*/dist-packages/ivre/VERSION && \
    sed -ri 's#(VERSION = .*)(['\''"])$#\1-docker\2#' /usr/local/lib/python*/dist-packages/ivre/__init__.py

RUN echo 'DB = "mongodb://ivredb/"' > /etc/ivre.conf
