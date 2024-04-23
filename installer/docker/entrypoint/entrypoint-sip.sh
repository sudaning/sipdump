#!/bin/bash
/usr/local/sipdump/bin/sipdump -c /etc/sipdump/sipdump.xml
exec "$@"