#!/bin/bash
/usr/local/sipdump/bin/mrcpdump -c /etc/mrcpdump/mrcpdump.xml
exec "$@"