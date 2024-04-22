#!/bin/bash

sipdump -c /etc/sipdump/sipdump.xml

exec "$@"