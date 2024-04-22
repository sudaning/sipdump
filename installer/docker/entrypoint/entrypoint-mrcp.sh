#!/bin/bash

mrcpdump -c /etc/mrcpdump/mrcpdump.xml

exec "$@"