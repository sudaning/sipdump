#!/bin/bash

basepath=$(cd `dirname $0`; pwd)

help() {
  printf "usage: %s\n" "$0" >&2
}

install_dep_sipdump() {
  echo -e "\e[1;32minstall sipdump dep...\e[0m"
  cd ${basepath}
  cd ../dependency && yum localinstall -y rpm/*.rpm
  cd ${basepath}
  cd ../dependency && tar zxf apr-1.7.2.tar.gz && cd apr-1.7.2 && ./buildconf && ./configure && make && make install
	cd ${basepath}
  cd ../dependency && tar zxf apr-util-1.6.3.tar.gz && cd apr-util-1.6.3 && ./configure --with-apr=../apr-1.7.2 && make && make install
	cd /usr/lib64/pkgconfig && ln -sf /usr/local/apr/lib/pkgconfig/apr-1.pc . && ln -sf /usr/local/apr/lib/pkgconfig/apr-util-1.pc .
	cd ${basepath}
  cp -f ../dependency/pkg-config/* /usr/lib64/pkgconfig/
  cp -f ../dependency/ldconfig/* /etc/ld.so.conf.d/
  ldconfig
}

install_sipdump() {
  echo -e "\e[1;32msipdump install...\e[0m"

  if [ -f "/usr/local/sipdump/bin/sipdump" ]; then
    echo -e "\e[1;32msipdump has been installed\e[0m"
    return 0
  fi

  cd ${basepath}
  cd .. && rm -rf build && mkdir build && cd build && cmake3 .. && make && make install
  if [ $? -ne 0 ]; then
    echo -e "\e[1;31msipdump install error!\e[0m"
    exit 1
  fi

  if [ ! -f "/usr/local/sipdump/bin/sipdump" ]; then
    echo -e "\e[1;31msipdump check error!\e[0m"
    exit 1
  else
    echo -e "\e[1;32msipdump install success!\e[0m"
  fi

  cd ${basepath}
  chmod 775 docker/entrypoint/*
  cp docker/entrypoint/* /usr/local/bin/
}

install () {
  install_dep_sipdump
  install_sipdump
}

install
