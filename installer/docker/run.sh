docker run --name mrcp_dump \
  -v /etc/localtime:/etc/localtime \
  -v /etc/mrcpdump/:/etc/mrcpdump/ \
  -v /var/mrcp/mrcpdump:/var/mrcpdump \
  --restart=always \
  --net=host \
  -d mrcpdump-image:1.1.0 \
  entrypoint-mrcp.sh

docker run --name sip_dump \
  -v /etc/localtime:/etc/localtime \
  -v /etc/sipdump/:/etc/sipdump/ \
  -v /var/sip/sipdump:/var/sipdump \
  --restart=always \
  --net=host \
  -d sipdump-image:1.1.0 \
  entrypoint-sip.sh