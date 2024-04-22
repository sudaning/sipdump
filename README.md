# 介绍
sipdump是一款基于sip协议和mrcp协议的抓包分析工具，帮助做好音视频分析

# 特性
1. 支持分析SIP协议，SDP协议，MRCP协议
2. 支持按照SIP会话聚合SIP信令+MRCP信令+RTP包+RTCP包
3. 支持docker部署
4. 支持多IP组归属主机，提供多网卡和NAT解决方案
5. 支持定制化pcap文件命名
6. 支持SIP会话信息总结性输出与统计
7. 支持扩展插件满足定制化需求

# 待开发功能
1. 支持IPv6网络

# 依赖
|库名|版本|官网|
|---|---|---|
|apr|1.7.2|https://apr.apache.org/|
|apr-util|1.6.3|https://apr.apache.org/|
|libpcap|1.5.3|https://www.tcpdump.org/|
|cmake|3.10|https://cmake.org/|

# 编译&安装
```
# 1. 编译安装依赖
...

# 2. 编译安装sipdump
mkdir -p build
cd build
cmake3 ..
make 
make install
```

# 启动
## 示例
```
# 简单参数启动
./sipdump -i enp2s0 -d /tmp/sipdump -R rtp,rtcp,event
```
```
# 带网卡过滤参数启动
./sipdump -v trace -i enp2s0 -d /tmp/sipdump -R rtp,rtcp,event port 5060 or \(ip[6:2]\&0x1fff\)!=0
```
```
# 带配置文件启动
./sipdump -c /etc/sipdump/sipdump.xml
```
## 启动参数
|<div style="width:64px">参数</div>|<div style="width:160px">配置字段</div>|类型|<div style="width:160px">说明</div>|示例|备注|
|---|---|---|---|---|---|
| |\<log-name\>|string|日志名|```<log-name>sipdump</log-name>```|无|
| |\<log-mode\>|string|日志模式|```<log-mode>syslog</log-mode>```|无|
| |\<log-facility\>|string|syslog日志设备|```<log-facility>LOG_LOCAL5</log-facility>```|无|
|-c||string|配置文件|```-c ./config/sipdump.xml```|无|
|-i| \<interface type="eth"\> |string|网卡名称|```-i eth0```<br><br>```<interface type="eth">eth0</interface>```|从网卡中抓数据分析（与 -r 二选一）|
|-r| \<interface type="file"\> |string|pcap包名称|```-r sipdump.pcap```<br><br>```<interface type="file">sipdump.pcap</interface>```|从pcap文件中抓数据分析（与 -i 二选一）|
|-v|\<log-level\>|string|日志级别|```-v debug```<br><br>```<log-level>info</log-level>```|默认info|
|-P|\<pid\>|string|PID文件|```-P ./sipdump.pid```<br><br>```<pid>./sipdump.pid</pid>```|默认/var/run/sipdump.pid|
|-d|\<record\>|string|抓包文件保存路径|```-d /var/sipdump/${sip_call_id}.pcap```<br><br>```<record>/var/sipdump/${sip_call_id}.pcap</record>```|默认 ./pcap/\${year}-\${month}-\${day}/\${hour}/\${hour}\${minute}\${second}_\${sip_call_id}.pcap|
|-T|\<limit-time\>|string|最大会话时间|```-T 3600```<br><br>```<limit-time>3600</limit-time>```|默认7200秒，超过时间清理会话|
|-B|无|string|buffer大小|```-B 32768``` ```-B 10KB``` ```-B 512MB```|默认0，不设置，支持单位混合输入|
|-m|无|string|SIP方法过滤|```-m INVITE,OPTION,REGISTER```|默认INVITE（分隔符可以是,;\|）|
|-n|无|string|号码过滤|```^1[3456789]d{9}$```|默认无，正则表达式
|-R|\<rtp-filter\>|string|媒体包过滤|```-R rtp,rtcp,event```<br><br>```<rtp-filter>rtp,rtcp,event</rtp-filter>```|默认none（分隔符可以是,;\|）|
|-p|\<promiscuous\>|bool|禁用网卡混杂模式|```-p```<br><br>```<promiscuous>true</promiscuous>```|默认开启混杂模式|
|-U|无|bool|禁用pcap写入立即刷新|```-U```|默认立即刷新|
|额外参数|\<pcap-filter-exp\>|string|网卡过滤|```port 5060 or \(ip[6:2]\&0x1fff\)!=0```<br><br>```<pcap-filter-exp>port 5060 or (ip[6:2]&0x1fff)</pcap-filter-exp>```|直接设置到网卡中，参考tcpdump|
| |\<ip-group\>|node|IP组|```参考sipdump.xml```|无|
| |\<plugins\>|node|插件|```参考sipdump.xml```|无|

## 注意
配置文件与其他输入参数是覆盖关系，-c在前，则先读取配置文件中的参数，后续有同样的参数，则会覆盖配置；反之亦然。

## 联系我
邮箱：sudaning@sina.com
微信: 18682099276