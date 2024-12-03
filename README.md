# Network Path Tracer

基于 eBPF 的网络请求追踪工具，用于监控和分析 CentOS 7.9 系统中的网络请求路径。

## 功能特性

- 追踪网络数据包在系统中的完整路径
- 显示数据包经过的 iptables 链和规则
- 记录数据包出入的网络接口
- 提供详细的数据包处理信息
- 支持多种灵活的过滤条件

## 系统要求

- CentOS 7.9
- Kernel 版本 >= 3.10.0
- 确保系统已安装以下依赖：
  ```bash
  yum install -y kernel-devel-$(uname -r)
  yum install -y elfutils-libelf-devel
  yum install -y clang llvm
  ```

## 使用方法

### 基本使用

直接运行编译好的二进制文件：

```bash
sudo ./net-tracer
```

### 使用过滤条件

工具支持多种灵活的过滤参数，可以组合使用：

#### IP 过滤
支持单个 IP 或 CIDR 格式的网段过滤：
```bash
# 过滤单个源IP
sudo ./net-tracer --src-ip 192.168.1.100

# 过滤整个源网段
sudo ./net-tracer --src-ip 192.168.1.0/24

# 过滤目标IP网段
sudo ./net-tracer --dst-ip 10.0.0.0/8
```

#### 端口过滤
支持单个端口或端口范围：
```bash
# 过滤单个源端口
sudo ./net-tracer --src-port 80

# 过滤源端口范围
sudo ./net-tracer --src-port 1000-2000

# 过滤目标端口范围
sudo ./net-tracer --dst-port 8000-8080
```

#### 协议过滤
支持协议名称或协议号，可以同时指定多个协议：
```bash
# 按协议名称过滤
sudo ./net-tracer --protocol tcp

# 按多个协议过滤
sudo ./net-tracer --protocol tcp,udp

# 按协议号过滤
sudo ./net-tracer --protocol 6,17

# 使用 all 匹配所有协议
sudo ./net-tracer --protocol all
```

#### 网络接口过滤
```bash
# 按网络接口名称过滤
sudo ./net-tracer --interface eth0
```

#### 组合过滤
可以组合多个过滤条件：
```bash
# 过滤特定网段的 Web 流量
sudo ./net-tracer --src-ip 192.168.1.0/24 --dst-port 80,443 --protocol tcp

# 过滤特定接口的 DNS 流量
sudo ./net-tracer --interface eth0 --dst-port 53 --protocol udp
```

所有支持的过滤参数：
- `--src-ip`: 源IP地址或CIDR网段
- `--dst-ip`: 目标IP地址或CIDR网段
- `--src-port`: 源端口或端口范围（如：80 或 1000-2000）
- `--dst-port`: 目标端口或端口范围
- `--protocol`: 协议（支持名称如tcp,udp或协议号）
- `--interface`: 网络接口名称

## 编译说明

如需自行编译，确保已安装 Go 1.16 或更高版本：

```bash
make build
