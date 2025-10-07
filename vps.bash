# 一键写入并执行：全面的 PVE/VPS 网络虚拟化能力探针（ultimate）
cat > /usr/local/bin/pve-net-probe-ultimate.sh <<'EOF'
#!/usr/bin/env bash
# pve-net-probe-ultimate.sh
# 最全面的 PVE/VPS 网络虚拟化能力自检与自动修复脚本（中文）
# 自动安装缺失软件（apt/dnf/yum），详细检测（成功后进入仔细检测）
# 生成：/var/log/pve-net-probe-ultimate.log （文本日志）
#       /var/log/pve-net-probe-ultimate.json （JSON 报告）
# 用法: sudo /usr/local/bin/pve-net-probe-ultimate.sh [--no-install] [--no-fix] [--quick]
set -euo pipefail

LOG=/var/log/pve-net-probe-ultimate.log
REPORT=/var/log/pve-net-probe-ultimate.json
: > "$LOG"
: > "$REPORT"
exec 3>&1 1>>"$LOG" 2>&1

# 彩色输出（终端）
if [ -t 1 ]; then
  RED=$(printf '\033[1;31m'); GRE=$(printf '\033[1;32m'); YEL=$(printf '\033[1;33m'); BLU=$(printf '\033[1;34m'); RST=$(printf '\033[0m')
else
  RED='' GRE='' YEL='' BLU='' RST=''
fi

# 选项
DO_INSTALL=1
DO_FIX=1
QUICK=0
for a in "$@"; do
  case "$a" in
    --no-install) DO_INSTALL=0 ;;
    --no-fix) DO_FIX=0 ;;
    --quick) QUICK=1 ;;
    --help|-h) echo "用法: $0 [--no-install] [--no-fix] [--quick]"; exit 0 ;;
  esac
done

timestamp(){ date '+%F %T'; }
log(){ echo -e "$(timestamp) $*"; }
info(){ log "[INFO] $*"; }
warn(){ log "[WARN] $*"; }
err(){ log "[ERR]  $*"; }
ok(){ log "[OK]   $*"; }

# 安全清理子程序（确保临时对象删除）
cleanup(){
  info "开始清理临时资源..."
  # 删除可能残留的 netns
  ip -o netns list 2>/dev/null | awk '{print $1}' | grep -E '^pve_probe_ns_' | while read -r ns; do
    ip netns delete "$ns" 2>/dev/null || true
  done
  # 删除 temporary links/devices
  for d in pve_probe_veth_a pve_probe_br pve_probe_vxlan pve_probe_gre pve_dummy0 pve_probe_ovs_br pve_probe_macvlan pve_probe_ipvlan pve_probe_vlan; do
    ip link del "$d" 2>/dev/null || true
  done
  # remove temporary OVS bridge if exists
  if command -v ovs-vsctl >/dev/null 2>&1; then
    ovs-vsctl --if-exists del-br pve_probe_ovs_br 2>/dev/null || true
  fi
}
trap cleanup EXIT

# 检查是否为 root
if [ "$(id -u)" -ne 0 ]; then
  echo "请以 root 身份运行本脚本（sudo）。"
  exit 1
fi

echo "=== PVE 网络虚拟化能力自检（Ultimate） ==="
echo "日志: $LOG"
echo "JSON 报告: $REPORT"
echo ""

# helper: run cmd capturing stdout/stderr & return status
run_and_capture(){
  local out
  out=$(bash -c "$*" 2>&1) || { echo "$out"; return 1; }
  echo "$out"
  return 0
}

# ---------- 检测发行版与包管理器 ----------
PM="unknown"
DISTRO="unknown"
DISTRO_PRETTY=""
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO="$ID"
  DISTRO_PRETTY="$PRETTY_NAME"
fi
if command -v apt-get >/dev/null 2>&1; then PM="apt"
elif command -v dnf >/dev/null 2>&1; then PM="dnf"
elif command -v yum >/dev/null 2>&1; then PM="yum"; fi
info "系统: $DISTRO_PRETTY (ID=$DISTRO), 包管理器: $PM"

# ---------- 必需工具 & 自动安装 ----------
# 需要的常用工具包（名称按发行版差异）
NEEDED_CMDS=(ip ovs-vsctl brctl iptables nft ethtool tcpdump conntrack ebtables systemd-detect-virt modprobe)
NEEDED_PKGS_DEBIAN="iproute2 bridge-utils openvswitch-switch iptables nftables ethtool tcpdump conntrack ebtables"
NEEDED_PKGS_REDHAT="iproute bridge-utils openvswitch iptables-services nftables ethtool tcpdump conntrack-tools ebtables"

install_packages(){
  if [ "$DO_INSTALL" -ne 1 ]; then
    warn "跳过自动安装（--no-install）"
    return 0
  fi
  info "开始尝试自动安装缺失软件（根据系统选择）..."
  if [ "$PM" = "apt" ]; then
    apt-get update -qq || warn "apt-get update 失败"
    apt-get install -y -qq $NEEDED_PKGS_DEBIAN || warn "apt 安装部分包失败，请手动安装：$NEEDED_PKGS_DEBIAN"
  elif [ "$PM" = "dnf" ] || [ "$PM" = "yum" ]; then
    if [ "$PM" = "dnf" ]; then
      dnf install -y -q $NEEDED_PKGS_REDHAT || warn "dnf 安装失败，请手动安装：$NEEDED_PKGS_REDHAT"
    else
      yum install -y -q $NEEDED_PKGS_REDHAT || warn "yum 安装失败，请手动安装：$NEEDED_PKGS_REDHAT"
    fi
  else
    warn "未识别包管理器（$PM），跳过自动安装，请手动安装：$NEEDED_PKGS_DEBIAN 或 $NEEDED_PKGS_REDHAT"
  fi

  # 启动 openvswitch 服务（如果存在）
  if command -v ovs-vsctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q openvswitch; then
      systemctl enable --now openvswitch 2>/dev/null || systemctl enable --now openvswitch-switch 2>/dev/null || warn "尝试启动 openvswitch 服务失败"
    fi
  fi
}

# check & try install missing
check_and_install_missing(){
  local missing=()
  for cmd in "${NEEDED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    warn "发现缺失命令: ${missing[*]}"
    install_packages
  else
    ok "基础命令已就绪: ${NEEDED_CMDS[*]}"
  fi
}

# ---------- 内核 & 虚拟化检测 ----------
KVER="$(uname -r)"
info "内核版本: $KVER"
IN_CONTAINER=0
if command -v systemd-detect-virt >/dev/null 2>&1; then
  VIRT=$(systemd-detect-virt -v 2>/dev/null || true)
  if [ -n "$VIRT" ]; then
    warn "检测到虚拟化/容器环境: $VIRT （部分内核模块或功能可能被限制）"
    IN_CONTAINER=1
  fi
else
  # 备用检测
  if grep -qa container= /proc/1/environ 2>/dev/null || [ -f /.dockerenv ]; then
    warn "可能在容器内运行"
    IN_CONTAINER=1
  fi
fi

# 尝试读取内核配置预览
if [ -f /proc/config.gz ]; then
  zcat /proc/config.gz | sed -n '1,120p' > /tmp/pve_probe_kernel_config_preview.txt 2>/dev/null || true
  info "已读取 /proc/config.gz 的前几行到 /tmp/pve_probe_kernel_config_preview.txt"
elif [ -f "/boot/config-$KVER" ]; then
  head -n 120 "/boot/config-$KVER" > /tmp/pve_probe_kernel_config_preview.txt 2>/dev/null || true
  info "已读取 /boot/config-$KVER 的前几行到 /tmp/pve_probe_kernel_config_preview.txt"
else
  warn "无法读取内核 config（/proc/config.gz 或 /boot/config-$KVER 不存在）"
fi

# ---------- 尝试加载常用内核模块（不致命） ----------
try_modprobe(){
  local m=$1
  if modprobe -n -v "$m" >/dev/null 2>&1; then
    if modprobe "$m" >/dev/null 2>&1; then
      ok "已加载模块 $m"
      return 0
    else
      warn "modprobe $m 失败（可能内核未编译或权限受限）"
      return 1
    fi
  else
    warn "模块 $m 似乎不存在"
    return 1
  fi
}
MODULES_TO_TRY=(veth macvlan ipvlan vxlan br_netfilter 8021q ip_gre dummy)
for m in "${MODULES_TO_TRY[@]}"; do
  try_modprobe "$m" || true
done

# ---------- 创建临时 dummy 设备（用于安全测试） ----------
create_dummy(){
  if ip link show pve_dummy0 >/dev/null 2>&1; then
    ok "pve_dummy0 已存在"
    return 0
  fi
  if try_modprobe dummy >/dev/null 2>&1 || true; then
    ip link add pve_dummy0 type dummy 2>/dev/null || { warn "创建 dummy 设备失败"; return 1; }
    ip link set pve_dummy0 up
    ok "创建并激活 dummy 设备 pve_dummy0"
    return 0
  fi
  warn "无法创建 dummy 设备"
  return 1
}

# ---------- 记录单项检测结果结构化（准备写入 JSON） ----------
JSON_PARTS=()
add_json(){ # add_json "key" "status" "message"
  local key="$1"; local status="$2"; local msg="$3"
  # escape quotes in msg
  msg="${msg//\"/\\\"}"
  JSON_PARTS+=("{\"item\":\"$key\",\"status\":\"$status\",\"message\":\"$msg\"}")
}

# ---------- 基础 & 详细 probe 函数 ----------
probe_veth_basic(){
  info "检测 veth（基本）..."
  if ip link add pve_probe_veth_a type veth peer name pve_probe_veth_b 2>/dev/null; then
    ip link del pve_probe_veth_a 2>/dev/null || true
    ok "veth 基本创建测试通过"
    add_json "veth_basic" "ok" "veth pair 创建成功"
    return 0
  else
    warn "veth 基本创建测试失败"
    add_json "veth_basic" "fail" "无法创建 veth pair"
    return 1
  fi
}

probe_veth_detailed(){
  info "veth 进入仔细检测：创建 namespace，分配地址并 ping"
  ns="pve_probe_ns_veth_$(date +%s%N | tail -c 6)"
  ip netns add "$ns"
  set -o errexit
  ip link add pve_probe_veth_a type veth peer name pve_probe_veth_b || { err "创建 veth pair 失败"; ip netns delete "$ns" 2>/dev/null || true; add_json "veth_detailed" "fail" "创建 veth 失败"; return 1; }
  ip link set pve_probe_veth_b netns "$ns"
  ip addr add 10.254.254.1/24 dev pve_probe_veth_a || true
  ip link set pve_probe_veth_a up
  ip netns exec "$ns" ip addr add 10.254.254.2/24 dev pve_probe_veth_b || true
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip link set pve_probe_veth_b up
  sleep 0.5
  if ip netns exec "$ns" ping -c 1 -W 1 10.254.254.1 >/dev/null 2>&1; then
    ok "veth 详细测试通过（namespace 内 ping 主机成功）"
    add_json "veth_detailed" "ok" "veth+netns 双向连通（ping 成功）"
    ip netns delete "$ns"
    ip link del pve_probe_veth_a 2>/dev/null || true
    return 0
  else
    warn "veth 详细测试失败：namespace 无法 ping 主机"
    add_json "veth_detailed" "fail" "veth+netns ping 失败"
    ip netns delete "$ns" 2>/dev/null || true
    ip link del pve_probe_veth_a 2>/dev/null || true
    return 1
  fi
}

probe_bridge_basic(){
  info "检测 bridge（基本）..."
  if ip link add name pve_probe_br type bridge 2>/dev/null; then
    ip link del pve_probe_br 2>/dev/null || true
    ok "bridge 基本创建测试通过"
    add_json "bridge_basic" "ok" "bridge 创建成功"
    return 0
  else
    warn "bridge 基本创建失败"
    add_json "bridge_basic" "fail" "无法创建 bridge"
    return 1
  fi
}

probe_bridge_detailed(){
  info "bridge 进入仔细检测：veth + bridge + namespace 连通性测试"
  ns="pve_probe_ns_br_$(date +%s%N | tail -c 6)"
  ip netns add "$ns"
  ip link add pve_probe_br type bridge
  ip link add pve_probe_veth_a type veth peer name pve_probe_veth_b
  ip link set pve_probe_veth_b netns "$ns"
  ip link set pve_probe_veth_a master pve_probe_br
  ip link set pve_probe_veth_a up
  ip link set pve_probe_br up
  ip netns exec "$ns" ip link set pve_probe_veth_b up
  ip addr add 192.168.250.1/24 dev pve_probe_veth_a || true
  ip netns exec "$ns" ip addr add 192.168.250.2/24 dev pve_probe_veth_b || true
  sleep 0.5
  if ip netns exec "$ns" ping -c 1 -W 1 192.168.250.1 >/dev/null 2>&1; then
    ok "bridge 详细测试通过（namespace <-> host 通过 bridge 通信）"
    add_json "bridge_detailed" "ok" "bridge+veth+netns 连通"
    ip netns delete "$ns"
    ip link del pve_probe_br 2>/dev/null || true
    return 0
  else
    warn "bridge 详细测试失败"
    add_json "bridge_detailed" "fail" "bridge 连通性测试失败"
    ip netns delete "$ns" 2>/dev/null || true
    ip link del pve_probe_br 2>/dev/null || true
    return 1
  fi
}

probe_macvlan_basic(){
  info "检测 macvlan（基本）..."
  create_dummy || true
  if ip link add link pve_dummy0 name pve_probe_macvlan0 type macvlan mode bridge 2>/dev/null; then
    ip link del pve_probe_macvlan0 2>/dev/null || true
    ok "macvlan 基本创建测试通过"
    add_json "macvlan_basic" "ok" "macvlan 在 dummy 上创建成功"
    return 0
  else
    warn "macvlan 基本创建失败"
    add_json "macvlan_basic" "fail" "macvlan 在 dummy 上创建失败"
    return 1
  fi
}

probe_macvlan_detailed(){
  info "macvlan 进入仔细检测：创建 netns 并测试 IP 可达性与宿主互通性质（注意：host<->macvlan 可能隔离）"
  ns="pve_probe_ns_macvlan_$(date +%s%N | tail -c 6)"
  ip netns add "$ns"
  ip link add link pve_dummy0 name pve_probe_macvlan0 type macvlan mode bridge
  ip link set pve_probe_macvlan0 netns "$ns"
  ip netns exec "$ns" ip addr add 10.253.253.2/24 dev pve_probe_macvlan0 || true
  ip netns exec "$ns" ip link set pve_probe_macvlan0 up
  ip addr add 10.253.253.1/24 dev pve_dummy0 || true
  ip link set pve_dummy0 up
  sleep 0.5
  # 尝试从 host ping namespace
  if ip netns exec "$ns" ping -c 1 -W 1 10.253.253.1 >/dev/null 2>&1; then
    ok "macvlan 详细测试：namespace -> host ping 成功"
    # 再试 host -> ns
    if ping -c 1 -W 1 10.253.253.2 >/dev/null 2>&1; then
      ok "macvlan 详细测试：host -> namespace ping 也成功（说明 macvlan 模式允许 host 通信）"
      add_json "macvlan_detailed" "ok" "双向可达"
    else
      warn "macvlan 模式 host -> ns 无法 ping（macvlan host-isolation）"
      add_json "macvlan_detailed" "partial" "ns->host 可达，但 host->ns 受限（典型 macvlan 隔离情形）"
    fi
  else
    warn "macvlan 详细测试：namespace -> host ping 失败"
    add_json "macvlan_detailed" "fail" "ns->host ping 失败"
  fi
  ip netns delete "$ns" 2>/dev/null || true
  ip addr del 10.253.253.1/24 dev pve_dummy0 2>/dev/null || true
  ip link del pve_probe_macvlan0 2>/dev/null || true
}

probe_ipvlan_basic(){
  info "检测 ipvlan（基本）..."
  create_dummy || true
  if ip link add link pve_dummy0 name pve_probe_ipvlan0 type ipvlan mode l2 2>/dev/null; then
    ip link del pve_probe_ipvlan0 2>/dev/null || true
    ok "ipvlan 基本创建测试通过"
    add_json "ipvlan_basic" "ok" "ipvlan 在 dummy 上创建成功"
    return 0
  else
    warn "ipvlan 创建失败"
    add_json "ipvlan_basic" "fail" "ipvlan 创建失败"
    return 1
  fi
}

probe_ipvlan_detailed(){
  info "ipvlan 进入仔细检测：netns 测试"
  ns="pve_probe_ns_ipvlan_$(date +%s%N | tail -c 6)"
  ip netns add "$ns"
  ip link add link pve_dummy0 name pve_probe_ipvlan0 type ipvlan mode l2
  ip link set pve_probe_ipvlan0 netns "$ns"
  ip netns exec "$ns" ip addr add 10.252.252.2/24 dev pve_probe_ipvlan0 || true
  ip netns exec "$ns" ip link set pve_probe_ipvlan0 up
  ip addr add 10.252.252.1/24 dev pve_dummy0 || true
  ip link set pve_dummy0 up
  sleep 0.5
  if ip netns exec "$ns" ping -c 1 -W 1 10.252.252.1 >/dev/null 2>&1; then
    ok "ipvlan 详细测试通过（ns->host ping 成功）"
    add_json "ipvlan_detailed" "ok" "ipvlan ns->host 可达"
  else
    warn "ipvlan 详细测试失败"
    add_json "ipvlan_detailed" "fail" "ipvlan ns->host ping 失败"
  fi
  ip netns delete "$ns" 2>/dev/null || true
  ip addr del 10.252.252.1/24 dev pve_dummy0 2>/dev/null || true
  ip link del pve_probe_ipvlan0 2>/dev/null || true
}

probe_vlan_basic(){
  info "检测 802.1q VLAN 模块（基本）..."
  if modprobe 8021q >/dev/null 2>&1; then
    ok "8021q 模块存在"
    add_json "vlan_basic" "ok" "8021q 模块加载成功"
    return 0
  else
    warn "8021q 模块可能不存在或加载失败"
    add_json "vlan_basic" "fail" "8021q 模块不可用"
    return 1
  fi
}

probe_vlan_detailed(){
  info "VLAN 进入仔细检测：在 dummy 上创建 vlan 接口"
  create_dummy || true
  if ip link add link pve_dummy0 name pve_probe_vlan type vlan id 100 2>/dev/null; then
    ip link set pve_probe_vlan up
    ok "VLAN 详细创建成功（dummy0.100）"
    add_json "vlan_detailed" "ok" "vlan 在 dummy 上创建与激活成功"
    ip link del pve_probe_vlan 2>/dev/null || true
    return 0
  else
    warn "VLAN 详细创建失败"
    add_json "vlan_detailed" "fail" "vlan 在 dummy 上创建失败"
    return 1
  fi
}

probe_ovs(){
  info "检测 Open vSwitch (OVS)..."
  if command -v ovs-vsctl >/dev/null 2>&1; then
    ok "发现 ovs-vsctl"
    add_json "ovs_presence" "ok" "ovs-vsctl 可用"
    # 详细测试：创建临时 OVS bridge，并通过 veth 验证
    info "OVS 进入仔细检测：创建临时 ovs bridge"
    ovs-vsctl --may-exist add-br pve_probe_ovs_br || true
    ip link add pve_probe_veth_a type veth peer name pve_probe_veth_b || true
    ovs-vsctl --if-exists add-port pve_probe_ovs_br pve_probe_veth_a || true
    ip link set pve_probe_veth_a up || true
    ip link set pve_probe_veth_b up || true
    sleep 0.5
    if ovs-vsctl list-br | grep -q pve_probe_ovs_br; then
      ok "OVS 临时 bridge 创建成功"
      add_json "ovs_detailed" "ok" "OVS 临时 bridge 创建成功"
      return 0
    else
      warn "OVS 临时 bridge 创建检测失败"
      add_json "ovs_detailed" "fail" "OVS 临时 bridge 创建失败"
      return 1
    fi
  else
    warn "未安装 OVS"
    add_json "ovs_presence" "fail" "ovs-vsctl 未安装"
    return 1
  fi
}

probe_vrf(){
  info "检测 VRF 支持..."
  ns="pve_probe_ns_vrf_$(date +%s%N | tail -c 6)"
  ip netns add "$ns"
  if ip netns exec "$ns" ip link add dev pve_probe_vrf type vrf table 100 2>/dev/null; then
    ok "VRF 创建测试通过"
    add_json "vrf" "ok" "VRF 支持"
    ip netns delete "$ns" 2>/dev/null || true
    return 0
  else
    warn "VRF 创建测试失败"
    add_json "vrf" "fail" "VRF 不可用"
    ip netns delete "$ns" 2>/dev/null || true
    return 1
  fi
}

probe_vxlan(){
  info "检测 VXLAN 支持..."
  if ip link add name pve_probe_vxlan type vxlan id 42 dev pve_dummy0 >/dev/null 2>&1; then
    ip link del pve_probe_vxlan 2>/dev/null || true
    ok "VXLAN 支持"
    add_json "vxlan" "ok" "vxlan 创建设备成功"
    return 0
  else
    warn "VXLAN 创建失败"
    add_json "vxlan" "fail" "vxlan 不可用"
    return 1
  fi
}

probe_gre(){
  info "检测 GRE/gretap 支持..."
  if ip link add gre_probe type gretap remote 127.0.0.1 local 127.0.0.1 ttl 64 >/dev/null 2>&1; then
    ip link del gre_probe 2>/dev/null || true
    ok "GRE 支持"
    add_json "gre" "ok" "gretap 创建设备成功"
    return 0
  else
    warn "GRE 创建失败"
    add_json "gre" "fail" "GRE 不可用"
    return 1
  fi
}

probe_nat(){
  info "检测 NAT 支持（iptables/nftables）..."
  if command -v iptables >/dev/null 2>&1 && iptables -t nat -L >/dev/null 2>&1; then
    ok "iptables NAT 表可用"
    add_json "nat_iptables" "ok" "iptables nat 可用"
    return 0
  fi
  if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q nat; then
    ok "nftables NAT 表可用"
    add_json "nat_nft" "ok" "nftables nat 表可用"
    return 0
  fi
  warn "未检测到 NAT 支持"
  add_json "nat" "fail" "未检测到 iptables 或 nft nat 支持"
  return 1
}

probe_ebtables(){
  info "检测 ebtables 支持..."
  if command -v ebtables >/dev/null 2>&1; then
    ok "ebtables 可用"
    add_json "ebtables" "ok" "ebtables 工具存在"
    return 0
  else
    warn "ebtables 未安装"
    add_json "ebtables" "fail" "ebtables 不存在"
    return 1
  fi
}

probe_conntrack(){
  info "检测 conntrack 支持..."
  if [ -f /proc/net/nf_conntrack ] || [ -f /proc/net/ip_conntrack ]; then
    ok "内核 conntrack 表存在"
    add_json "conntrack" "ok" "内核 conntrack 表可用"
    return 0
  fi
  if command -v conntrack >/dev/null 2>&1; then
    if conntrack -L >/dev/null 2>&1; then
      ok "conntrack-tools 可用"
      add_json "conntrack_tool" "ok" "conntrack-tools 可用"
      return 0
    fi
  fi
  warn "未检测到 conntrack"
  add_json "conntrack" "fail" "conntrack 不可用"
  return 1
}

probe_ethtool(){
  info "检测 ethtool 并读取关键网卡特性（如 offload）"
  if ! command -v ethtool >/dev/null 2>&1; then
    warn "ethtool 未安装"
    add_json "ethtool" "fail" "ethtool 未安装"
    return 1
  fi
  # 选主网卡（除 lo）
  MAINIF=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1 || true)
  if [ -z "$MAINIF" ]; then
    warn "未找到非 lo 的接口，跳过 ethtool 检查"
    add_json "ethtool" "fail" "无主接口"
    return 1
  fi
  out=$(ethtool -k "$MAINIF" 2>/dev/null || true)
  ok "ethtool 可用，读取 $MAINIF 的 offload 特性"
  add_json "ethtool" "ok" "ethtool for $MAINIF: ${out//$'\n'/\\n}"
  return 0
}

probe_mtu_and_promisc(){
  info "检测 MTU、promisc 与基本统计"
  MAINIF=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1 || true)
  if [ -z "$MAINIF" ]; then
    warn "未找到主接口"
    add_json "mtu_promisc" "fail" "无主接口"
    return 1
  fi
  mtu=$(ip -o link show "$MAINIF" | awk '{for(i=1;i<=NF;i++) if($i~/mtu/) print $(i+1)}' || true)
  promisc=$(cat /sys/class/net/"$MAINIF"/flags 2>/dev/null || true)
  stats=$(cat /sys/class/net/"$MAINIF"/statistics/tx_packets 2>/dev/null || true)
  add_json "mtu_promisc" "ok" "iface=$MAINIF mtu=$mtu flags=$promisc tx_packets=$stats"
  ok "读取到接口 $MAINIF MTU=$mtu"
  return 0
}

probe_sysctl(){
  info "检查关键 sysctl（ip_forward/br_netfilter/rp_filter）"
  ipf=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "N/A")
  brnf=$(sysctl -n net.bridge.bridge-nf-call-iptables 2>/dev/null || echo "N/A")
  rp=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo "N/A")
  add_json "sysctl" "ok" "ip_forward=$ipf bridge-nf-call-iptables=$brnf rp_filter=$rp"
  ok "sysctl: ip_forward=$ipf bridge-nf-call-iptables=$brnf rp_filter=$rp"
  return 0
}

# ---------- 自动修复（可选） ----------
auto_fix_sysctl(){
  if [ "$DO_FIX" -ne 1 ]; then
    warn "跳过自动修复 sysctl（--no-fix）"
    return
  fi
  info "尝试开启 net.ipv4.ip_forward 与 bridge-nf-call-iptables 持久化"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || warn "设置 ip_forward 失败"
  # br_netfilter 模块如果存在则设置
  if modprobe br_netfilter >/dev/null 2>&1; then
    sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null 2>&1 || warn "设置 bridge-nf-call-iptables 失败"
  fi
  cat > /etc/sysctl.d/99-pve-net-probe.conf <<SYSCTL
# PVE 网络探针持久化设置（自动写入）
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
SYSCTL
  sysctl --system >/dev/null 2>&1 || warn "sysctl --system 加载失败"
  ok "尝试写入 /etc/sysctl.d/99-pve-net-probe.conf 并应用"
  add_json "auto_fix_sysctl" "ok" "设置 ip_forward、bridge-nf-call-iptables 并写入 /etc/sysctl.d"
}

# ---------- 汇总检测并按能力生成推荐 ----------
DETECTED_CAPS=()

run_all_probes(){
  info "=== 开始基础能力探针 ==="
  check_and_install_missing
  probe_veth_basic && DETECTED_CAPS+=("veth")
  probe_bridge_basic && DETECTED_CAPS+=("bridge")
  probe_macvlan_basic && DETECTED_CAPS+=("macvlan")
  probe_ipvlan_basic && DETECTED_CAPS+=("ipvlan")
  probe_vlan_basic && DETECTED_CAPS+=("vlan")
  probe_ovs || true
  probe_vrf || true
  probe_vxlan || true
  probe_gre || true
  probe_nat || true
  probe_ebtables || true
  probe_conntrack || true
  probe_ethtool || true
  probe_mtu_and_promisc || true
  probe_sysctl || true
  info "=== 基础能力探针完成 ==="
  add_json "detected_caps" "info" "${DETECTED_CAPS[*]}"
}

# 如果基础探针有关键通过，则进入仔细检测
run_detailed_checks(){
  info "=== 开始仔细检测（详细测试） ==="
  # 使用 dummy 设备作为测试基底
  create_dummy || warn "创建 dummy 失败，某些测试可能跳过"
  # veth 详细
  if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "veth"; then
    probe_veth_detailed || warn "veth 详细检测失败"
  fi
  if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "bridge"; then
    probe_bridge_detailed || warn "bridge 详细检测失败"
  fi
  if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "macvlan"; then
    probe_macvlan_detailed || warn "macvlan 详细检测失败"
  fi
  if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "ipvlan"; then
    probe_ipvlan_detailed || warn "ipvlan 详细检测失败"
  fi
  if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "vlan"; then
    probe_vlan_detailed || warn "vlan 详细检测失败"
  fi
  # OVS 详细在 probe_ovs 已部分执行
  if command -v ovs-vsctl >/dev/null 2>&1; then
    probe_ovs || warn "OVS 详细检测失败"
  fi
  info "=== 仔细检测完成 ==="
}

# ---------- 生成推荐（策略选择器） ----------
generate_recommendation(){
  info "=== 生成推荐方案 ==="
  local recs=()
  # 首选：bridge + veth
  if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "bridge" && printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "veth"; then
    recs+=("桥接 (bridge + veth)：最兼容 PVE/KVM/LXC，容器/VM 可直接桥接到宿主网，端口/防火墙控制灵活。")
  fi
  # OVS
  if command -v ovs-vsctl >/dev/null 2>&1; then
    recs+=("Open vSwitch：适合需要策略/流表、overlay 隧道 (VXLAN/GRE) 或 SDN 应用场景。")
  fi
  # macvlan / ipvlan 当宿主不允许 bridge
  if ! printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "bridge"; then
    if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "macvlan"; then
      recs+=("macvlan：当云厂商禁止 bridge 时的替代方案（注意 host<->container 的通信可能受限）。")
    fi
    if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "ipvlan"; then
      recs+=("ipvlan：与 macvlan 相似，某些场景下更接近主机转发行为。")
    fi
  fi
  # overlay
  if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "vxlan" || printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "gre"; then
    recs+=("Overlay (VXLAN/GRE)：可跨宿主机构建二层网络，适合分布式集群/跨机房通信。")
  fi
  # NAT 作为最后退路
  if printf '%s\n' "${DETECTED_CAPS[@]}" | grep -q "nat"; then
    recs+=("NAT/路由（iptables/nft）：当无法做 bridge 或 provider 限制较多时，使用 NAT 是最保守的兼容方案（会改变源 IP，端口映射需要额外配置）。")
  fi
  if [ "${#recs[@]}" -eq 0 ]; then
    recs+=("未检测到可用的网络虚拟化能力；建议联系云商或检查内核/配置。")
  fi

  info "推荐（按优先级）："
  for i in "${!recs[@]}"; do
    echo " $((i+1)). ${recs[i]}"
  done
  add_json "recommendations" "info" "$(printf '%s; ' "${recs[@]}")"
}

# ---------- 运行流程 ----------
info "开始运行（若需跳过自动安装或自动修复，请用 --no-install / --no-fix）"
check_and_install_missing
run_all_probes

# 若检测到 veth/bridge 等关键能力，则进入仔细检测（除非 quick 模式）
if [ "$QUICK" -eq 0 ]; then
  run_detailed_checks
else
  info "快速模式（--quick）：跳过仔细检测"
fi

# 自动修复 sysctl（可选）
auto_fix_sysctl

# 生成推荐
generate_recommendation

# 写 JSON 报告
echo "[" > "$REPORT"
first=1
for p in "${JSON_PARTS[@]}"; do
  if [ "$first" -eq 1 ]; then
    echo "$p" >> "$REPORT"
    first=0
  else
    echo ",$p" >> "$REPORT"
  fi
done
echo "]" >> "$REPORT"
ok "JSON 报告已写入：$REPORT"
ok "文本日志已写入：$LOG"

# 最后输出简单摘要（也输出到终端）
echo ""
echo -e "${GRE}检测完成 - 简要结果（查看完整日志: sudo less $LOG; JSON: sudo less $REPORT）${RST}"
# 摘要：列出通过项
echo "检测到的能力（摘要）: ${DETECTED_CAPS[*]:-（无）}"
echo ""
echo -e "${YEL}注意：脚本尝试自动安装并修复常见问题，但无法更改云厂商底层网络限制。如果检测失败，建议查看日志并按日志中建议操作（或把日志粘贴到聊天来让我帮你分析）。${RST}"
EOF