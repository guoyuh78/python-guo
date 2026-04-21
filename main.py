#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多协议 WebSocket 代理服务端
支持 VLESS / Trojan / Shadowsocks (v2ray-plugin) 协议复用，基于 aiohttp 实现异步高并发转发。
适用于容器化部署或免费主机环境，提供自动订阅生成与保活机制。
"""

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
import time
from aiohttp import web

# ── 环境变量配置 ──────────────────────────────────────────────────────────────
# 通过环境变量注入运行时参数，便于容器化部署与动态配置
UUID = os.environ.get('UUID', '')                                            # 节点认证标识（支持带/不带连字符格式）
DOMAIN = os.environ.get('DOMAIN', '')                                        # 对外服务域名或反代域名（不含协议前缀）
SUB_PATH = os.environ.get('SUB_PATH', 'sub')                                 # 订阅接口访问路径标识
NAME = os.environ.get('NAME', '')                                            # 节点自定义名称（用于订阅显示）
WSPATH = os.environ.get('WSPATH', UUID[:8])                                  # WebSocket 通信路径，默认取 UUID 前8位
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # 服务监听端口，优先读取容器分配端口
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true'            # 是否启用自动访问保活（针对部分免费主机防休眠）
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'                        # 调试模式开关，控制日志输出级别
CONN_TIMEOUT = int(os.environ.get('CONN_TIMEOUT', '60'))                     #可配置的连接/读写超时（秒）

# ── 全局状态与常量 ────────────────────────────────────────────────────────────
CurrentDomain = DOMAIN          # 实际生效的域名或公网IP
CurrentPort   = 443             # 实际生效的对外端口（默认走TLS 443）
Tls = 'tls'                     # 传输层安全标识（tls / none）
ISP = ''                        # 运营商/地理位置标识，用于订阅节点命名
_dns_cache: dict = {}           # DNS 解析缓存表 {hostname: (ip, expire_time)}
DNS_CACHE_TTL = 300             # DNS 缓存有效期（秒）
_http_session = None            # 全局 aiohttp 客户端会话实例

DNS_SERVERS = ['8.8.4.4', '1.1.1.1']  # 备用 DoH 解析服务器
_DOH_URLS = {
    '8.8.4.4': 'https://dns.google/resolve',
    '1.1.1.1': 'https://cloudflare-dns.com/dns-query',
}
# 测速域名黑名单：防止节点被滥用为公开测速入口，消耗服务器带宽
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org',
]

# ── 日志系统配置 ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
# 抑制 aiohttp 底层高频访问日志，避免干扰核心业务日志
for _noisy in ('aiohttp.access', 'aiohttp.server', 'aiohttp.client',
               'aiohttp.internal', 'aiohttp.websocket'):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# ── 基础工具函数 ──────────────────────────────────────────────────────────────
def get_http_session() -> aiohttp.ClientSession:
    """获取或重建全局 aiohttp 客户端会话，复用连接池以提升外部请求性能"""
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'Mozilla/5.0'},
        )
    return _http_session

def is_port_available(port: int, host: str = '0.0.0.0') -> bool:
    """检测指定端口是否处于空闲可绑定状态"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port: int, max_attempts: int = 100):
    """从起始端口开始顺序探测，返回首个可用端口；若超出尝试次数则返回 None"""
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    """校验目标域名是否命中测速黑名单，支持精确匹配与子域名后缀匹配"""
    if not host:
        return False
    h = host.lower()
    return any(h == b or h.endswith('.' + b) for b in BLOCKED_DOMAINS)

def _uuid_with_dashes(raw: str) -> str:
    """将无连字符的32位UUID转换为标准8-4-4-4-12格式"""
    return f'{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}'

# ── 网络与DNS工具 ─────────────────────────────────────────────────────────────
async def get_isp() -> None:
    """通过外部API获取服务器出口IP的地理位置与运营商信息，用于订阅节点命名"""
    global ISP
    session = get_http_session()
    sources = [
        ('https://api.ip.sb/geoip', 'country_code', 'isp'),
        ('http://ip-api.com/json',  'countryCode',  'org'),
    ]
    for url, country_key, isp_key in sources:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # 拼接国家代码与运营商，替换空格为下划线以符合URL规范
                    ISP = f"{data.get(country_key, '')}-{data.get(isp_key, '')}".replace(' ', '_')
                    return
        except Exception as e:
            logger.debug(f'ISP lookup failed ({url}): {e}')
    ISP = 'Unknown'

async def get_ip() -> None:
    """确定服务对外地址与TLS策略。若未配置DOMAIN，则回退至明文IP直连模式"""
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            session = get_http_session()
            async with session.get('https://api-ipv4.ip.sb/ip') as resp:
                if resp.status == 200:
                    CurrentDomain = (await resp.text()).strip()
                    Tls = 'none'
                    CurrentPort = PORT
                    logger.warning(
                        'TLS is disabled (DOMAIN not set). '
                        'Shadowsocks subscription uses plaintext transport. '
                        'Set DOMAIN for TLS protection.'
                    )
                    return
        except Exception as e:
            logger.error(f'Failed to get public IP: {e}')
        CurrentDomain = 'change-your-domain.com'
        Tls = 'tls'
        CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

async def resolve_host(host: str) -> str:
    """基于 DoH (DNS over HTTPS) 的异步域名解析器，内置 LRU 风格缓存机制"""
    # 若传入已是合法IP地址，则直接返回，跳过解析
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    now = time.monotonic()
    # 检查缓存是否命中且未过期
    if host in _dns_cache:
        ip, expire = _dns_cache[host]
        if now < expire:
            logger.debug(f'DNS cache hit: {host} -> {ip}')
            return ip

    session = get_http_session()
    # 轮询配置的 DoH 服务器进行解析
    for dns_ip in DNS_SERVERS:
        doh_url = _DOH_URLS.get(dns_ip)
        if not doh_url:
            continue
        try:
            async with session.get(
                doh_url,
                params={'name': host, 'type': 'A'},
                headers={'Accept': 'application/dns-json'},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get('Status') == 0:
                        for answer in data.get('Answer', []):
                            if answer.get('type') == 1:  # A记录
                                resolved = answer['data']
                                _dns_cache[host] = (resolved, now + DNS_CACHE_TTL)
                                logger.debug(f'DNS resolved: {host} -> {resolved} (via {dns_ip})')
                                return resolved
        except Exception as e:
            logger.debug(f'DoH resolve failed ({dns_ip}): {e}')
    # 解析失败时降级返回原始主机名，交由底层socket处理
    logger.debug(f'DNS resolve failed for {host}, using original hostname')
    return host

# ── 协议地址解析 ──────────────────────────────────────────────────────────────
def _parse_addr(data: bytes, offset: int, atyp: int, is_vless: bool = False):
    """
    依据 SOCKS5/VLESS/Trojan 地址规范解析目标地址
    :param data: 原始二进制数据流
    :param offset: 当前解析起始偏移量
    :param atyp: 地址类型标识（1:IPv4, 2/3:域名, 3/4:IPv6）
    :param is_vless: 是否使用 VLESS 协议地址类型映射
    :return: (解析后的地址字符串, 新的偏移量) 或 (None, 原偏移量)
    """
    # VLESS 与标准 SOCKS/Trojan 的地址类型标识存在差异，需动态映射
    domain_atyp = 2 if is_vless else 3
    ipv6_atyp   = 3 if is_vless else 4
    try:
        if atyp == 1:  # IPv4 (4字节)
            if offset + 4 > len(data):
                return None, offset
            host = '.'.join(str(b) for b in data[offset:offset + 4])
            return host, offset + 4
        if atyp == domain_atyp:  # 域名 (1字节长度 + 变长字符串)
            if offset >= len(data):
                return None, offset
            host_len = data[offset]
            offset += 1
            if offset + host_len > len(data):
                return None, offset
            host = data[offset:offset + host_len].decode(errors='replace')
            return host, offset + host_len
        if atyp == ipv6_atyp:  # IPv6 (16字节，按2字节组转换为十六进制)
            if offset + 16 > len(data):
                return None, offset
            host = ':'.join(
                f'{(data[j] << 8) + data[j + 1]:04x}'
                for j in range(offset, offset + 16, 2)
            )
            return host, offset + 16
    except Exception as e:
        logger.debug(f'_parse_addr error: {e}')
    return None, offset

# ── 代理核心逻辑 ──────────────────────────────────────────────────────────────
class ProxyHandler:
    """协议处理器：负责握手校验、目标连接建立与双向数据中继"""
    def __init__(self, uuid_no_dash: str):
        self.uuid       = uuid_no_dash
        self.uuid_bytes = bytes.fromhex(uuid_no_dash)

    async def _relay(self, websocket, reader, writer) -> None:
        """
        WebSocket 与 TCP Socket 之间的全双工数据中继
        采用两个并发协程分别处理上行与下行流量，任一方向断开即终止会话
        """
        async def ws_to_tcp() -> None:
            try:
                async for msg in websocket:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        writer.write(msg.data)
                        await asyncio.wait_for(writer.drain(), timeout=CONN_TIMEOUT)
                    elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                        break
            except asyncio.TimeoutError:
                logger.debug('ws_to_tcp: drain timeout')
            except Exception as e:
                logger.debug(f'ws_to_tcp error: {e}')
            finally:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=5)
                except Exception:
                    pass

        async def tcp_to_ws() -> None:
            try:
                while True:
                    data = await asyncio.wait_for(
                        reader.read(4096), timeout=CONN_TIMEOUT
                    )
                    if not data:
                        break
                    await websocket.send_bytes(data)
            except asyncio.TimeoutError:
                logger.debug('tcp_to_ws: read timeout')
            except Exception as e:
                logger.debug(f'tcp_to_ws error: {e}')

        # 并发执行双向转发，任意协程退出即结束中继
        await asyncio.gather(ws_to_tcp(), tcp_to_ws())

    async def _connect_and_relay(self, websocket, host: str, port: int, remaining: bytes) -> None:
        """校验目标域名、解析IP、建立TCP连接并启动数据中继"""
        if is_blocked_domain(host):
            logger.debug(f'Blocked domain: {host}')
            await websocket.close()
            return

        resolved = await resolve_host(host)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolved, port),
                timeout=CONN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.debug(f'Connect timeout: {host}:{port}')
            return
        except Exception as e:
            logger.debug(f'Connect error {host}:{port}: {e}')
            return

        # 若握手阶段存在剩余载荷（如HTTP请求头或协议初始数据），优先写入目标连接
        if remaining:
            writer.write(remaining)
            await writer.drain()
        await self._relay(websocket, reader, writer)

    # ── VLESS 协议处理 ────────────────────────────────────────────────────
    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        """
        解析 VLESS 协议握手头
        结构: [1B Ver][16B UUID][1B ExtLen][Ext...][2B Port][1B AType][Addr][Payload...]
        """
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            if first_msg[1:17] != self.uuid_bytes:
                return False
            # 计算扩展字段后的偏移量：18(基础头) + ExtLen
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[i:i + 2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            host, i = _parse_addr(first_msg, i, atyp, is_vless=True)
            if host is None:
                return False
            # 返回 VLESS 响应头 [Ver=0, Status=0]
            await websocket.send_bytes(bytes([0, 0]))
            await self._connect_and_relay(websocket, host, port, first_msg[i:])
            return True
        except Exception as e:
            logger.debug(f'VLESS handler error: {e}')
        return False

    # ── Trojan 协议处理 ──────────────────────────────────────────────────
    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        """
        解析 Trojan 协议握手头
        结构: [56B SHA224 Hex][\r\n][1B Cmd][1B AType][Addr][2B Port][\r\n][Payload...]
        """
        try:
            if len(first_msg) < 58:
                return False
            received_hash = first_msg[:56].decode('ascii', errors='replace')
            def sha224(s: str) -> str:
                return hashlib.sha224(s.encode()).hexdigest()
            uuid_dash = _uuid_with_dashes(self.uuid)
            # 兼容带/不带连字符的UUID哈希校验
            if received_hash not in {sha224(self.uuid), sha224(uuid_dash)}:
                return False
            offset = 56
            if first_msg[offset:offset + 2] == b'\r\n':
                offset += 2
            if first_msg[offset] != 1:  # Cmd=1 表示 CONNECT
                return False
            offset += 1
            atyp = first_msg[offset]
            offset += 1
            host, offset = _parse_addr(first_msg, offset, atyp, is_vless=False)
            if host is None:
                return False
            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset + 2])[0]
            offset += 2
            if first_msg[offset:offset + 2] == b'\r\n':
                offset += 2
            await self._connect_and_relay(websocket, host, port, first_msg[offset:])
            return True
        except Exception as e:
            logger.debug(f'Trojan handler error: {e}')
        return False

    # ── Shadowsocks (v2ray-plugin) 协议处理 ──────────────────────────────
    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        """
        解析 Shadowsocks over WebSocket 原始载荷头
        结构: [1B AType][Addr][2B Port][Payload...]
        注：此处仅处理路由寻址部分，加密层由 v2ray-plugin 客户端前置处理
        """
        try:
            if len(first_msg) < 7:
                return False
            offset = 0
            atyp = first_msg[offset]
            offset += 1
            host, offset = _parse_addr(first_msg, offset, atyp, is_vless=False)
            if host is None:
                return False
            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset + 2])[0]
            offset += 2
            await self._connect_and_relay(websocket, host, port, first_msg[offset:])
            return True
        except Exception as e:
            logger.debug(f'Shadowsocks handler error: {e}')
        return False

# ── HTTP / WebSocket 路由控制器 ───────────────────────────────────────────────
async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    """WebSocket 接入点：路径校验、协议特征识别与分发"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    # 严格校验 WebSocket 路径，防止非法探测
    if f'/{WSPATH}' not in request.path:
        await ws.close()
        return ws

    proxy = ProxyHandler(UUID.replace('-', ''))
    try:
        # 等待客户端首帧数据，超时则断开
        first = await asyncio.wait_for(ws.receive(), timeout=10)
        if first.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        msg = first.data

        # 基于首字节与长度特征进行协议多路复用识别
        if len(msg) > 17 and msg[0] == 0:
            if await proxy.handle_vless(ws, msg):
                return ws
        if len(msg) >= 58:
            if await proxy.handle_trojan(ws, msg):
                return ws
        if len(msg) > 0 and msg[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg):
                return ws

        await ws.close()
    except asyncio.TimeoutError:
        logger.debug('WebSocket: first-message timeout')
        await ws.close()
    except Exception as e:
        logger.debug(f'WebSocket handler error: {e}')
        await ws.close()
    return ws

async def http_handler(request: web.Request) -> web.Response:
    """HTTP 路由：首页展示与 Base64 订阅接口生成"""
    if request.path == '/':
        try:
            with open('index.html', encoding='utf-8') as f:
                return web.Response(text=f.read(), content_type='text/html')
        except Exception:
            return web.Response(text='Hello world!', content_type='text/html')

    if request.path == f'/{SUB_PATH}':
        await get_isp()
        await get_ip()
        name_part  = f'{NAME}-{ISP}' if NAME else ISP
        tls_param  = 'tls' if Tls == 'tls' else 'none'
        ss_tls_str = 'tls;' if Tls == 'tls' else ''

        # 构建标准分享链接（符合 v2rayN / Clash / SIP002 规范）
        vless_url = (
            f'vless://{UUID}@{CurrentDomain}:{CurrentPort}'
            f'?encryption=none&security={tls_param}&sni={CurrentDomain}'
            f'&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}'
        )
        trojan_url = (
            f'trojan://{UUID}@{CurrentDomain}:{CurrentPort}'
            f'?security={tls_param}&sni={CurrentDomain}'
            f'&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}'
        )
        ss_auth = base64.b64encode(f'none:{UUID}'.encode()).decode()
        ss_url  = (
            f'ss://{ss_auth}@{CurrentDomain}:{CurrentPort}'
            f'?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain}'
            f';path%3D%2F{WSPATH};{ss_tls_str}sni%3D{CurrentDomain}'
            f';skip-cert-verify%3Dtrue;mux%3D0#{name_part}'
        )
        # 合并链接并进行 Base64 编码，符合通用订阅格式规范
        content = base64.b64encode(
            f'{vless_url}\n{trojan_url}\n{ss_url}'.encode()
        ).decode()
        return web.Response(text=content + '\n', content_type='text/plain')

    return web.Response(status=404, text='Not Found\n')

# ── 保活任务 ──────────────────────────────────────────────────────────────────
async def add_access_task() -> None:
    """向外部保活接口注册当前订阅地址，防止免费主机因无流量进入休眠状态"""
    if not AUTO_ACCESS or not DOMAIN:
        return
    try:
        session = get_http_session()
        await session.post(
            'https://oooo.serv00.net/add-url',
            json={'url': f'https://{DOMAIN}/{SUB_PATH}'},
        )
        logger.info('Automatic access task added successfully')
    except Exception as e:
        logger.debug(f'add_access_task failed: {e}')

# ── 服务入口与生命周期管理 ────────────────────────────────────────────────────
async def main() -> None:
    """应用初始化、端口探测、路由注册与异步事件循环启动"""
    actual_port = PORT
    if not is_port_available(actual_port):
        logger.warning(f'Port {actual_port} in use, searching for an available port...')
        actual_port = find_available_port(actual_port + 1)
        if actual_port is None:
            logger.error('No available ports found')
            sys.exit(1)
    logger.info(f'Using port {actual_port}')

    app = web.Application()
    app.router.add_get('/',            http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}',   websocket_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, '0.0.0.0', actual_port).start()
    logger.info(f'✅ Server running on port {actual_port}')

    await add_access_task()

    try:
        # 阻塞主协程，维持服务持续运行
        await asyncio.Future()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        # 优雅退出：关闭HTTP会话与Web Runner资源
        session = get_http_session()
        await session.close()
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\nServer stopped by user')
