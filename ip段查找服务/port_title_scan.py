#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 段端口 + 浏览器标题扫描器

特性：
- 支持超大段扫描（/8 /16），基于生成器 + 批量任务，低内存占用
- TCP 端口探测与 HTTP(S) title 获取分离并发控制
- 支持标题 / 响应体关键字匹配
- 支持 http / https / socks5 代理
- 实时写入结果，支持 txt / json / csv
- 支持断点续扫（记录最后处理的 IP）
- 优雅退出（Ctrl+C 保存进度）

依赖：
    pip install aiohttp
    如需 socks5 代理：pip install aiohttp-socks
"""

import argparse
import asyncio
import csv
import gc
import io
import ipaddress
import json
import os
import random
import re
import signal
import sys
import time
from datetime import datetime


def check_dependencies():
    """检查依赖"""
    try:
        import aiohttp
        return aiohttp
    except ImportError:
        print("[!] 缺少依赖 aiohttp，请执行: pip install aiohttp")
        print("    如需 socks5 代理，额外执行: pip install aiohttp-socks")
        sys.exit(1)


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
]


class MassScanner:
    def __init__(self, args, aiohttp_module):
        self.args = args
        self.aiohttp = aiohttp_module

        # 双并发控制：TCP 探测可以更高并发，HTTP 请求单独限制
        self.tcp_sem = asyncio.Semaphore(args.tcp_threads)
        self.http_sem = asyncio.Semaphore(args.http_threads)

        self.running = True
        self.start_time = time.time()
        self.last_ip = None

        self.stats = {"scanned": 0, "open": 0, "matched": 0, "errors": 0}
        self.lock = asyncio.Lock()

        self.output_file = args.output or self._auto_output_file()
        self.status_file = args.status_file or self._auto_status_file()
        self._init_output()

        # 信号处理：优雅退出
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (ValueError, AttributeError):
            pass

    def _auto_output_file(self):
        """自动生成输出文件名"""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip_part = (self.args.ip or "from_file").replace("/", "_").replace(":", "_")[:50]
        port_part = str(self.args.port).replace(",", "-").replace(" ", "")[:30]
        base = f"scan_{ip_part}_{port_part}_{ts}"
        ext = {"txt": ".txt", "json": ".json", "csv": ".csv"}[self.args.format]
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), base + ext)

    def _auto_status_file(self):
        """自动生成状态文件名"""
        base = os.path.splitext(os.path.basename(self.output_file))[0]
        return os.path.join(os.path.dirname(self.output_file), f".{base}.status")

    def _init_output(self):
        """初始化输出文件"""
        if self.args.format == "csv":
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "port", "scheme", "url", "title", "body_matched", "status", "time"])
        elif self.args.format == "json":
            with open(self.output_file, "w", encoding="utf-8") as f:
                pass
        else:
            with open(self.output_file, "w", encoding="utf-8") as f:
                f.write(f"# 目标: {self.args.ip or self.args.ip_file}\n")
                f.write(f"# 端口: {self.args.port}\n")
                f.write(f"# 标题关键字: {self.args.keyword}\n")
                if self.args.body_keyword:
                    f.write(f"# 响应体关键字: {self.args.body_keyword}\n")
                if self.args.no_http:
                    f.write("# IP:PORT\tBANNER\n")
                else:
                    f.write("# URL\tTITLE\n")

    def _signal_handler(self, signum, frame):
        """信号处理"""
        signame = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        print(f"\n[!] 收到信号 {signame}，正在保存进度并退出...")
        self.running = False
        self._save_status()
        sys.exit(0)

    def _save_status(self):
        """保存扫描进度"""
        if self.last_ip and self.status_file:
            try:
                with open(self.status_file, "w", encoding="utf-8") as f:
                    f.write(self.last_ip)
                if not self.args.quiet:
                    print(f"[*] 进度已保存: {self.status_file} (最后IP: {self.last_ip})")
            except Exception as e:
                print(f"[!] 保存进度失败: {e}")

    def _load_status(self):
        """加载扫描进度"""
        if self.args.resume and self.status_file and os.path.exists(self.status_file):
            try:
                with open(self.status_file, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except Exception:
                return None
        return None

    def ip_generator(self):
        """按需生成 IP，不占用内存"""
        resume_ip = self._load_status()
        found_resume = resume_ip is None

        sources = []
        if self.args.ip_file:
            sources.append(self._read_ip_file())
        if self.args.ip:
            sources.append(self._parse_ip_line(self.args.ip))

        for source in sources:
            for ip in source:
                if not self.running:
                    break
                if not found_resume:
                    if ip == resume_ip:
                        found_resume = True
                    continue
                self.last_ip = ip
                yield ip

    def _read_ip_file(self):
        """从文件读取 IP 列表"""
        with open(self.args.ip_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                yield from self._parse_ip_line(line)

    def _parse_ip_line(self, line):
        """解析单行 IP 描述：CIDR / 范围 / 单个 IP"""
        line = line.strip()
        if not line:
            return

        # 范围格式: 1.1.1.1-1.1.2.255
        if "-" in line and "/" not in line:
            try:
                start, end = line.split("-", 1)
                start_ip = int(ipaddress.ip_address(start.strip()))
                end_ip = int(ipaddress.ip_address(end.strip()))
                for i in range(start_ip, end_ip + 1):
                    yield str(ipaddress.ip_address(i))
            except ValueError as e:
                print(f"[!] 解析IP范围失败 {line}: {e}")
            return

        # CIDR 或单个 IP
        try:
            network = ipaddress.ip_network(line, strict=False)
            for host in network.hosts():
                yield str(host)
        except ValueError:
            try:
                ipaddress.ip_address(line)
                yield line
            except ValueError:
                print(f"[!] 无法解析IP: {line}")

    def get_ports(self):
        """解析端口列表"""
        ports = []
        if self.args.ports_file and os.path.exists(self.args.ports_file):
            with open(self.args.ports_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ports.extend(self._parse_ports(line))
        if self.args.port:
            ports.extend(self._parse_ports(str(self.args.port)))
        return sorted(set(ports)) if ports else [80]

    def _parse_ports(self, s):
        """解析端口字符串，支持 80,443,8080-8090"""
        result = []
        for part in s.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    result.extend(range(int(start), int(end) + 1))
                except ValueError:
                    print(f"[!] 解析端口范围失败: {part}")
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    print(f"[!] 无效端口: {part}")
        return result

    def _create_session(self):
        """创建 aiohttp session"""
        proxy = self.args.proxy
        connector = None

        # socks5 代理需要 aiohttp-socks
        if proxy and proxy.startswith(("socks5://", "socks4://")):
            try:
                from aiohttp_socks import ProxyConnector
                connector = ProxyConnector.from_url(proxy)
            except ImportError:
                print("[!] 使用 socks5 代理需要安装 aiohttp-socks: pip install aiohttp-socks")
                sys.exit(1)

        if connector is None:
            ssl_context = False
            connector = self.aiohttp.TCPConnector(
                limit=self.args.http_threads * 2,
                limit_per_host=2,
                ssl=ssl_context,
                enable_cleanup_closed=True,
                force_close=True,
            )

        timeout = self.aiohttp.ClientTimeout(total=self.args.http_timeout)
        return self.aiohttp.ClientSession(connector=connector, timeout=timeout)

    async def run(self):
        """主扫描循环"""
        ports = self.get_ports()
        if not ports:
            print("[!] 没有指定端口")
            return

        if not self.args.quiet:
            print(f"[*] 输出文件: {self.output_file}")
            print(f"[*] 端口: {ports}")
            print(f"[*] TCP并发: {self.args.tcp_threads}, HTTP并发: {self.args.http_threads}")
            print(f"[*] TCP超时: {self.args.tcp_timeout}s, HTTP超时: {self.args.http_timeout}s")
            print(f"[*] 批次大小: {self.args.batch}")
            if self.args.proxy:
                print(f"[*] 代理: {self.args.proxy}")
            if self.args.resume:
                print(f"[*] 断点续扫模式，状态文件: {self.status_file}")

        async with self._create_session() as session:
            batch = []
            counter = 0

            for ip in self.ip_generator():
                for port in ports:
                    batch.append(asyncio.create_task(self._scan_target(session, ip, port)))

                if len(batch) >= self.args.batch:
                    await asyncio.gather(*batch, return_exceptions=True)
                    batch = []
                    counter += 1
                    if counter % 10 == 0:
                        gc.collect()
                    if not self.args.quiet:
                        self._print_progress()

                if not self.running:
                    break

            if batch:
                await asyncio.gather(*batch, return_exceptions=True)

        self._save_status()
        if not self.args.quiet:
            self._print_progress(final=True)
            print(f"\n[+] 扫描完成，结果保存至: {self.output_file}")

    async def _scan_target(self, session, ip, port):
        """扫描单个目标"""
        if not self.running:
            return

        # TCP 端口探测
        async with self.tcp_sem:
            if not self.running:
                return
            is_open = await self._tcp_probe(ip, port)

        async with self.lock:
            self.stats["scanned"] += 1

        if not is_open:
            return

        async with self.lock:
            self.stats["open"] += 1

        # 只扫描端口模式：可选抓取 Banner 并匹配关键字
        if self.args.no_http:
            if self.args.grab_banner:
                banner = await self._grab_banner(ip, port)
                matched = False
                if self.args.keyword and self.args.keyword.lower() in banner.lower():
                    matched = True
                if self.args.body_keyword and self.args.body_keyword.lower() in banner.lower():
                    matched = True
                # 有关键字则只保存命中的；无关键字则保存所有开放端口的 Banner
                if matched:
                    async with self.lock:
                        self.stats["matched"] += 1
                    await self._save_port_only(ip, port, banner=banner)
                elif not self.args.keyword and not self.args.body_keyword:
                    await self._save_port_only(ip, port, banner=banner)
            else:
                await self._save_port_only(ip, port)
            return

        # HTTP(S) 标题识别
        async with self.http_sem:
            if not self.running:
                return
            await self._http_check(session, ip, port)

    async def _tcp_probe(self, ip, port):
        """TCP 端口探测"""
        try:
            conn = asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.args.tcp_timeout,
            )
            reader, writer = await conn
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    async def _grab_banner(self, ip, port):
        """抓取 TCP Banner（用于 SSH/FTP 等非 HTTP 服务识别）"""
        try:
            conn = asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.args.tcp_timeout,
            )
            reader, writer = await conn
            try:
                # 部分服务需要主动发送换行才会回显 Banner
                writer.write(b"\r\n")
                await writer.drain()
            except Exception:
                pass

            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=self.args.banner_timeout)
            except asyncio.TimeoutError:
                data = b""

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            banner = data.decode("utf-8", errors="ignore").strip()
            # 过滤不可见字符
            banner = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f]", " ", banner)
            return banner[:500]
        except Exception:
            return ""

    async def _http_check(self, session, ip, port):
        """HTTP(S) 请求并匹配标题/响应体"""
        headers = {
            "User-Agent": random.choice(USER_AGENTS) if self.args.random_ua else USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }

        schemes = ["http", "https"]
        if self.args.no_https:
            schemes = ["http"]
        elif self.args.no_http_proto:
            schemes = ["https"]

        for scheme in schemes:
            if not self.running:
                return

            url = f"{scheme}://{ip}:{port}"
            last_error = None

            for attempt in range(self.args.retries + 1):
                try:
                    kwargs = {"headers": headers, "allow_redirects": self.args.follow_redirects}
                    if self.args.proxy and not self.args.proxy.startswith(("socks5://", "socks4://")):
                        kwargs["proxy"] = self.args.proxy

                    async with session.get(url, **kwargs) as resp:
                        status = resp.status
                        if not (self.args.min_status <= status <= self.args.max_status):
                            break

                        text = await resp.text(errors="ignore")
                        title = self._extract_title(text)

                        # 标题匹配
                        title_match = False
                        if self.args.keyword:
                            if self.args.keyword.lower() in title.lower():
                                title_match = True

                        # 响应体匹配
                        body_match = False
                        if self.args.body_keyword:
                            if self.args.body_keyword.lower() in text.lower():
                                body_match = True

                        # 只要标题或响应体命中就算匹配
                        matched = title_match or (self.args.body_keyword and body_match)

                        if matched:
                            async with self.lock:
                                self.stats["matched"] += 1
                            await self._save_result(
                                ip=ip,
                                port=port,
                                scheme=scheme,
                                url=url,
                                title=title,
                                body_matched=body_match,
                                status=status,
                            )
                            return

                    # 该 scheme 请求成功但未命中，不需要重试
                    break

                except Exception as e:
                    last_error = e
                    await asyncio.sleep(0.1 * (attempt + 1))

            if last_error:
                async with self.lock:
                    self.stats["errors"] += 1

    def _extract_title(self, html):
        """从 HTML 中提取 title"""
        if not html:
            return ""
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
            return title
        return ""

    async def _save_port_only(self, ip, port, banner=""):
        """仅保存开放端口（可附带 Banner）"""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        async with self.lock:
            if self.args.format == "json":
                line = json.dumps({"ip": ip, "port": port, "banner": banner, "time": ts}, ensure_ascii=False) + "\n"
            elif self.args.format == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow([ip, port, "", "", banner, "", "", ts])
                line = output.getvalue()
            else:
                if banner:
                    line = f"{ip}:{port}\t{banner}\n"
                else:
                    line = f"{ip}:{port}\n"
            await asyncio.to_thread(self._write_line, line)

    async def _save_result(self, ip, port, scheme, url, title, body_matched, status):
        """保存匹配结果"""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        async with self.lock:
            if self.args.format == "json":
                line = json.dumps(
                    {
                        "ip": ip,
                        "port": port,
                        "scheme": scheme,
                        "url": url,
                        "title": title,
                        "body_matched": body_matched,
                        "status": status,
                        "time": ts,
                    },
                    ensure_ascii=False,
                ) + "\n"
            elif self.args.format == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow([ip, port, scheme, url, title, body_matched, status, ts])
                line = output.getvalue()
            else:
                line = f"{url}\t{title}\n"

            await asyncio.to_thread(self._write_line, line)

    def _write_line(self, line):
        """同步写文件（在线程池中执行）"""
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(line)

    def _print_progress(self, final=False):
        """打印进度"""
        elapsed = time.time() - self.start_time
        rate = self.stats["scanned"] / elapsed if elapsed > 0 else 0
        msg = (
            f"已扫: {self.stats['scanned']} | "
            f"开放: {self.stats['open']} | "
            f"命中: {self.stats['matched']} | "
            f"错误: {self.stats['errors']} | "
            f"耗时: {self._format_time(elapsed)} | "
            f"速度: {rate:.1f}/s"
        )
        if final:
            print(f"\n[+] {msg}")
        else:
            print(f"\r{msg}", end="", flush=True)

    @staticmethod
    def _format_time(seconds):
        """格式化时间"""
        seconds = int(seconds)
        h, remainder = divmod(seconds, 3600)
        m, s = divmod(remainder, 60)
        if h > 0:
            return f"{h}h{m}m{s}s"
        if m > 0:
            return f"{m}m{s}s"
        return f"{s}s"


def main():
    parser = argparse.ArgumentParser(
        description="IP 段端口 + 浏览器标题扫描器（支持大段 /8 /16 低资源稳定运行）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
用法示例:
  # 扫描 /24 段，端口 80，标题含 Login
  python3 port_title_scan.py -i 192.168.1.0/24 -p 80 -k Login

  # 扫描 /16 段，多端口，高并发，走代理
  python3 port_title_scan.py -i 172.16.0.0/16 -p 80,443,8080-8090 -k admin -t 1000 --tcp-timeout 1 --proxy http://127.0.0.1:8080

  # 扫描 /8 段，只探测端口，不获取标题
  python3 port_title_scan.py -i 10.0.0.0/8 -p 22 --no-http -t 2000 --batch 50000

  # 扫描局域网 22 端口（SSH），抓取 Banner 并匹配 SSH
  python3 port_title_scan.py -i 192.168.1.0/24 -p 22 --no-http --grab-banner -k SSH -t 500

  # 断点续扫
  python3 port_title_scan.py -i 192.168.0.0/16 -p 80 -k OA --resume
        """,
    )

    # 目标
    target_group = parser.add_argument_group("目标")
    target_group.add_argument("-i", "--ip", help="IP 段，例如 192.168.1.0/24 或 10.0.0.1-10.0.0.255")
    target_group.add_argument("-f", "--ip-file", help="从文件读取 IP 段/列表，每行一个")

    # 端口
    port_group = parser.add_argument_group("端口")
    port_group.add_argument("-p", "--port", default="80", help="端口，支持 80,443,8080-8090，默认 80")
    port_group.add_argument("--ports-file", help="从文件读取端口列表，每行一个")

    # 匹配
    match_group = parser.add_argument_group("匹配")
    match_group.add_argument("-k", "--keyword", help="标题(title)匹配关键字（包含即匹配）")
    match_group.add_argument("--body-keyword", help="响应体匹配关键字（包含即匹配）")
    match_group.add_argument("--min-status", type=int, default=200, help="最小 HTTP 状态码，默认 200")
    match_group.add_argument("--max-status", type=int, default=399, help="最大 HTTP 状态码，默认 399")

    # 性能
    perf_group = parser.add_argument_group("性能")
    perf_group.add_argument("-t", "--threads", type=int, default=500, help="TCP 探测并发数，默认 500")
    perf_group.add_argument("--tcp-threads", type=int, help="TCP 探测并发数（单独设置，默认等于 --threads）")
    perf_group.add_argument("--http-threads", type=int, help="HTTP 请求并发数（单独设置，默认等于 --threads/5）")
    perf_group.add_argument("--tcp-timeout", type=float, default=1.0, help="TCP 探测超时（秒），默认 1.0")
    perf_group.add_argument("--http-timeout", type=float, default=3.0, help="HTTP 请求超时（秒），默认 3.0")
    perf_group.add_argument("--batch", type=int, default=10000, help="每批任务数，默认 10000")
    perf_group.add_argument("--retries", type=int, default=1, help="HTTP 请求失败重试次数，默认 1")

    # 网络
    net_group = parser.add_argument_group("网络")
    net_group.add_argument("--proxy", help="代理，例如 http://127.0.0.1:8080 或 socks5://127.0.0.1:1080")
    net_group.add_argument("--follow-redirects", action="store_true", default=True, help="跟随重定向，默认开启")
    net_group.add_argument("--no-follow-redirects", dest="follow_redirects", action="store_false", help="不跟随重定向")
    net_group.add_argument("--random-ua", action="store_true", default=True, help="随机 User-Agent，默认开启")
    net_group.add_argument("--no-random-ua", dest="random_ua", action="store_false", help="固定 User-Agent")

    # 协议
    proto_group = parser.add_argument_group("协议")
    proto_group.add_argument("--no-http-proto", action="store_true", help="只尝试 https")
    proto_group.add_argument("--no-https", action="store_true", help="只尝试 http（默认同时尝试 http/https）")
    proto_group.add_argument("--grab-banner", action="store_true", help="对非 HTTP 服务抓取 Banner（如 SSH、FTP）")
    proto_group.add_argument("--banner-timeout", type=float, default=2.0, help="Banner 读取超时（秒），默认 2.0")

    # 输出
    out_group = parser.add_argument_group("输出")
    out_group.add_argument("-o", "--output", help="输出文件路径，默认自动命名")
    out_group.add_argument("--format", choices=["txt", "json", "csv"], default="txt", help="输出格式")
    out_group.add_argument("--no-http", action="store_true", help="只扫描端口，不获取 HTTP title（可与 --grab-banner 配合识别 SSH 等）")
    out_group.add_argument("--status-file", help="状态文件路径（用于断点续扫）")

    # 其他
    parser.add_argument("--resume", action="store_true", help="断点续扫（从状态文件记录的位置继续）")
    parser.add_argument("-q", "--quiet", action="store_true", help="静默模式（减少进度输出）")

    args = parser.parse_args()

    if not args.ip and not args.ip_file:
        parser.print_help()
        print("\n[!] 必须指定 -i/--ip 或 -f/--ip-file 之一")
        sys.exit(1)

    if not args.no_http and not args.keyword and not args.body_keyword:
        parser.print_help()
        print("\n[!] 获取标题时必须指定 -k/--keyword 或 --body-keyword")
        sys.exit(1)

    # 默认并发设置
    if args.tcp_threads is None:
        args.tcp_threads = args.threads
    if args.http_threads is None:
        args.http_threads = max(1, args.threads // 5)

    # Windows 下 aiohttp 默认使用 aiodns，需要 SelectorEventLoop
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except AttributeError:
            pass

    aiohttp = check_dependencies()
    scanner = MassScanner(args, aiohttp)

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        scanner._save_status()
        print("\n[!] 已中断，进度已保存")
    except Exception as e:
        scanner._save_status()
        print(f"\n[!] 运行出错: {e}")
        raise


if __name__ == "__main__":
    main()
