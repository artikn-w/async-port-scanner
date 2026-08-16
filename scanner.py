#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import socket
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional, Dict
import aiohttp
import argparse

DEFAULT_PORTS = [80, 443, 22, 8080, 3306, 5432]
TIMEOUT = 3.0
MAX_CONCURRENT_TASKS = 50

@dataclass
class ScanResult:
    ip: str
    port: int
    is_open: bool
    banner: Optional[str] = None
    http_headers: Optional[Dict[str, str]] = None
    response_time: Optional[float] = None
    error: Optional[str] = None

class AsyncPortScanner:
    
    def __init__(self, target_ips: List[str], ports: List[int] = None):
        self.target_ips = target_ips
        self.ports = ports or DEFAULT_PORTS
        self.results: List[ScanResult] = []
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
        self._session: Optional[aiohttp.ClientSession] = None
        
    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=TIMEOUT)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()
    
    async def _check_port(self, ip: str, port: int) -> ScanResult:
        start_time = time.perf_counter()
        result = ScanResult(ip=ip, port=port, is_open=False)
        
        try:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=TIMEOUT
                )
                result.is_open = True
                result.response_time = time.perf_counter() - start_time
                
                if port in [22, 23]:
                    try:
                        banner = await asyncio.wait_for(
                            reader.read(1024), 
                            timeout=1.0
                        )
                        result.banner = banner.decode('utf-8', errors='ignore')[:200]
                    except:
                        pass
                
                writer.close()
                await writer.wait_closed()
                
            except asyncio.TimeoutError:
                result.error = "Connection timeout"
            except ConnectionRefusedError:
                result.error = "Connection refused"
            except OSError as e:
                result.error = f"OS error: {str(e)[:50]}"
                
        except Exception as e:
            result.error = f"Unexpected: {str(e)[:50]}"
            
        if result.is_open and port in [80, 443, 8080, 8443]:
            await self._fetch_http_headers(result)
            
        return result
    
    async def _fetch_http_headers(self, result: ScanResult):
        if not self._session:
            return
            
        scheme = "https" if result.port in [443, 8443] else "http"
        url = f"{scheme}://{result.ip}:{result.port}"
        
        try:
            async with self._session.get(url, timeout=2.0) as resp:
                result.http_headers = dict(resp.headers)
                result.http_headers['_status_code'] = str(resp.status)
                if 'Server' in resp.headers:
                    server_header = resp.headers.get('Server', 'unknown')
                    if result.banner:
                        result.banner = f"{result.banner} | Server: {server_header}"
                    else:
                        result.banner = f"Server: {server_header}"
        except Exception:
            pass
    
    async def _scan_target(self, ip: str):
        tasks = []
        for port in self.ports:
            async with self.semaphore:
                task = asyncio.create_task(self._check_port(ip, port))
                tasks.append(task)
        
        port_results = await asyncio.gather(*tasks)
        self.results.extend(port_results)
        
        open_ports = [r.port for r in port_results if r.is_open]
        if open_ports:
            print(f"[+] {ip}: открыто {len(open_ports)} портов: {open_ports}")
        else:
            print(f"[-] {ip}: открытых портов не найдено")
    
    async def scan(self) -> List[ScanResult]:
        print(f"[*] Запуск сканирования {len(self.target_ips)} хостов, {len(self.ports)} портов")
        print(f"[*] Максимальная параллельность: {MAX_CONCURRENT_TASKS}")
        start_time = time.perf_counter()
        
        tasks = [self._scan_target(ip) for ip in self.target_ips]
        await asyncio.gather(*tasks)
        
        elapsed = time.perf_counter() - start_time
        print(f"[*] Сканирование завершено за {elapsed:.2f} секунд")
        
        return self.results
    
    def export_to_json(self, filename: str = None):
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"
            
        export_data = {
            "scan_date": datetime.now().isoformat(),
            "total_hosts": len(self.target_ips),
            "total_open_ports": sum(1 for r in self.results if r.is_open),
            "results": [asdict(r) for r in self.results]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
            
        print(f"[✓] Отчет сохранен в {filename}")
        return filename

def parse_ip_range(ip_range: str) -> List[str]:
    ips = []
    
    if '/' in ip_range:
        base, cidr = ip_range.split('/')
        if cidr == '24':
            base_parts = base.split('.')
            prefix = '.'.join(base_parts[:3])
            for i in range(1, 255):
                ips.append(f"{prefix}.{i}")
        else:
            raise ValueError("Поддерживается только /24")
            
    elif '-' in ip_range:
        base, last = ip_range.split('-')
        base_parts = base.split('.')
        prefix = '.'.join(base_parts[:3])
        start = int(base_parts[3])
        end = int(last)
        for i in range(start, end + 1):
            ips.append(f"{prefix}.{i}")
    else:
        ips.append(ip_range)
        
    return ips

async def main():
    parser = argparse.ArgumentParser(
        description="Асинхронный сканер портов с HTTP-анализом"
    )
    parser.add_argument(
        "targets", 
        nargs="+",
        help="IP-адреса или диапазоны (192.168.1.1, 192.168.1.1-10, 192.168.1.0/24)"
    )
    parser.add_argument(
        "-p", "--ports",
        help="Порты через запятую (по умолчанию: 80,443,22,8080,3306,5432)",
        default="80,443,22,8080,3306,5432"
    )
    parser.add_argument(
        "-o", "--output",
        help="Имя файла для отчета (JSON)",
        default=None
    )
    parser.add_argument(
        "-t", "--timeout",
        help="Таймаут подключения в секундах",
        type=float,
        default=3.0
    )
    
    args = parser.parse_args()
    
    ports = [int(p.strip()) for p in args.ports.split(',')]
    
    all_ips = []
    for target in args.targets:
        try:
            ips = parse_ip_range(target)
            all_ips.extend(ips)
        except ValueError as e:
            print(f"[!] Ошибка в аргументе '{target}': {e}")
            return
    
    if not all_ips:
        print("[!] Нет IP-адресов для сканирования")
        return
        
    async with AsyncPortScanner(all_ips, ports) as scanner:
        scanner.TIMEOUT = args.timeout
        results = await scanner.scan()
        
        total_open = sum(1 for r in results if r.is_open)
        print(f"\nСтатистика:")
        print(f"   Всего проверок: {len(results)}")
        print(f"   Открыто портов: {total_open}")
        
        if total_open > 0:
            print("\nОткрытые порты:")
            for r in results:
                if r.is_open:
                    banner = f" ({r.banner})" if r.banner else ""
                    print(f"   {r.ip}:{r.port}{banner}")
        
        filename = scanner.export_to_json(args.output)
        print(f"\nПолный отчет: {filename}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем")
