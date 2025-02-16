"""
使用 arp-scan 扫描网络的支持组件。

有关此平台的更多详细信息，请参阅文档：
https://github.com/cyberjunky/home-assistant-arpscan_tracker/
"""
import logging
import re
import subprocess
from collections import namedtuple
from datetime import timedelta

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.util import Throttle

_LOGGER = logging.getLogger(__name__)

CONF_EXCLUDE = 'exclude'
CONF_INCLUDE = 'include'
CONF_OPTIONS = 'scan_options'
CONF_NETWORK = 'network'
DEFAULT_OPTIONS = '-R -sP -PS5353,80,443 -PU5353 --dns-servers 192.168.3.1,8.8.8.8,8.8.4.4 --system-dns'
DEFAULT_NETWORK = '192.168.1.0/24'

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_INCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_EXCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_OPTIONS, default=DEFAULT_OPTIONS):
        cv.string,
    vol.Optional(CONF_NETWORK, default=DEFAULT_NETWORK):
        cv.string
})


def get_scanner(hass, config):
    """验证配置并返回一个 ArpScan 扫描器。"""
    return ArpScanDeviceScanner(config[DOMAIN])

Device = namedtuple('Device', ['mac', 'name', 'ip', 'last_update', 'hostname'])

class ArpScanDeviceScanner(DeviceScanner):
    """此类使用 nmap 扫描设备。"""

    exclude = []
    include = []

    def __init__(self, config):
        """初始化扫描器。"""
        self.last_results = []

        self.exclude = config[CONF_EXCLUDE]
        self.include = config[CONF_INCLUDE]
        self._options = config[CONF_OPTIONS]
        self._network = config[CONF_NETWORK]

        _LOGGER.debug("正在安装 nmap 软件包")
        proc = subprocess.Popen('apk add nmap', shell=True, stdin=None, stdout=None, stderr=None, executable="/bin/bash")
        proc.wait()

        self.success_init = self._update_info()


    def scan_devices(self):
        """扫描新设备并返回包含已发现设备ID的列表。"""
        self._update_info()

        _LOGGER.debug("arpscan 最新扫描结果 %s", self.last_results)

        return [device.mac for device in self.last_results]


    def get_device_name(self, mac):
        """返回给定设备的名称。"""
        # 对于没有MAC地址的设备，返回其IP地址作为名称
        if mac.startswith('NO_MAC_'):
            return mac.replace('NO_MAC_', '').replace('_', '.')
        return mac.replace(':', '')


    def get_extra_attributes(self, device):
        """返回给定设备的额外属性。"""
        device_info = next(
            (result for result in self.last_results if result.mac == device), None
        )
        if device_info:
            attributes = {
                "ip": device_info.ip,
                "hostname": device_info.hostname
            }
            # 如果是无MAC地址设备，添加标记
            if device.startswith('NO_MAC_'):
                attributes["no_mac"] = True
            return attributes
        return {"ip": None, "hostname": None}


    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """
        扫描网络中的设备。
        如果扫描成功则返回布尔值。
        """
        _LOGGER.debug("正在扫描...")

        options = self._options

        last_results = []
        exclude_hosts = self.exclude
        include_hosts = self.include

        """如果存在包含列表则忽略排除列表"""
        if include_hosts:
            exclude_hosts = []

        # 构建扫描命令
        network = self._network
        if '/' in network:  # 如果是子网
            base_ip = network.split('/')[0].rsplit('.', 1)[0]
            # 分批扫描，每批32个IP
            all_scandata = []
            for i in range(0, 256, 32):
                ip_range = f"{base_ip}.{i}-{min(i+31, 255)}"
                cmd = f"nmap {options} {ip_range}"
                _LOGGER.debug("执行命令: %s", cmd)
                scandata = subprocess.getoutput(cmd)
                all_scandata.append(scandata)
            scandata = '\n'.join(all_scandata)
        else:  # 单个IP
            cmd = f"nmap {options} {network}"
            _LOGGER.debug("执行命令: %s", cmd)
            scandata = subprocess.getoutput(cmd)
        _LOGGER.debug("扫描数据 %s", scandata)

        now = dt_util.now()
        
        # 解析 nmap 输出
        current_ip = None
        current_mac = None
        current_hostname = None
        has_valid_hostname = False
        
        for line in scandata.splitlines():
            # 匹配带主机名的IP
            hostname_match = re.search(r'Nmap scan report for ([^\(]+)\(([0-9]+(?:\.[0-9]+){3})\)', line)
            if hostname_match:
                current_hostname = hostname_match.group(1).strip()
                current_ip = hostname_match.group(2)
                current_mac = None
                has_valid_hostname = True
                continue
                
            # 匹配普通IP
            ip_match = re.search(r'Nmap scan report for ([0-9]+(?:\.[0-9]+){3})', line)
            if ip_match:
                if has_valid_hostname:  # 如果之前找到了有效的主机名，就添加该设备
                    last_results.append(Device(
                        mac=current_mac if current_mac else f"NO_MAC_{current_ip.replace('.', '_')}",
                        name=current_hostname,
                        ip=current_ip,
                        last_update=now,
                        hostname=current_hostname
                    ))
                current_ip = ip_match.group(1)
                current_mac = None
                current_hostname = None
                has_valid_hostname = False
                continue

            # 匹配 MAC 地址
            mac_match = re.search(r'MAC Address: ([0-9A-F:]{17}) \(.*\)', line, re.IGNORECASE)
            if mac_match:
                current_mac = mac_match.group(1)

            # 如果有效主机名和MAC地址，就添加设备
            if current_ip and has_valid_hostname:
                if include_hosts and current_ip not in include_hosts:
                    _LOGGER.debug("已排除 %s", current_ip)
                    current_ip = None
                    continue

                if current_ip in exclude_hosts:
                    _LOGGER.debug("已排除 %s", current_ip)
                    current_ip = None
                    continue

                # 如果没有MAC地址，使用IP地址作为标识
                if not current_mac:
                    current_mac = f"NO_MAC_{current_ip.replace('.', '_')}"
                    _LOGGER.debug("设备 %s 无法获取MAC地址，使用IP作为标识", current_ip)

                # 添加设备到结果列表
                last_results.append(Device(
                    mac=current_mac,
                    name=current_hostname,  # 使用主机名作为设备名称
                    ip=current_ip,
                    last_update=now,
                    hostname=current_hostname
                ))
                
                # 重置当前设备信息
                current_ip = None
                current_mac = None
                current_hostname = None
                has_valid_hostname = False

        self.last_results = last_results

        _LOGGER.debug("Arpscan 扫描成功")
        return True
 
