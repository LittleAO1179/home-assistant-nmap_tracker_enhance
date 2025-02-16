"""使用 Surge API 跟踪设备的组件。
"""
import logging
import json
from datetime import timedelta
import requests
from datetime import datetime
from collections import namedtuple
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_API_KEY
from homeassistant.util import Throttle
import homeassistant.util.dt as dt_util

_LOGGER = logging.getLogger(__name__)

CONF_INCLUDE = 'include'
CONF_EXCLUDE = 'exclude'
DEFAULT_HOST = '192.168.3.33'
DEFAULT_PORT = 6171

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=10)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_API_KEY): cv.string,
    vol.Optional(CONF_HOST, default=DEFAULT_HOST): cv.string,
    vol.Optional('port', default=DEFAULT_PORT): cv.port,
    vol.Optional(CONF_INCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_EXCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string])
})


def get_scanner(hass, config):
    """验证配置并返回扫描器。"""
    scanner = SurgeDeviceScanner(config[DOMAIN])
    return scanner if scanner.success_init else None

Device = namedtuple('Device', ['mac', 'name', 'ip', 'last_update', 'hostname'])

class SurgeDeviceScanner(DeviceScanner):
    """使用 Surge API 跟踪设备。"""

    def __init__(self, config):
        """初始化扫描器。"""
        self.host = config.get(CONF_HOST)
        self.port = config.get('port')
        self.api_key = config.get(CONF_API_KEY)
        self.exclude = config.get(CONF_EXCLUDE, [])
        self.include = config.get(CONF_INCLUDE, [])
        
        self.last_results = []
        self.success_init = False

        # 测试API连接
        try:
            self._update_info()
            self.success_init = True
        except requests.exceptions.RequestException as ex:
            _LOGGER.error("无法连接到 Surge API: %s", ex)
            self.success_init = False


    def scan_devices(self):
        """扫描设备并返回发现的设备MAC地址列表。"""
        self._update_info()
        return [device.mac for device in self.last_results]


    def get_device_name(self, mac):
        """返回设备名称。"""
        result = next(
            (device for device in self.last_results if device.mac == mac), None
        )
        return result.name if result else None


    def get_extra_attributes(self, mac):
        """返回设备的额外属性。"""
        device = next(
            (result for result in self.last_results if result.mac == mac), None
        )
        if device:
            return {
                'ip': device.ip,
                'hostname': device.hostname,
                'last_update': device.last_update
            }
        return {}


    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """从 Surge API 更新设备信息。"""
        _LOGGER.debug("正在从 Surge API 获取设备信息")
        
        try:
            response = requests.get(
                f'http://{self.host}:{self.port}/v1/devices',
                headers={'X-Key': self.api_key},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            now = dt_util.now()
            self.last_results = []

            for device in data.get('devices', []):
                # 检查设备是否在 DHCP 设备列表中
                dhcp_device = device.get('dhcpDevice', {})
                if not dhcp_device:
                    continue

                ip = device.get('displayIPAddress')
                mac = device.get('physicalAddress')
                hostname = device.get('name')
                
                # 检查包含/排除列表
                if self.include and ip not in self.include:
                    continue
                if ip in self.exclude:
                    continue

                # 检查最后在线时间
                last_seen = dhcp_device.get('dhcpLastSeen')
                if last_seen:
                    try:
                        last_seen_dt = datetime.strptime(last_seen, '%Y-%m-%dT%H:%M:%S%z')
                        # 如果设备在5分钟内有活动，就认为在线
                        if (now.astimezone() - last_seen_dt).total_seconds() < 300:
                            self.last_results.append(Device(
                                mac=mac,
                                name=hostname,
                                ip=ip,
                                last_update=last_seen,
                                hostname=dhcp_device.get('dhcpHostname', '')
                            ))
                    except ValueError as e:
                        _LOGGER.error("解析时间戳错误: %s", e)

            return True

        except requests.exceptions.RequestException as ex:
            _LOGGER.error("从 Surge API 获取数据失败: %s", ex)
            return False
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
 
