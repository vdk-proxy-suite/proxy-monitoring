import os
import shutil
import subprocess
from pathlib import Path

from .model import CollectionError, Metric, Snapshot


def process_epoch(unit: str, proc: Path = Path('/proc')) -> str:
    result = subprocess.run(
        ['systemctl', 'show', unit, '-p', 'MainPID', '-p', 'InvocationID', '-p', 'ActiveState'],
        capture_output=True, text=True, timeout=4, check=False,
    )
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if result.returncode or values.get('ActiveState') != 'active' or not values.get('MainPID', '0').isdigit():
        raise CollectionError('service_unavailable')
    pid = values['MainPID']
    if pid == '0':
        raise CollectionError('service_unavailable')
    stat = (proc / pid / 'stat').read_text()
    ticks = stat[stat.rfind(')') + 2:].split()[19]
    boot = (proc / 'sys/kernel/random/boot_id').read_text().strip()
    return f"{boot}:{values.get('InvocationID', '')}:{pid}:{ticks}"


def collect_host(source: dict, proc: Path = Path('/proc')) -> Snapshot:
    boot = (proc / 'sys/kernel/random/boot_id').read_text().strip()
    metrics = []
    ticks = os.sysconf('SC_CLK_TCK')
    cpu = list(map(int, (proc / 'stat').read_text().splitlines()[0].split()[1:]))
    # guest and guest_nice are already included in user/nice.
    for name, value in zip(('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal'), cpu[:8]):
        metrics.append(Metric('host.cpu_ticks_total', 'counter', 'ticks', value, {'mode': name}))
    metrics.append(Metric('host.clock_ticks_per_second', 'gauge', 'Hz', ticks))
    memory = {}
    for line in (proc / 'meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        memory[key] = int(value.split()[0]) * 1024
    for key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'):
        metrics.append(Metric('host.memory_bytes', 'gauge', 'bytes', memory[key], {'field': key}))
    for period, value in zip(('1', '5', '15'), (proc / 'loadavg').read_text().split()[:3]):
        metrics.append(Metric('host.load_average', 'gauge', 'ratio', float(value), {'minutes': period}))
    for line in (proc / 'net/dev').read_text().splitlines()[2:]:
        iface, fields = line.split(':', 1)
        values = list(map(int, fields.split()))
        if iface.strip() == 'lo':
            continue
        for name, index, unit in (('rx_bytes', 0, 'bytes'), ('tx_bytes', 8, 'bytes'),
                                  ('rx_errors', 2, 'events'), ('tx_errors', 10, 'events'),
                                  ('rx_drops', 3, 'events'), ('tx_drops', 11, 'events')):
            metrics.append(Metric(f'host.network_{name}_total', 'counter', unit, values[index], {'interface': iface.strip()}))
    for mount in source.get('mountpoints', ['/']):
        usage = shutil.disk_usage(mount)
        stat = os.statvfs(mount)
        for name, value, unit in (('disk_free', usage.free, 'bytes'), ('disk_total', usage.total, 'bytes'),
                                  ('inodes_free', stat.f_favail, 'inodes')):
            metrics.append(Metric(f'host.{name}', 'gauge', unit, value, {'mountpoint': mount}))
    return Snapshot(boot, metrics)


def socket_metrics(ports: list[int], proc: Path = Path('/proc')) -> list[Metric]:
    states = {'01': 'established', '08': 'close_wait', '0A': 'listen'}
    counts = {(p, s): 0 for p in ports for s in states.values()}
    for table in ('tcp', 'tcp6'):
        path = proc / 'net' / table
        if table == 'tcp6' and not path.exists():
            continue
        for line in path.read_text().splitlines()[1:]:
            fields = line.split()
            port = int(fields[1].rsplit(':', 1)[1], 16)
            state = states.get(fields[3])
            if (port, state) in counts:
                counts[port, state] += 1
    return [Metric('tcp.sockets', 'gauge', 'sockets', value, {'port': str(port), 'state': state})
            for (port, state), value in sorted(counts.items())]
