import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxy_monitoring.linux import process_epoch, socket_metrics
from proxy_monitoring.model import CollectionError


class LinuxAdapterTests(unittest.TestCase):
    def test_epoch_includes_boot_invocation_and_exact_start_ticks(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / 'sys/kernel/random').mkdir(parents=True)
            (proc / 'sys/kernel/random/boot_id').write_text('boot-1\n')
            (proc / '42').mkdir()
            fields = ['S'] + ['0'] * 18 + ['123456'] + ['0'] * 10
            (proc / '42/stat').write_text('42 (name with spaces) ' + ' '.join(fields))
            result = subprocess.CompletedProcess([], 0, 'MainPID=42\nInvocationID=inv-1\nActiveState=active\n')
            with patch('proxy_monitoring.linux.subprocess.run', return_value=result):
                self.assertEqual(process_epoch('a.service', proc), 'boot-1:inv-1:42:123456')

    def test_inactive_service_does_not_invent_epoch(self):
        result = subprocess.CompletedProcess([], 0, 'MainPID=0\nActiveState=inactive\n')
        with patch('proxy_monitoring.linux.subprocess.run', return_value=result):
            with self.assertRaisesRegex(CollectionError, 'service_unavailable'):
                process_epoch('a.service')

    def test_socket_count_and_absent_ipv6(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / 'net').mkdir()
            (proc / 'net/tcp').write_text('header\n0: 0100007F:0438 00000000:0000 0A\n'
                                        '1: 0100007F:0438 00000000:0000 08\n')
            metrics = socket_metrics([1080], proc)
            values = {m.dimensions['state']: m.value for m in metrics}
            self.assertEqual(values, {'listen': 1, 'established': 0, 'close_wait': 1})
