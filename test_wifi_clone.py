# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
import unittest
from owctl import _parse_wifi_ifaces, _parse_wifi_radios


RAW_UCI = """
wireless.radio0=wifi-device
wireless.radio0.type='mac80211'
wireless.radio0.band='2g'
wireless.radio0.channel='8'
wireless.default_radio0=wifi-iface
wireless.default_radio0.device='radio0'
wireless.default_radio0.network='lan'
wireless.default_radio0.mode='ap'
wireless.default_radio0.ssid='spidertje'
wireless.default_radio0.encryption='psk2'
wireless.default_radio0.key='rocklobster'
wireless.radio1=wifi-device
wireless.radio1.type='mac80211'
wireless.radio1.band='5g'
wireless.radio1.channel='120'
wireless.default_radio1=wifi-iface
wireless.default_radio1.device='radio1'
wireless.default_radio1.network='lan'
wireless.default_radio1.mode='ap'
wireless.default_radio1.ssid='spidertje2-fast'
wireless.default_radio1.encryption='none'
"""


class TestWifiParsers(unittest.TestCase):
    def test_parse_ifaces(self):
        ifaces = _parse_wifi_ifaces(RAW_UCI)
        self.assertEqual(len(ifaces), 2)
        ssids = {i['ssid']: i for i in ifaces}
        self.assertIn('spidertje', ssids)
        self.assertIn('spidertje2-fast', ssids)
        self.assertEqual(ssids['spidertje']['band'], '2g')
        self.assertEqual(ssids['spidertje2-fast']['band'], '5g')
        self.assertEqual(ssids['spidertje']['key'], 'rocklobster')

    def test_parse_radios(self):
        radios = _parse_wifi_radios(RAW_UCI)
        self.assertEqual(radios, {'radio0': {'band': '2g'}, 'radio1': {'band': '5g'}})


if __name__ == '__main__':
    unittest.main()
