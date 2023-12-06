# totpcli.py - A small CLI TOTP generator.
# Copyright (C) 2023 Fabio J. T. Chino
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import unittest
import totpcli

TEST_SEED = b'12345678901234567890'

HOTPGenerator = totpcli.HOTPGenerator


class HOTPGeneratorTest(unittest.TestCase):

    def test_constructor(self):
        gen = HOTPGenerator(TEST_SEED)
        m = gen.mac(0x0.to_bytes(8, byteorder='big'))
        self.assertEqual(0xcc93cf18508d94934c64b65d8ba7667fb7cde4b0.to_bytes(
            20, byteorder='big'), m)

    def test_mac(self):
        gen = HOTPGenerator(TEST_SEED)
        SAMPLES = [
            [0x0, 0xcc93cf18508d94934c64b65d8ba7667fb7cde4b0],
            [0x1, 0x75a48a19d4cbe100644e8ac1397eea747a2d33ab],
            [0x2, 0x0bacb7fa082fef30782211938bc1c5e70416ff44],
            [0x3, 0x66c28227d03a2d5529262ff016a1e6ef76557ece],
            [0x4, 0xa904c900a64b35909874b33e61c5938a8e15ed1c],
            [0x5, 0xa37e783d7b7233c083d4f62926c7a25f238d0316],
            [0x6, 0xbc9cd28561042c83f219324d3c607256c03272ae],
            [0x7, 0xa4fb960c0bc06e1eabb804e5b397cdc4b45596fa],
            [0x8, 0x1b3c89f65e6c9e883012052823443f048b4332db],
            [0x9, 0x1637409809a679dc698207310c8c7fc07290d9e5]]
        for v, exp in SAMPLES:
            m = gen.mac(v.to_bytes(8, byteorder='big'))
            self.assertEqual(exp.to_bytes(
                20, byteorder='big'), m)

    def test_dt(self):
        SAMPLES = [
            [0xcc93cf18508d94934c64b65d8ba7667fb7cde4b0, 0x4c93cf18],
            [0x75a48a19d4cbe100644e8ac1397eea747a2d33ab, 0x41397eea],
            [0x0bacb7fa082fef30782211938bc1c5e70416ff44, 0x82fef30],
            [0x66c28227d03a2d5529262ff016a1e6ef76557ece, 0x66ef7655],
            [0xa904c900a64b35909874b33e61c5938a8e15ed1c, 0x61c5938a],
            [0xa37e783d7b7233c083d4f62926c7a25f238d0316, 0x33c083d4],
            [0xbc9cd28561042c83f219324d3c607256c03272ae, 0x7256c032],
            [0xa4fb960c0bc06e1eabb804e5b397cdc4b45596fa, 0x4e5b397],
            [0x1b3c89f65e6c9e883012052823443f048b4332db, 0x2823443f],
            [0x1637409809a679dc698207310c8c7fc07290d9e5, 0x2679dc69]]
        for v, exp in SAMPLES:
            self.assertEqual(exp, HOTPGenerator.dt(
                v.to_bytes(20, byteorder='big')))

    def test_hotp(self):
        gen = HOTPGenerator(TEST_SEED)
        SAMPLES = [
            [0, 755224],
            [1, 287082],
            [2, 359152],
            [3, 969429],
            [4, 338314],
            [5, 254676],
            [6, 287922],
            [7, 162583],
            [8, 399871],
            [9, 520489],
        ]
        for c, exp in SAMPLES:
            self.assertEqual(exp, gen.hotp(c))
        # Test truncation
        self.assertEqual(84755224, gen.hotp(0, digits=8))
        self.assertEqual(1284755224, gen.hotp(0, digits=10))
        self.assertEqual(5224, gen.hotp(0, digits=4))
