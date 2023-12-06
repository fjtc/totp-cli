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

import hmac
import hashlib
import time
import base64
import argparse
from pathlib import Path
import sys

PROG_DESC = """
totpcli.py is a small CLI program that can generate TOTP passwords.
"""

DEFAULT_SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'


class HOTPGenerator:
    """
    This class implements the HOTP/TOTP generator as defined by RFC4226 and RFC6238.
    """

    def __init__(self, seed: bytes, digestmod=hashlib.sha1) -> None:
        """
        Creates a new instance of this class using the given seed and hash algorithm.
        """
        self.__seed = seed
        self.__digestmod = digestmod

    def mac(self, v: bytes) -> bytes:
        """
        Computes the MAC of the given value using the current seed.
        """
        mac = hmac.new(self.__seed, digestmod=self.__digestmod)
        mac.update(v)
        return mac.digest()

    @classmethod
    def dt(cls, m: bytes) -> int:
        """
        Computes the dynamic truncate as specified by RFC4226.
        """
        offs = int(m[19]) & 0xF
        return int.from_bytes(m[offs:offs+4], byteorder='big') & 0x7FFFFFFF

    def hotp(self, c: int, digits: int = 6) -> int:
        """
        Computes the HOTP as specified by RFC4226.
        """
        v = c.to_bytes(8, byteorder='big')
        m = self.mac(v)
        otp = self.dt(m)
        return otp % (10**digits)

    @classmethod
    def current_cycle(cls, cycle: int):
        """
        Returns the current TOTP cycle.
        """
        return int(time.time() / cycle)

    def totp(self, cycle: int, digits: int = 6) -> int:
        """
        Computes the current TOTP as specified by RFC4226.
        """
        current = self.current_cycle(cycle)
        return self.hotp(current, digits=digits)


def run(secret: str, cycle: int, digits: int):
    # Parse the seed
    try:
        s = base64.b32decode(secret)
    except ValueError as ex:
        print(f'Invalid secret: {ex}')
        sys.exit(1)
    # Generate!
    gen = HOTPGenerator(s)
    otp = gen.totp(cycle, digits=digits)
    format = f'{{:0{str(digits)}}}'
    print(format.format(otp))


def main():
    parser = argparse.ArgumentParser(prog=Path(__file__).name,
                                     description=PROG_DESC)
    parser.add_argument('--secret', '-s', default=DEFAULT_SEED,
                        metavar='<secret in Base32>', dest='secret',
                        help='The seed encoded in Base32. Defaults to GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ (sample seed in RFC4226).')
    parser.add_argument('--cycle', '-c', type=int, default=30,
                        metavar='<cycle in seconds>', dest='cycle', help='The time cycle in')
    parser.add_argument('--digits', '-d', type=int, default=6,
                        metavar='<digits>', dest='digits')
    args = parser.parse_args()
    run(args.secret, args.cycle, args.digits)


if __name__ == '__main__':
    main()
