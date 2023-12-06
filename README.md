# totp-cli

## Description

**totp-cli** is a very small Python CLI utility that acts as a TOTP generator. 
It follows the standard defined by [rfc6238](https://datatracker.ietf.org/doc/html/rfc6238)
and is compatible with all TOTP solutions based on it.

It was intended to be used by developers and testers as a way to make the development
process easier and also allow testing automations in some cases.

## Dependencies

This program is expected to run in a plain installation of Python 3.x with no 
additional dependencies.

## Installation

Just copy `totpcli.py` to any directory and run the program from there.

##  Usage

Run `python totpcli.py` to get the current TOTP for the test seed from the RFC4226.
The resulting OTP will be written to the console's stdout.

```
python totpcli.py --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --cycle 30 --digits 6
```

Run `python totpcli.py -h` to get more details about the options.

## Example secrets

If you need a good seed for testing, try `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`. It
is the reference seed `12345678901234567890` used as examples in the RFC4226.

The file `RFC4226.png` in this repository can be imported by Google Authenticatior 
and others can be used to import it.

![](RFC4226.png)

It is important to notice that this QRCode encondes the following token definition:

```
otpauth://totp/Sample Seed?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=RFC4226
```

## License

This program is licensed under the terms of GNU GENERAL PUBLIC LICENSE Version 3.
