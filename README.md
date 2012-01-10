# openssl2nettle

## Description

openssl2nettle is a small tool to convert openssl keys to the s-expression format used by libnettle.

Currently only RSA private keys as used by OpenSSH (aka ~/.ssh/id_rsa) are supported using openssl2nettle-rsa
Unlike pkcs1-conv (distributed with libnettle), this uses openssl to read the openssl key and should therefore work with all openssl rsa keys.
(I only wrote this because pkcs1-conv won't work with my encrypted id_rsa key.)

## Requirements

 * make
 * libnettle (>= 2.4, although earlier versions might work)
 * libgmp
 * openssl

## Build

Just type:

	make

## Usage

	cat ~/.ssh/id_rsa | openssl2nettle-rsa > id_rsa.sexp

## License

Copyright (C) 2012 *Prof. MAAD* aka Max Wolter

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
