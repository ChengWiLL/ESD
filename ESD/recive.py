#! /usr/bin/python3
from scapy.all import *


def add(x, y):
    return x + y

def apply_async(func, args, *, callback):
    # Compute the result
    result = func(*args)
    # Invoke the callback with the result
    callback(result)

def make_handler():
    sequence = 0
    def handler(result):
        nonlocal sequence
        sequence += 1
        print('[{}] Got: {}'.format(sequence, result))
    print(sequence)
    return handler

handler = make_handler()
apply_async(add, (2, 3), callback=handler)
