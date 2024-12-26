#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import remote

def get_info():
    url = "/ip"

    # Connect to the server with the port
    r = remote("ipinfo.io", 80)

    # Build the request
    http_request = f"GET {url} HTTP/1.1\r\n"
    http_request += f"Host: ipinfo.io\r\n"
    http_request += "User-Agent: curl/7.88.1\r\n"
    http_request += "Accept: */*\r\n\r\n"

    # Send and get response
    r.send(http_request.encode())
    response = r.recv().decode()

    r.close()

    return response


info = get_info()
print(info)
