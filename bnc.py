import asyncio
import socket
from hashlib import sha256
import configparser
import aiodns
import sys
import os
import re
import netifaces

config = configparser.ConfigParser()
config.read('config.ini')

password = config.get('Settings', 'password')
ipv4_vhost = config.get('Settings', 'ipv4_vhost')
ipv6_vhost = config.get('Settings', 'ipv6_vhost')
listen_ip = config.get('Settings', 'listen_ip')
listen_port = config.getint('Settings', 'listen_port')

def get_external_ipv4_addresses():
    ipv4_addresses = []
    output = os.popen('ip -4 addr show scope global').read()
    for line in output.split('\n'):
        if 'inet' in line:
            ipv4_address = line.strip().split()[1].split('/')[0]
            ipv4_addresses.append(ipv4_address)
    return ipv4_addresses

def get_external_ipv6_addresses():
    ipv6_addresses = []
    output = os.popen('ip -6 addr show scope global').read()
    for line in output.split('\n'):
        if 'inet6' in line:
            ipv6_address = line.strip().split()[1].split('/')[0]
            ipv6_addresses.append(ipv6_address)
    return ipv6_addresses

async def get_external_ipv4_addresses_async():
    return await asyncio.to_thread(get_external_ipv4_addresses)

async def get_external_ipv6_addresses_async():
    return await asyncio.to_thread(get_external_ipv6_addresses)

async def resolve_hostname(hostname, address_family):
    resolver = aiodns.DNSResolver()

    try:
        socket.inet_pton(address_family, hostname)
        return [hostname]
    except OSError:
        pass

    try:
        if address_family == socket.AF_INET:
            response = await resolver.query(hostname, "A")
            return [str(record.host) for record in response]
        elif address_family == socket.AF_INET6:
            response = await resolver.query(hostname, "AAAA")
            return [str(record.host) for record in response]
    except aiodns.error.DNSError as e:
        print(f'Error resolving hostname: {e}')
        return []

async def irc_connect(server, port, address_family, vhost=None):
    loop = asyncio.get_event_loop()

    remote_addresses = await resolve_hostname(server, address_family)
    if not remote_addresses:
        raise ValueError(f"Could not resolve hostname '{server}'")

    remote_sockaddr = (remote_addresses[0], port)

    if vhost:
        local_sockaddr = (vhost, 0)
    else:
        local_sockaddr = None
    irc_reader, irc_writer = await asyncio.open_connection(sock=socket.create_connection(remote_sockaddr, source_address=local_sockaddr))
    irc_writer.transport.set_write_buffer_limits(high=None)
    return irc_reader, irc_writer


async def forward_data(reader, writer, client_writer=None, irc_server=None):
    while True:
        try:
            data = await reader.readline()
            if not data:
                print(f'Connection closed: {writer.get_extra_info("peername")}')
                writer.close()
                return
            else:
                print(f'Forwarding data: {data}')
                writer.write(data)
                await writer.drain()

        except asyncio.CancelledError:
            print(f'Cancelled: {writer.get_extra_info("peername")}')
            writer.close()
            return
        except Exception as e:
            print(f'Error forwarding data: {e}')
            writer.close()
            return

async def handle_client(client_reader, client_writer):
    authenticated = False
    cap_ls = 'CAP LS'
    nick = None
    user = None


    banner = '''
   __        __    _       ____  _   ________
  / /_____ _/ /_  (_)___  / __ )/ | / / ____/
 / __/ __ `/ __ \/ / __ \/ __  /  |/ / /     
/ /_/ /_/ / / / / / /_/ / /_/ / /|  / /___   
\__/\__,_/_/ /_/_/\____/_____/_/ |_/\____/              
                        v0.1 by kofany
Available commands:
  /quote vh4 <IPv4 address> - Set IPv4 VHOST
  /quote vh6 <IPv6 address> - Set IPv6 VHOST
  /quote vh - List available IPv4 and IPv6 addresses
  /quote conn4 <server> <port> - Connect to an IRC server using IPv4
  /quote conn6 <server> <port> - Connect to an IRC server using IPv6
  /quote help - Display this help text
'''

    while not authenticated:
        data = await client_reader.readline()
        if not data:
            client_writer.close()
            return
        if data.startswith(b'CAP LS'):
            cap_ls = data.strip().decode()
        elif data.startswith(b'NICK '):
            nick = data.strip().decode()
        elif data.startswith(b'USER '):
            user_parts = data.strip().decode().split()
            username = user_parts[1]
            user = ' '.join(user_parts[:2]) + f' {username} conn_server_placeholder ' + f' {user_parts[4]}\r\n'
        elif data.startswith(b'PASS '):
            client_password = data[5:].strip()
            if sha256(client_password).hexdigest() == password:
                authenticated = True
                client_writer.write(b'Authentication successful.\n')
                await client_writer.drain()
                client_writer.write(banner.encode())
                await client_writer.drain()
            else:
                client_writer.write(b'Invalid password.\n')
                await client_writer.drain()

    while True:
        data = await client_reader.readline()
        if not data:
            client_writer.close()
            return
        if data.startswith(b'CAP LS'):
            cap_ls = data.strip().decode()
        elif data.startswith(b'NICK '):
            nick = data.strip().decode()
        elif data.startswith(b'USER '):
            user_parts = data.strip().decode().split()
            username = user_parts[1]
            user = ' '.join(user_parts[:2]) + f' {username} conn_server_placeholder ' + f' {user_parts[4]}\r\n'

        if data.startswith(b'vh4 '):
            ipv4_vhost = data[4:].strip().decode()
            client_writer.write(f'IPv4 VHOST set to: {ipv4_vhost}\n'.encode())
            await client_writer.drain()

        elif data.startswith(b'vh6 '):
            ipv6_vhost = data[4:].strip().decode()
            client_writer.write(f'IPv6 VHOST set to: {ipv6_vhost}\n'.encode())
            await client_writer.drain()

        elif data.startswith(b'vh'):
            ipv4_addresses = await get_external_ipv4_addresses_async()
            ipv6_addresses = await get_external_ipv6_addresses_async()
            
            print(f'Debug: IPv4 addresses: {ipv4_addresses}')
            print(f'Debug: IPv6 addresses: {ipv6_addresses}')

            client_writer.write(b'Available IPv4 addresses:\r\n')
            await client_writer.drain()

            for ipv4_address in ipv4_addresses:
                print(f'Debug: Sending IPv4 address: {ipv4_address}')
                client_writer.write(f'NOTICE {nick} :{ipv4_address}\r\n'.encode())
                await client_writer.drain()

            client_writer.write(b'Available IPv6 addresses:\r\n')
            await client_writer.drain()

            for ipv6_address in ipv6_addresses:
                print(f'Debug: Sending IPv6 address: {ipv6_address}')
                client_writer.write(f'NOTICE {nick} :{ipv6_address}\r\n'.encode())
                await client_writer.drain()

        elif data.startswith(b'help'):
            help_text = '''Available commands:
Available commands:
  /quote vh4 <IPv4 address> - Set IPv4 VHOST
  /quote vh6 <IPv6 address> - Set IPv6 VHOST
  /quote vh - List available IPv4 and IPv6 addresses
  /quote conn4 <server> <port> - Connect to an IRC server using IPv4
  /quote conn6 <server> <port> - Connect to an IRC server using IPv6
  /quote help - Display this help text
'''
            client_writer.write(help_text.encode())
            await client_writer.drain()

        elif data.startswith(b'conn4 '):
            tokens = data.split()
            if len(tokens) < 3:
                client_writer.write(b'Invalid command.\n')
                await client_writer.drain()
                continue
            server = tokens[1].decode()
            port = int(tokens[2]) if len(tokens) >= 3 else 6667

            print(f'Connecting to {server}:{port} using IPv4')
            try:
                irc_reader, irc_writer = await irc_connect(server, port, socket.AF_INET, ipv4_vhost)
                await connect_and_forward_data(client_reader, client_writer, irc_reader, irc_writer, cap_ls, nick, user)

            except Exception as e:
                client_writer.write(f'Error connecting to {server}:{port} using IPv4: {e}\n'.encode())
                await client_writer.drain()

        elif data.startswith(b'conn6 '):
            tokens = data.split()
            if len(tokens) < 3:
                client_writer.write(b'Invalid command.\n')
                await client_writer.drain()
                continue

            server = tokens[1].decode()
            port = int(tokens[2]) if len(tokens) >= 3 else 6667

            print(f'Connecting to {server}:{port} using IPv6')
            try:
                irc_reader, irc_writer = await irc_connect(server, port, socket.AF_INET6, ipv6_vhost)
                await connect_and_forward_data(client_reader, client_writer, irc_reader, irc_writer, cap_ls, nick, user)

            except Exception as e:
                client_writer.write(f'Error connecting to {server}:{port} using IPv6: {e}\n'.encode())
                await client_writer.drain()

async def connect_and_forward_data(client_reader, client_writer, irc_reader, irc_writer, cap_ls, nick, user):
    irc_writer.write(f'{cap_ls}\r\n'.encode())
    irc_writer.write(f'{nick}\r\n'.encode())
    irc_writer.write(user.encode().replace(b'conn_server_placeholder', irc_writer.get_extra_info("peername")[0].encode()))

    await irc_writer.drain()

    forward_task1 = asyncio.create_task(forward_data(client_reader, irc_writer))
    forward_task2 = asyncio.create_task(forward_data(irc_reader, client_writer))

    await asyncio.gather(forward_task1, forward_task2)

async def main():
    server = await asyncio.start_server(handle_client, listen_ip, listen_port)
    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\nExiting...')
        sys.exit(0)

