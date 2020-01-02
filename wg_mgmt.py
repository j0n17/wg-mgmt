import os
import io
import argparse
import configparser
import ipaddress
import subprocess
import sys


def first_available_ip_from_subnet(args: object):
    result = []
    host_list = {}
    taken_host_list = {}

    subnets = list(map(lambda x: x.strip(), args.subnet.split(',')))
    for subnet in subnets:
        network = ipaddress.ip_network(subnet, strict=True)
        if network.version == 4 or network.version == 6:
            host_list[network.version] = network

    raw_command = subprocess.check_output(
        [args.wg_binary, 'show', args.wg_interface, 'allowed-ips'], stderr=sys.stdout)

    raw_lines = raw_command.decode('utf-8').split('\n')
    raw_lines = [x.split('\t')[1].split(' ') for x in raw_lines if x]
    for line in raw_lines:
        for ip in line:
            parsed_ip = ipaddress.ip_network(ip, strict=True)[0]
            if not parsed_ip.version in taken_host_list:
                taken_host_list[parsed_ip.version] = []

            taken_host_list[parsed_ip.version].append(parsed_ip)

    if 4 in host_list:
        # Grab the first free ivp4 address
        for ip in host_list[4].hosts():
            if ip != host_list[4][0] and ip != host_list[4][1]:
                if 4 not in taken_host_list or ip not in taken_host_list[4]:
                    result.append(str(ipaddress.ip_network(ip, strict=True)))
                    break

    if 6 in host_list:
        # Grab the first free ivp6 address
        for ip in host_list[6].hosts():
            if ip != host_list[6][0] and ip != host_list[6][1]:
                if 6 not in taken_host_list or ip not in taken_host_list[6]:
                    result.append(str(ipaddress.ip_network(ip, strict=True)))
                    break

    return ", ".join(result)


def get_public_key(args: object, privkey: str):
    pipe = subprocess.Popen(["echo", privkey], stdout=subprocess.PIPE)
    pubkey = subprocess.check_output(
        [args.wg_binary, "pubkey"], stdin=pipe.stdout)
    pubkey_cleaned = pubkey.decode("utf-8").strip()
    return pubkey_cleaned


def get_server_public_key(args: object):
    pubkey = subprocess.check_output(
        [args.wg_binary, "show", args.wg_interface, 'public-key'])
    pubkey_cleaned = pubkey.decode("utf-8").strip()
    return pubkey_cleaned


def get_private_key(args: object):
    if args.privkey:
        return args.privkey

    privkey = subprocess.check_output([args.wg_binary, "genkey"])
    privkey_cleaned = privkey.decode("utf-8").strip()
    return privkey_cleaned


def parse_args() -> object:
    p = argparse.ArgumentParser()
    # Mandatory arguments
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--subnet',
                       help="Automatically generates the value of [Interface][Address] based on already affected IP addresses")
    group.add_argument('--address',
                       help="[Interface][Address] value")
    p.add_argument('--endpoint',
                   help="[Peer][Endpoint] value", required=True)

    # Optional arguments
    p.add_argument('--privkey',
                   help="[Interface][PrivateKey] value")

    p.add_argument('--dns',
                   help="[Interface][DNS] value",
                   default='1.1.1.1')
    p.add_argument('--keep-alive',
                   help="[Interface][PersistentKeepalive] value",
                   default=0)
    p.add_argument('--mtu',
                   help="[Interface][MTU] value",
                   default=0)
    p.add_argument('--allowed-ips',
                   help="[Peer][AllowedIPs] value",
                   default='0.0.0.0/0,::/0')

    p.add_argument('--wg-binary',
                   help="Path to wg binary (default = wg)",
                   type=str,
                   default='wg')
    p.add_argument('--qrencode-binary',
                   help="Path to qrencode binary (default = qrencode)",
                   type=str,
                   default='qrencode')

    p.add_argument('--wg-interface',
                   help="WireGuard interface (default = wg0)",
                   type=str, default='wg0')

    # Output arguments
    p.add_argument('--qr',
                   help="Outputs the configuration as a QRcode instead of stdout",
                   action='store_const',
                   const=True, default=False)

    # Add to peer
    p.add_argument('--auto-add',
                   help="Executes 'wg set [WG_INTERFACE] [PUBKEY] allowd-ips [ALLOWED_IPS]' with the generated data",
                   action='store_const',
                   const=True, default=False)
    return p.parse_args()


def generate_configuration(args, privkey, interface_address, server_pubkey) -> str:
    config = configparser.ConfigParser()
    config.optionxform = str

    config.add_section('Interface')
    config.set('Interface', 'PrivateKey', privkey)
    config.set('Interface', 'Address', interface_address)
    config.set('Interface', 'DNS', args.dns)

    if int(args.mtu) > 0:
        config.set('Interface', 'MTU', args.mtu)

    config.add_section('Peer')
    config.set('Peer', 'PublicKey', server_pubkey)
    config.set('Peer', 'Endpoint', args.endpoint)
    config.set('Peer', 'AllowedIPs', args.allowed_ips)

    if int(args.keep_alive) > 0:
        config.set('Peer', 'PersistentKeepalive', args.keep_alive)

    output = io.StringIO()
    config.write(output)
    content = output.getvalue()
    output.close()

    return content.strip() + "\n"


def generate_qrcode(args, config):
    pipe = subprocess.Popen(["echo", config], stdout=subprocess.PIPE)
    qrcode = subprocess.check_output(
        [args.qrencode_binary, "-t", "ANSIUTF8"], stdin=pipe.stdout)
    print(qrcode.decode("utf-8").strip())


def main():
    args = parse_args()
    privkey = get_private_key(args)
    pubkey = get_public_key(args, privkey)
    interface_address = args.address
    server_pubkey = get_server_public_key(args)

    if args.subnet is not None:
        interface_address = first_available_ip_from_subnet(args)

    interface_address = interface_address.replace(' ', '')

    if args.auto_add is False:
        print("# Run the following command to add this newly created peer")
        print(
            f"# {args.wg_binary} set {args.wg_interface} peer '{pubkey}' allowed-ips '{interface_address}'\n\n")

    config = generate_configuration(
        args,
        privkey=privkey,
        interface_address=interface_address,
        server_pubkey=server_pubkey
    )

    if args.qr:
        generate_qrcode(args, config)
    else:
        print(config)

    if args.auto_add is True:
        subprocess.Popen([
            args.wg_binary, "set", args.wg_interface, "peer",
            pubkey, "allowed-ips", interface_address
        ])
        subprocess.Popen([
            args.wg_binary, "show", args.wg_interface])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError:
        pass
