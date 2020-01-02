# wg-mgmt

WireGuard® VPN peer creator.

## Dependencies:
`Python3`, `wg`

Optionnaly, you'll need `qrencode` (if `--qr` argument is specified)

## Install:

Using wget
```sh
$ wget https://raw.githubusercontent.com/j0n17/wg-mgmt/master/wg_mgmt.py
```

Using curl
```sh
$ curl -o wg_mgmt.py https://raw.githubusercontent.com/j0n17/wg-mgmt/master/wg_mgmt.py
```



## Usage command:

```sh
# Display what to do in order to create add a new peer
$ python3 wg_mgmt.py --subnet 10.10.0.0/24,fd86:ea04:1111::/64 --endpoint example.org:51280
# Run the following command to add this newly created peer
# wg set wg0 peer 'mgNpWHZe1a4irAyp/x2Fz1Psz19Rf+e0T5GZPLgKFho=' allowed-ips '10.10.0.4/32,fd86:ea04:1111::4/128'


[Interface]
PrivateKey = IPa804Rvd8I/uE+kjGun2f9PhBKdxrEVxZmnIFQfcHQ=
Address = 10.10.0.4/32,fd86:ea04:1111::4/128
DNS = 1.1.1.1

[Peer]
PublicKey = mgNpWHZe1a4irAyp/x2Fz1Psz19Rf+e0T5GZPLgKFho=
Endpoint = example.org:51280
AllowedIPs = 0.0.0.0/0,::/0




# If you need to manually specify the IP addresses used
$ python3 wg_mgmt.py --address 10.10.0.4/32,fd86:ea04:1111::3/128 --endpoint example.org:51280
# Run the following command to add this newly created peer
# wg set wg0 peer 'JTOE9DRu4jfCjpBzUl5rXZZJBHdtd2ZRx/m+uiCxPV8=' allowed-ips '10.10.0.4/32,fd86:ea04:1111::3/128'


[Interface]
PrivateKey = 6P6jliBjYHrzeb9C3xRpvbNjuKQNEin7juSfgWMCR3g=
Address = 10.10.0.4/32,fd86:ea04:1111::3/128
DNS = 1.1.1.1

[Peer]
PublicKey = JTOE9DRu4jfCjpBzUl5rXZZJBHdtd2ZRx/m+uiCxPV8=
Endpoint = example.org:51280
AllowedIPs = 0.0.0.0/0,::/0
```


```sh
$ python3 wg_mgmt.py -h
usage: wg_mgmt.py [-h] (--subnet SUBNET | --address ADDRESS) --endpoint
                  ENDPOINT [--privkey PRIVKEY] [--dns DNS]
                  [--keep-alive KEEP_ALIVE] [--mtu MTU]
                  [--allowed-ips ALLOWED_IPS] [--wg-binary WG_BINARY]
                  [--qrencode-binary QRENCODE_BINARY]
                  [--wg-interface WG_INTERFACE] [--qr] [--auto-add]

optional arguments:
  -h, --help            show this help message and exit
  --subnet SUBNET       Automatically generates the value of
                        [Interface][Address] based on already affected IP
                        addresses
  --address ADDRESS     [Interface][Address] value
  --endpoint ENDPOINT   [Peer][Endpoint] value
  --privkey PRIVKEY     [Interface][PrivateKey] value
  --dns DNS             [Interface][DNS] value
  --keep-alive KEEP_ALIVE
                        [Interface][PersistentKeepalive] value
  --mtu MTU             [Interface][MTU] value
  --allowed-ips ALLOWED_IPS
                        [Peer][AllowedIPs] value
  --wg-binary WG_BINARY
                        Path to wg binary (default = wg)
  --qrencode-binary QRENCODE_BINARY
                        Path to qrencode binary (default = qrencode)
  --wg-interface WG_INTERFACE
                        WireGuard interface (default = wg0)
  --qr                  Outputs the configuration as a QRcode instead of
                        stdout
  --auto-add            Executes 'wg set [WG_INTERFACE] [PUBKEY] allowd-ips
                        [ALLOWED_IPS]' with the generated data
```
