# How to operate the RG

## Send a correct authentication request

```bash
wpa_supplicant -i eth0 -Dwired -c /etc/wpa_supplicant/wpa_supplicant.conf
```

## Send a failing authentication request

```bash
wpa_supplicant -i eth0 -Dwired -c /etc/wpa_supplicant/wpa_supplicant_fail.conf
```

## Request an IP

```bash
dhclient -d eth0
```

## Ping the gateway

Assuming that your DHCP Server correctly returns the gateway informations:

```bash
ping $(route -n | awk NR==3 | awk '{ print $2 }')
```