# Wireless

## Simulate wifi network in VM

The following diagram shows the simulated wifi network in a VM:

     ┌──────────────────────────────────────────────────────────────────────────────────────┐
     │      namespace: ns                             namespace: default                    │
     │                           │                                                          │
     │                           │                                                          │
     │     br0 (access point)                  br-ex (OVS bridge)                           │
     │      │                    │               │                                          │
     │      │                    │               │                                          │
     │      │                                    │                                          │
     │      │                    │               │                                          │
     │    wlan1    ──────────────┴─────────    wlan0 (client)       enp1s0 (default route)  │
     │                                                                                      │
     │                           │                                                          │
     └───────────────────────────┴──────────────────────────────────────────────────────────┘


Steps to setup the wifi network:

- Install packages required to setup the wireless network:

```bash
dnf install -y hostapd dnsmasq iw kernel-modules-internal NetworkManager-wifi
```

- Reboot system

```bash
systemctl reboot
```

- Load `mac80211_hwsim` kernel module (software simulator of 802.11 radio for mac80211):

```bash
modprobe mac80211_hwsim radios=2
```

- Set `wlan0` managed by NetworkManager and `wlan1` unmanaged. `wlan0` and `wlan1` are automatically created after loading `mac80211_hwsim`:

```bash
nmcli device set wlan0 managed yes
nmcli device set wlan1 managed no
```

- Create new namespace `ns` and move device `phy1` (wlan1) to it:

```bash
ip netns add ns
iw phy phy1 set netns name ns
```

- Create linux bridge `br0` and add interface `wlan1` to the bridge:

```bash
ip -n ns link add br0 type bridge
ip -n ns link set wlan1 up
ip -n ns link set br0 up
ip -n ns addr add dev br0 172.25.1.1/24


cat <<EOF > /tmp/wlan1.conf
interface=wlan1
driver=nl80211
ctrl_interface=/var/run/hostapd-wlan1
ctrl_interface_group=0
ssid=myssid
country_code=EN
hw_mode=g
channel=7
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=secret123
bridge=br0
wds_sta=1
EOF

```

- Start wireless access point using `hostapd` in namespace `ns`:

```bash
ip netns exec ns hostapd /tmp/wlan1.conf > /tmp/wlan1.log 2>&1 &
```

- Start dhcp server using `dnsmasq` on bridge `br0` in namespace `ns`:

```bash
ip netns exec ns dnsmasq --interface br0 --bind-interfaces --dhcp-range=172.25.1.100,172.25.1.200 --dhcp-sequential-ip --dhcp-leasefile=/dev/null
```

- Add NetworkManager connection `wifi-interface` on interface `wlan0` in default namespace:

```bash
nmcli con add type wifi ifname wlan0 con-name wifi-interface wifi.ssid myssid wifi-sec.psk secret123 wifi-sec.key-mgmt WPA-PSK
```

> Note: `wifi.ssid`, `wifi-sec.psk` and `wifi-sec.key-mgmt` match with the values configured in `wlan1.conf` access point.


## Configure wlan0 as ovn-kubernetes gateway interface

- Specify the `gatewayInterface` in the CNI config file `/etc/microshift/ovn.yaml`:

```yaml
ovsInit:
  gatewayInterface: wlan0
```

- Start `microshift` service

```bash
systemctl start microshift
```
