### Steps to run ovn-kubernetes as default CNI

#### host configuration

1. disable NetworkManager and install tools

Avoid interfarence by NetworkManager to manually configured ovs network (described in `host ovs configuration` section below)

```
$ systemctl stop NetworkManager
$ systemctl disable NetworkManager

$ yum install -y bind-utils net-tools git vim
```

2. install crio-1.24

```
$ curl -L -o /etc/yum.repos.d/devel:kubic:libcontainers:stable.repo https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/CentOS_8_Stream/devel:kubic:libcontainers:stable.repo
$ curl -L -o /etc/yum.repos.d/devel:kubic:libcontainers:stable:cri-o:1.24.repo https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:1.24/CentOS_8_Stream/devel:kubic:libcontainers:stable:cri-o:1.24.repo

$ yum install -y cri-o cri-tools
$ systemctl enable crio --now
```

#### cni config

1. add ovn-kubernetes cni config to `/etc/cni/net.d/`

```
$ cat > /etc/cni/net.d/00-ovn.conf << EOF
{
  "cniVersion": "0.4.0",
  "name": "ovn-kubernetes",
  "type": "ovn-k8s-cni-overlay",
  "ipam": {},
  "dns": {},
  "logFile": "/var/log/ovn-kubernetes/ovn-k8s-cni-overlay.log",
  "logLevel": "4",
  "logfile-maxsize": 100,
  "logfile-maxbackups": 5,
  "logfile-maxage": 5
}
EOF
```
2. add workload partitioning config to `/etc/crio/crio.conf` (or `/etc/crio/crio.conf.d/*.conf`)

```
cat >> /etc/crio/crio.conf << EOF
[crio.runtime.workloads.management]
activation_annotation = "target.workload.openshift.io/management"
annotation_prefix = "resources.workload.openshift.io"
resources = { "cpushares" = 0, "cpuset" = "0" }
EOF
```

3. build and copy ovnk cni plugin binary

```
$ git clone https://github.com/openshift/ovn-kubernetes.git
$ cd ovn-kubernetes
$ cd go-controller; CGO_ENABLED=0 make
$ cp _output/go/bin/ovn-k8s-cni-overlay /opt/cni/bin
```

4. restart crio service

```
$ systemctl restart crio
```

#### host ovs configuration

1. install ovs packages on the host

```
$ ovs=http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/openvswitch2.17/2.17.0/8.el8fdp/x86_64/openvswitch2.17-2.17.0-8.el8fdp.x86_64.rpm
$ selinux=http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/openvswitch-selinux-extra-policy/1.0/28.el8fdp/noarch/openvswitch-selinux-extra-policy-1.0-28.el8fdp.noarch.rpm
$ yum install -y $ovs $selinux iptables
```

2. configure ovs

```
$ systemctl start openvswitch
$ ovs-vsctl add-br br-ex -- set bridge br-ex other-config:hwaddr=\"<mac-address-of-eno1>\"
$ ovs-vsctl add-port br-ex eno1; ip addr flush dev eno1; pkill dhclient; dhclient -v br-ex
$ ovs-vsctl set interface eno1 type=system
$ ovs-vsctl set open . external-ids:ovn-remote="unix:/var/run/ovn/ovnsb_db.sock"
$ ovs-vsctl set open . other_config:n-handler-threads=1
$ ovs-vsctl set open . other_config:n-revalidator-threads=1
```

> Replace `eno1` with the default route interface on your host system.
> Adding `eno1` to `br-ex` will disconnect host from external network temporarily if default interface is used for ssh into the host. The above cmds may fail so make sure you have other ways to access the system and revert the change if needed.

3. configure ovs-vswitchd

Update `ExecStart=` in `/usr/lib/systemd/system/ovs-vswitchd.service` to the following:

```
ExecStart=/usr/share/openvswitch/scripts/ovs-ctl \
          --no-ovsdb-server --no-monitor --system-id=random --no-mlockall \
          ${OVS_USER_OPT} \
          start $OPTIONS
```

> The above adds `--no-mlockall` option for ovs-vswitchd

Add `CPUAffinity=0` in `/usr/lib/systemd/system/ovs-vswitchd.service`

```
[Service]
CPUAffinity=0
```
> The above adds `CPUAffinity=0` to ovs-vswitchd

4. configure ovsdb-server

Update `ExecStart=` in `/usr/lib/systemd/system/ovs-vswitchd.service` to the following:

```
ExecStart=/usr/share/openvswitch/scripts/ovs-ctl \
          --no-ovs-vswitchd --no-monitor --system-id=random --no-mlockall \
          ${OVS_USER_OPT} \
          start $OPTIONS
```

> The above adds `--no-mlockall` option for ovs-vswitchd

Add `CPUAffinity=0` in `/usr/lib/systemd/system/ovsdb-server.service`

```
[Service]
CPUAffinity=0
```
> The above adds `CPUAffinity=0` to ovsdb-server

5. restart ovs services

```
$ systemctl daemon-reload
$ systemctl restart ovs-vswitchd
$ systemctl restart ovsdb-server
$ systemctl restart openvswitch
```

#### update ovnk manifests

1. (Optional) `/var/lib/microshift/resources/kubeadmin/kubeconfig` is mounted to `master/daemonset.yaml` and `node/daemonset.yaml`, Change it if you have customized microshift data directory (cfg.DataDir)

#### update hostname

```
$ echo "192.168.122.102	microshift microshift" >> /etc/hosts
```

> This is optional in the case the default hostname can be resolved.
> It is in the format of "<node ip> <host name> <host name>"


#### make and run microshift

```
$ ./script/bindata.sh
$ make clean; make
$ ./hack/cleanup.sh
$ (optional) crio wipe -f && sleep 1 && systemctl restart crio
$ ./microshift run
```

Wait for CNI pods to be created, for example `dns-default-xxxx` in `openshift-dns` namespace


### metrics

```
$ mkdir -p ~/.kube
$ cat /var/lib/microshift/resources/kubeadmin/kubeconfig > ~/.kube/config
```

Copy oc & kubectl to /usr/local/bin/


```
$ oc apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
$ kubectl top pods -A --containers
```
