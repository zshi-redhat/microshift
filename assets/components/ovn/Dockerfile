#
# This is the OpenShift ovn overlay network image.
# it provides an overlay network using ovs/ovn/ovn-kube
#
# The standard name for this image is ovn-kube

# Notes:
# This is for a build where the ovn-kubernetes utilities
# are built in this Dockerfile and included in the image (instead of the rpm)
#

FROM registry.ci.openshift.org/ocp/builder:rhel-8-golang-1.18-openshift-4.12 AS builder

WORKDIR /go/src/github.com/openshift/ovn-kubernetes
COPY . .

# build the binaries
RUN cd go-controller; CGO_ENABLED=0 make

FROM registry.ci.openshift.org/ocp/4.12:base

USER root

ENV PYTHONDONTWRITEBYTECODE yes

# install needed rpms - openvswitch must be 2.10.4 or higher
# install selinux-policy first to avoid a race
RUN yum install -y  \
	selinux-policy && \
	yum clean all

RUN INSTALL_PKGS="" && \
	yum install -y http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/openvswitch2.17/2.17.0/22.el8fdp/x86_64/openvswitch2.17-2.17.0-22.el8fdp.x86_64.rpm http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/openvswitch2.17/2.17.0/22.el8fdp/x86_64/python3-openvswitch2.17-2.17.0-22.el8fdp.x86_64.rpm && \
	yum install -y http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/ovn22.06/22.06.0/27.el8fdp/x86_64/ovn22.06-22.06.0-27.el8fdp.x86_64.rpm http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/ovn22.06/22.06.0/27.el8fdp/x86_64/ovn22.06-central-22.06.0-27.el8fdp.x86_64.rpm http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/ovn22.06/22.06.0/27.el8fdp/x86_64/ovn22.06-host-22.06.0-27.el8fdp.x86_64.rpm && \
	yum clean all && rm -rf /var/cache/*

RUN mkdir -p /var/run/openvswitch && \
    mkdir -p /var/run/ovn && \
    mkdir -p /etc/cni/net.d && \
    mkdir -p /opt/cni/bin && \
    mkdir -p /usr/libexec/cni/

COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovnkube /usr/bin/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovn-k8s-cni-overlay /usr/libexec/cni/


# copy git commit number into image
COPY .git/HEAD /root/.git/HEAD
COPY .git/refs/heads/ /root/.git/refs/heads/

# ovnkube.sh is the entry point. This script examines environment
# variables to direct operation and configure ovn
COPY dist/images/ovnkube.sh /root/

# iptables wrappers
COPY ./dist/images/iptables-scripts/iptables /usr/sbin/
COPY ./dist/images/iptables-scripts/iptables-save /usr/sbin/
COPY ./dist/images/iptables-scripts/iptables-restore /usr/sbin/
COPY ./dist/images/iptables-scripts/ip6tables /usr/sbin/
COPY ./dist/images/iptables-scripts/ip6tables-save /usr/sbin/
COPY ./dist/images/iptables-scripts/ip6tables-restore /usr/sbin/
COPY ./dist/images/iptables-scripts/iptables /usr/sbin/

WORKDIR /root
ENTRYPOINT /root/ovnkube.sh
