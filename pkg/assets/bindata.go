// Code generated for package assets by go-bindata DO NOT EDIT. (@generated)
// sources:
// assets/components/flannel/clusterrole.yaml
// assets/components/flannel/clusterrolebinding.yaml
// assets/components/flannel/configmap.yaml
// assets/components/flannel/daemonset.yaml
// assets/components/flannel/podsecuritypolicy.yaml
// assets/components/flannel/service-account.yaml
// assets/components/hostpath-provisioner/clusterrole.yaml
// assets/components/hostpath-provisioner/clusterrolebinding.yaml
// assets/components/hostpath-provisioner/daemonset.yaml
// assets/components/hostpath-provisioner/namespace.yaml
// assets/components/hostpath-provisioner/scc.yaml
// assets/components/hostpath-provisioner/service-account.yaml
// assets/components/hostpath-provisioner/storageclass.yaml
// assets/components/openshift-dns/dns/cluster-role-binding.yaml
// assets/components/openshift-dns/dns/cluster-role.yaml
// assets/components/openshift-dns/dns/configmap.yaml
// assets/components/openshift-dns/dns/daemonset.yaml
// assets/components/openshift-dns/dns/namespace.yaml
// assets/components/openshift-dns/dns/service-account.yaml
// assets/components/openshift-dns/dns/service.yaml
// assets/components/openshift-dns/node-resolver/daemonset.yaml
// assets/components/openshift-dns/node-resolver/service-account.yaml
// assets/components/openshift-router/cluster-role-binding.yaml
// assets/components/openshift-router/cluster-role.yaml
// assets/components/openshift-router/configmap.yaml
// assets/components/openshift-router/deployment.yaml
// assets/components/openshift-router/namespace.yaml
// assets/components/openshift-router/service-account.yaml
// assets/components/openshift-router/service-cloud.yaml
// assets/components/openshift-router/service-internal.yaml
// assets/components/ovn/clusterrole.yaml
// assets/components/ovn/clusterrolebinding.yaml
// assets/components/ovn/configmap-ovn-ca.yaml
// assets/components/ovn/configmap.yaml
// assets/components/ovn/master/.daemonset.yaml.swp
// assets/components/ovn/master/daemonset.yaml
// assets/components/ovn/master/serviceaccount.yaml
// assets/components/ovn/namespace.yaml
// assets/components/ovn/node/daemonset.yaml
// assets/components/ovn/node/serviceaccount.yaml
// assets/components/ovn/role.yaml
// assets/components/ovn/rolebinding.yaml
// assets/components/ovn/service.yaml
// assets/components/service-ca/clusterrole.yaml
// assets/components/service-ca/clusterrolebinding.yaml
// assets/components/service-ca/deployment.yaml
// assets/components/service-ca/ns.yaml
// assets/components/service-ca/role.yaml
// assets/components/service-ca/rolebinding.yaml
// assets/components/service-ca/sa.yaml
// assets/components/service-ca/signing-cabundle.yaml
// assets/components/service-ca/signing-secret.yaml
// assets/core/0000_50_cluster-openshift-controller-manager_00_namespace.yaml
// assets/crd/0000_03_authorization-openshift_01_rolebindingrestriction.crd.yaml
// assets/crd/0000_03_config-operator_01_proxy.crd.yaml
// assets/crd/0000_03_quota-openshift_01_clusterresourcequota.crd.yaml
// assets/crd/0000_03_security-openshift_01_scc.crd.yaml
// assets/crd/0000_10_config-operator_01_build.crd.yaml
// assets/crd/0000_10_config-operator_01_featuregate.crd.yaml
// assets/crd/0000_10_config-operator_01_image.crd.yaml
// assets/crd/0000_10_config-operator_01_imagecontentsourcepolicy.crd.yaml
// assets/crd/0000_11_imageregistry-configs.crd.yaml
// assets/scc/0000_20_kube-apiserver-operator_00_scc-anyuid.yaml
// assets/scc/0000_20_kube-apiserver-operator_00_scc-hostaccess.yaml
// assets/scc/0000_20_kube-apiserver-operator_00_scc-hostmount-anyuid.yaml
// assets/scc/0000_20_kube-apiserver-operator_00_scc-hostnetwork.yaml
// assets/scc/0000_20_kube-apiserver-operator_00_scc-nonroot.yaml
// assets/scc/0000_20_kube-apiserver-operator_00_scc-privileged.yaml
// assets/scc/0000_20_kube-apiserver-operator_00_scc-restricted.yaml
package assets

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _assetsComponentsFlannelClusterroleYaml = []byte(`kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: flannel
rules:
- apiGroups: ['extensions']
  resources: ['podsecuritypolicies']
  verbs: ['use']
  resourceNames: ['psp.flannel.unprivileged']
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - nodes/status
  verbs:
  - patch`)

func assetsComponentsFlannelClusterroleYamlBytes() ([]byte, error) {
	return _assetsComponentsFlannelClusterroleYaml, nil
}

func assetsComponentsFlannelClusterroleYaml() (*asset, error) {
	bytes, err := assetsComponentsFlannelClusterroleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/flannel/clusterrole.yaml", size: 418, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsFlannelClusterrolebindingYaml = []byte(`kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: flannel
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: flannel
subjects:
- kind: ServiceAccount
  name: flannel
  namespace: kube-system`)

func assetsComponentsFlannelClusterrolebindingYamlBytes() ([]byte, error) {
	return _assetsComponentsFlannelClusterrolebindingYaml, nil
}

func assetsComponentsFlannelClusterrolebindingYaml() (*asset, error) {
	bytes, err := assetsComponentsFlannelClusterrolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/flannel/clusterrolebinding.yaml", size: 248, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsFlannelConfigmapYaml = []byte(`kind: ConfigMap
apiVersion: v1
metadata:
  name: kube-flannel-cfg
  namespace: kube-system
  labels:
    tier: node
    app: flannel
data:
  cni-conf.json: |
    {
      "name": "cbr0",
      "cniVersion": "0.3.1",
      "plugins": [
        {
          "type": "flannel",
          "delegate": {
            "hairpinMode": true,
            "forceAddress": true,
            "isDefaultGateway": true
          }
        },
        {
          "type": "portmap",
          "capabilities": {
            "portMappings": true
          }
        }
      ]
    }
  net-conf.json: |
    {
      "Network": "10.42.0.0/16",
      "Backend": {
        "Type": "vxlan"
      }
    }`)

func assetsComponentsFlannelConfigmapYamlBytes() ([]byte, error) {
	return _assetsComponentsFlannelConfigmapYaml, nil
}

func assetsComponentsFlannelConfigmapYaml() (*asset, error) {
	bytes, err := assetsComponentsFlannelConfigmapYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/flannel/configmap.yaml", size: 674, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsFlannelDaemonsetYaml = []byte(`apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-flannel-ds
  namespace: kube-system
  labels:
    tier: node
    app: flannel
spec:
  selector:
    matchLabels:
      app: flannel
  template:
    metadata:
      labels:
        tier: node
        app: flannel
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/os
                operator: In
                values:
                - linux
      hostNetwork: true
      priorityClassName: system-node-critical
      tolerations:
      - operator: Exists
        effect: NoSchedule
      serviceAccountName: flannel
      initContainers:
      - name: install-cni-bin
        image: {{ .ReleaseImage.kube_flannel_cni }}
        imagePullPolicy: IfNotPresent
        command:
        - cp
        args:
        - -f
        - /flannel
        - /opt/cni/bin/flannel
        volumeMounts:
        - name: cni-plugin
          mountPath: /opt/cni/bin
      - name: install-cni
        image: {{ .ReleaseImage.kube_flannel }}
        imagePullPolicy: IfNotPresent
        command:
        - cp
        args:
        - -f
        - /etc/kube-flannel/cni-conf.json
        - /etc/cni/net.d/10-flannel.conflist
        volumeMounts:
        - name: cni
          mountPath: /etc/cni/net.d
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      containers:
      - name: kube-flannel
        image: {{ .ReleaseImage.kube_flannel }}
        imagePullPolicy: IfNotPresent
        command:
        - /opt/bin/flanneld
        args:
        - --ip-masq
        - --kube-subnet-mgr
        resources:
          requests:
            cpu: "100m"
            memory: "50Mi"
          limits:
            cpu: "100m"
            memory: "50Mi"
        securityContext:
          privileged: false
          capabilities:
            add: ["NET_ADMIN", "NET_RAW"]
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        volumeMounts:
        - name: run
          mountPath: /run/flannel
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      volumes:
      - name: run
        hostPath:
          path: /run/flannel
      - name: cni
        hostPath:
          path: /etc/cni/net.d
      - name: flannel-cfg
        configMap:
          name: kube-flannel-cfg
      - name: cni-plugin
        hostPath:
          path: /opt/cni/bin`)

func assetsComponentsFlannelDaemonsetYamlBytes() ([]byte, error) {
	return _assetsComponentsFlannelDaemonsetYaml, nil
}

func assetsComponentsFlannelDaemonsetYaml() (*asset, error) {
	bytes, err := assetsComponentsFlannelDaemonsetYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/flannel/daemonset.yaml", size: 2657, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsFlannelPodsecuritypolicyYaml = []byte(`apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: psp.flannel.unprivileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: docker/default
    seccomp.security.alpha.kubernetes.io/defaultProfileName: docker/default
    apparmor.security.beta.kubernetes.io/allowedProfileNames: runtime/default
    apparmor.security.beta.kubernetes.io/defaultProfileName: runtime/default
spec:
  privileged: false
  volumes:
  - configMap
  - secret
  - emptyDir
  - hostPath
  allowedHostPaths:
  - pathPrefix: "/etc/cni/net.d"
  - pathPrefix: "/etc/kube-flannel"
  - pathPrefix: "/run/flannel"
  readOnlyRootFilesystem: false
  # Users and groups
  runAsUser:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  # Privilege Escalation
  allowPrivilegeEscalation: false
  defaultAllowPrivilegeEscalation: false
  # Capabilities
  allowedCapabilities: ['NET_ADMIN', 'NET_RAW']
  defaultAddCapabilities: []
  requiredDropCapabilities: []
  # Host namespaces
  hostPID: false
  hostIPC: false
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  # SELinux
  seLinux:
    # SELinux is unused in CaaSP
    rule: 'RunAsAny'`)

func assetsComponentsFlannelPodsecuritypolicyYamlBytes() ([]byte, error) {
	return _assetsComponentsFlannelPodsecuritypolicyYaml, nil
}

func assetsComponentsFlannelPodsecuritypolicyYaml() (*asset, error) {
	bytes, err := assetsComponentsFlannelPodsecuritypolicyYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/flannel/podsecuritypolicy.yaml", size: 1195, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsFlannelServiceAccountYaml = []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: flannel
  namespace: kube-system`)

func assetsComponentsFlannelServiceAccountYamlBytes() ([]byte, error) {
	return _assetsComponentsFlannelServiceAccountYaml, nil
}

func assetsComponentsFlannelServiceAccountYaml() (*asset, error) {
	bytes, err := assetsComponentsFlannelServiceAccountYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/flannel/service-account.yaml", size: 86, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsHostpathProvisionerClusterroleYaml = []byte(`kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: kubevirt-hostpath-provisioner
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]

  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]

  - apiGroups: [""]
    resources: ["events"]
    verbs: ["list", "watch", "create", "update", "patch"]
`)

func assetsComponentsHostpathProvisionerClusterroleYamlBytes() ([]byte, error) {
	return _assetsComponentsHostpathProvisionerClusterroleYaml, nil
}

func assetsComponentsHostpathProvisionerClusterroleYaml() (*asset, error) {
	bytes, err := assetsComponentsHostpathProvisionerClusterroleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/hostpath-provisioner/clusterrole.yaml", size: 609, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsHostpathProvisionerClusterrolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubevirt-hostpath-provisioner
subjects:
- kind: ServiceAccount
  name: kubevirt-hostpath-provisioner-admin
  namespace: kubevirt-hostpath-provisioner
roleRef:
  kind: ClusterRole
  name: kubevirt-hostpath-provisioner
  apiGroup: rbac.authorization.k8s.io`)

func assetsComponentsHostpathProvisionerClusterrolebindingYamlBytes() ([]byte, error) {
	return _assetsComponentsHostpathProvisionerClusterrolebindingYaml, nil
}

func assetsComponentsHostpathProvisionerClusterrolebindingYaml() (*asset, error) {
	bytes, err := assetsComponentsHostpathProvisionerClusterrolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/hostpath-provisioner/clusterrolebinding.yaml", size: 338, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsHostpathProvisionerDaemonsetYaml = []byte(`apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kubevirt-hostpath-provisioner
  labels:
    k8s-app: kubevirt-hostpath-provisioner
  namespace: kubevirt-hostpath-provisioner
spec:
  selector:
    matchLabels:
      k8s-app: kubevirt-hostpath-provisioner
  template:
    metadata:
      labels:
        k8s-app: kubevirt-hostpath-provisioner
    spec:
      serviceAccountName: kubevirt-hostpath-provisioner-admin
      containers:
        - name: kubevirt-hostpath-provisioner
          image: {{ .ReleaseImage.kubevirt_hostpath_provisioner }}
          imagePullPolicy: IfNotPresent
          env:
            - name: USE_NAMING_PREFIX
              value: "false" # change to true, to have the name of the pvc be part of the directory
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: PV_DIR
              value: /var/hpvolumes
          volumeMounts:
            - name: pv-volume # root dir where your bind mounts will be on the node
              mountPath: /var/hpvolumes
              #nodeSelector:
              #- name: xxxxxx
      volumes:
        - name: pv-volume
          hostPath:
            path: /var/hpvolumes
`)

func assetsComponentsHostpathProvisionerDaemonsetYamlBytes() ([]byte, error) {
	return _assetsComponentsHostpathProvisionerDaemonsetYaml, nil
}

func assetsComponentsHostpathProvisionerDaemonsetYaml() (*asset, error) {
	bytes, err := assetsComponentsHostpathProvisionerDaemonsetYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/hostpath-provisioner/daemonset.yaml", size: 1231, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsHostpathProvisionerNamespaceYaml = []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: kubevirt-hostpath-provisioner`)

func assetsComponentsHostpathProvisionerNamespaceYamlBytes() ([]byte, error) {
	return _assetsComponentsHostpathProvisionerNamespaceYaml, nil
}

func assetsComponentsHostpathProvisionerNamespaceYaml() (*asset, error) {
	bytes, err := assetsComponentsHostpathProvisionerNamespaceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/hostpath-provisioner/namespace.yaml", size: 78, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsHostpathProvisionerSccYaml = []byte(`kind: SecurityContextConstraints
apiVersion: security.openshift.io/v1
metadata:
  name: hostpath-provisioner
allowPrivilegedContainer: true
requiredDropCapabilities:
- KILL
- MKNOD
- SETUID
- SETGID
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: RunAsAny
fsGroup:
  type: RunAsAny
supplementalGroups:
  type: RunAsAny
allowHostDirVolumePlugin: true
users:
- system:serviceaccount:kubevirt-hostpath-provisioner:kubevirt-hostpath-provisioner-admin
volumes:
- hostPath
- secret
`)

func assetsComponentsHostpathProvisionerSccYamlBytes() ([]byte, error) {
	return _assetsComponentsHostpathProvisionerSccYaml, nil
}

func assetsComponentsHostpathProvisionerSccYaml() (*asset, error) {
	bytes, err := assetsComponentsHostpathProvisionerSccYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/hostpath-provisioner/scc.yaml", size: 480, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsHostpathProvisionerServiceAccountYaml = []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubevirt-hostpath-provisioner-admin
  namespace: kubevirt-hostpath-provisioner`)

func assetsComponentsHostpathProvisionerServiceAccountYamlBytes() ([]byte, error) {
	return _assetsComponentsHostpathProvisionerServiceAccountYaml, nil
}

func assetsComponentsHostpathProvisionerServiceAccountYaml() (*asset, error) {
	bytes, err := assetsComponentsHostpathProvisionerServiceAccountYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/hostpath-provisioner/service-account.yaml", size: 132, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsHostpathProvisionerStorageclassYaml = []byte(`apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: kubevirt-hostpath-provisioner
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: kubevirt.io/hostpath-provisioner
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
`)

func assetsComponentsHostpathProvisionerStorageclassYamlBytes() ([]byte, error) {
	return _assetsComponentsHostpathProvisionerStorageclassYaml, nil
}

func assetsComponentsHostpathProvisionerStorageclassYaml() (*asset, error) {
	bytes, err := assetsComponentsHostpathProvisionerStorageclassYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/hostpath-provisioner/storageclass.yaml", size: 276, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsDnsClusterRoleBindingYaml = []byte(`kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
    name: openshift-dns
subjects:
- kind: ServiceAccount
  name: dns
  namespace: openshift-dns
roleRef:
  kind: ClusterRole
  name: openshift-dns
`)

func assetsComponentsOpenshiftDnsDnsClusterRoleBindingYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsDnsClusterRoleBindingYaml, nil
}

func assetsComponentsOpenshiftDnsDnsClusterRoleBindingYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsDnsClusterRoleBindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/dns/cluster-role-binding.yaml", size: 223, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsDnsClusterRoleYaml = []byte(`kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: openshift-dns
rules:
- apiGroups:
  - ""
  resources:
  - endpoints
  - services
  - pods
  - namespaces
  verbs:
  - list
  - watch

- apiGroups:
  - discovery.k8s.io
  resources:
  - endpointslices
  verbs:
  - list
  - watch

- apiGroups:
  - authentication.k8s.io
  resources:
  - tokenreviews
  verbs:
  - create

- apiGroups:
  - authorization.k8s.io
  resources:
  - subjectaccessreviews
  verbs:
  - create
`)

func assetsComponentsOpenshiftDnsDnsClusterRoleYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsDnsClusterRoleYaml, nil
}

func assetsComponentsOpenshiftDnsDnsClusterRoleYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsDnsClusterRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/dns/cluster-role.yaml", size: 492, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsDnsConfigmapYaml = []byte(`apiVersion: v1
data:
  Corefile: |
    .:5353 {
        bufsize 512
        errors
        health {
            lameduck 20s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
            pods insecure
            fallthrough in-addr.arpa ip6.arpa
        }
        prometheus 127.0.0.1:9153
        forward . /etc/resolv.conf {
            policy sequential
        }
        cache 900 {
            denial 9984 30
        }
        reload
    }
kind: ConfigMap
metadata:
  labels:
    dns.operator.openshift.io/owning-dns: default
  name: dns-default
  namespace: openshift-dns
`)

func assetsComponentsOpenshiftDnsDnsConfigmapYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsDnsConfigmapYaml, nil
}

func assetsComponentsOpenshiftDnsDnsConfigmapYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsDnsConfigmapYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/dns/configmap.yaml", size: 610, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsDnsDaemonsetYaml = []byte(`kind: DaemonSet
apiVersion: apps/v1
metadata:
  labels:
    dns.operator.openshift.io/owning-dns: default
  name: dns-default
  namespace: openshift-dns
spec:
  selector:
    matchLabels:
      dns.operator.openshift.io/daemonset-dns: default
  template:
    metadata:
      labels:
        dns.operator.openshift.io/daemonset-dns: default
      annotations:
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
    spec:
      serviceAccountName: dns
      priorityClassName: system-node-critical
      containers:
      - name: dns
        image: {{ .ReleaseImage.coredns }}
        imagePullPolicy: IfNotPresent
        terminationMessagePolicy: FallbackToLogsOnError
        command: [ "coredns" ]
        args: [ "-conf", "/etc/coredns/Corefile" ]
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
          readOnly: true
        ports:
        - containerPort: 5353
          name: dns
          protocol: UDP
        - containerPort: 5353
          name: dns-tcp
          protocol: TCP
        readinessProbe:
          httpGet:
            path: /ready
            port: 8181
            scheme: HTTP
          initialDelaySeconds: 10
          periodSeconds: 3
          successThreshold: 1
          failureThreshold: 3
          timeoutSeconds: 3
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        resources:
          requests:
            cpu: 50m
            memory: 70Mi
      - name: kube-rbac-proxy
        image: {{ .ReleaseImage.kube_rbac_proxy }}
        imagePullPolicy: IfNotPresent
        args:
        - --secure-listen-address=:9154
        - --tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        - --upstream=http://127.0.0.1:9153/
        - --tls-cert-file=/etc/tls/private/tls.crt
        - --tls-private-key-file=/etc/tls/private/tls.key
        ports:
        - containerPort: 9154
          name: metrics
        resources:
          requests:
            cpu: 10m
            memory: 40Mi
        volumeMounts:
        - mountPath: /etc/tls/private
          name: metrics-tls
          readOnly: true
      dnsPolicy: Default
      nodeSelector:
        kubernetes.io/os: linux      
      volumes:
      - name: config-volume
        configMap:
          items:
          - key: Corefile
            path: Corefile
          name: dns-default
      - name: metrics-tls
        secret:
          defaultMode: 420
          secretName: dns-default-metrics-tls
      tolerations:
      # DNS needs to run everywhere. Tolerate all taints
      - operator: Exists
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      # TODO: Consider setting maxSurge to a positive value.
      maxSurge: 0
      # Note: The daemon controller rounds the percentage up
      # (unlike the deployment controller, which rounds down).
      maxUnavailable: 10%
`)

func assetsComponentsOpenshiftDnsDnsDaemonsetYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsDnsDaemonsetYaml, nil
}

func assetsComponentsOpenshiftDnsDnsDaemonsetYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsDnsDaemonsetYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/dns/daemonset.yaml", size: 3217, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsDnsNamespaceYaml = []byte(`kind: Namespace
apiVersion: v1
metadata:
  annotations:
    openshift.io/node-selector: ""
    workload.openshift.io/allowed: "management"
  name: openshift-dns
  labels:
    # set value to avoid depending on kube admission that depends on openshift apis
    openshift.io/run-level: "0"
    # allow openshift-monitoring to look for ServiceMonitor objects in this namespace
    openshift.io/cluster-monitoring: "true"
`)

func assetsComponentsOpenshiftDnsDnsNamespaceYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsDnsNamespaceYaml, nil
}

func assetsComponentsOpenshiftDnsDnsNamespaceYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsDnsNamespaceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/dns/namespace.yaml", size: 417, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsDnsServiceAccountYaml = []byte(`kind: ServiceAccount
apiVersion: v1
metadata:
  name: dns
  namespace: openshift-dns
`)

func assetsComponentsOpenshiftDnsDnsServiceAccountYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsDnsServiceAccountYaml, nil
}

func assetsComponentsOpenshiftDnsDnsServiceAccountYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsDnsServiceAccountYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/dns/service-account.yaml", size: 85, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsDnsServiceYaml = []byte(`kind: Service
apiVersion: v1
metadata:
  annotations:
    service.beta.openshift.io/serving-cert-secret-name: dns-default-metrics-tls
  labels:
      dns.operator.openshift.io/owning-dns: default
  name: dns-default
  namespace: openshift-dns
spec:
  clusterIP: {{.ClusterIP}}
  selector:
    dns.operator.openshift.io/daemonset-dns: default
  ports:
  - name: dns
    port: 53
    targetPort: dns
    protocol: UDP
  - name: dns-tcp
    port: 53
    targetPort: dns-tcp
    protocol: TCP
  - name: metrics
    port: 9154
    targetPort: metrics
    protocol: TCP
  # TODO: Uncomment when service topology feature gate is enabled.
  #topologyKeys:
  #  - "kubernetes.io/hostname"
  #  - "*"
`)

func assetsComponentsOpenshiftDnsDnsServiceYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsDnsServiceYaml, nil
}

func assetsComponentsOpenshiftDnsDnsServiceYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsDnsServiceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/dns/service.yaml", size: 691, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsNodeResolverDaemonsetYaml = []byte(`apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-resolver
  namespace: openshift-dns
spec:
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      dns.operator.openshift.io/daemonset-node-resolver: ""
  template:
    metadata:
      annotations:
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
      labels:
        dns.operator.openshift.io/daemonset-node-resolver: ""
    spec:
      containers:
      - command:
        - /bin/bash
        - -c
        - |
          #!/bin/bash
          set -uo pipefail

          trap 'jobs -p | xargs kill || true; wait; exit 0' TERM

          NAMESERVER=${DNS_DEFAULT_SERVICE_HOST}
          OPENSHIFT_MARKER="openshift-generated-node-resolver"
          HOSTS_FILE="/etc/hosts"
          TEMP_FILE="/etc/hosts.tmp"

          IFS=', ' read -r -a services <<< "${SERVICES}"

          # Make a temporary file with the old hosts file's attributes.
          cp -f --attributes-only "${HOSTS_FILE}" "${TEMP_FILE}"

          while true; do
            declare -A svc_ips
            for svc in "${services[@]}"; do
              # Fetch service IP from cluster dns if present. We make several tries
              # to do it: IPv4, IPv6, IPv4 over TCP and IPv6 over TCP. The two last ones
              # are for deployments with Kuryr on older OpenStack (OSP13) - those do not
              # support UDP loadbalancers and require reaching DNS through TCP.
              cmds=('dig -t A @"${NAMESERVER}" +short "${svc}.${CLUSTER_DOMAIN}"|grep -v "^;"'
                    'dig -t AAAA @"${NAMESERVER}" +short "${svc}.${CLUSTER_DOMAIN}"|grep -v "^;"'
                    'dig -t A +tcp +retry=0 @"${NAMESERVER}" +short "${svc}.${CLUSTER_DOMAIN}"|grep -v "^;"'
                    'dig -t AAAA +tcp +retry=0 @"${NAMESERVER}" +short "${svc}.${CLUSTER_DOMAIN}"|grep -v "^;"')
              for i in ${!cmds[*]}
              do
                ips=($(eval "${cmds[i]}"))
                if [[ "$?" -eq 0 && "${#ips[@]}" -ne 0 ]]; then
                  svc_ips["${svc}"]="${ips[@]}"
                  break
                fi
              done
            done

            # Update /etc/hosts only if we get valid service IPs
            # We will not update /etc/hosts when there is coredns service outage or api unavailability
            # Stale entries could exist in /etc/hosts if the service is deleted
            if [[ -n "${svc_ips[*]-}" ]]; then
              # Build a new hosts file from /etc/hosts with our custom entries filtered out
              grep -v "# ${OPENSHIFT_MARKER}" "${HOSTS_FILE}" > "${TEMP_FILE}"

              # Append resolver entries for services
              for svc in "${!svc_ips[@]}"; do
                for ip in ${svc_ips[${svc}]}; do
                  echo "${ip} ${svc} ${svc}.${CLUSTER_DOMAIN} # ${OPENSHIFT_MARKER}" >> "${TEMP_FILE}"
                done
              done

              # TODO: Update /etc/hosts atomically to avoid any inconsistent behavior
              # Replace /etc/hosts with our modified version if needed
              cmp "${TEMP_FILE}" "${HOSTS_FILE}" || cp -f "${TEMP_FILE}" "${HOSTS_FILE}"
              # TEMP_FILE is not removed to avoid file create/delete and attributes copy churn
            fi
            sleep 60 & wait
            unset svc_ips
          done
        env:
        - name: SERVICES
          # Comma or space separated list of services
          # NOTE: For now, ensure these are relative names; for each relative name,
          # an alias with the CLUSTER_DOMAIN suffix will also be added.
          value: "image-registry.openshift-image-registry.svc"
        - name: NAMESERVER
          value: 172.30.0.10
        - name: CLUSTER_DOMAIN
          value: cluster.local
        image: {{ .ReleaseImage.cli }}
        imagePullPolicy: IfNotPresent
        name: dns-node-resolver
        resources:
          requests:
            cpu: 5m
            memory: 21Mi
        securityContext:
          privileged: true
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: FallbackToLogsOnError
        volumeMounts:
        - mountPath: /etc/hosts
          name: hosts-file
      dnsPolicy: ClusterFirst
      hostNetwork: true
      nodeSelector:
        kubernetes.io/os: linux
      priorityClassName: system-node-critical
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      serviceAccount: node-resolver
      serviceAccountName: node-resolver
      terminationGracePeriodSeconds: 30
      tolerations:
      - operator: Exists
      volumes:
      - hostPath:
          path: /etc/hosts
          type: File
        name: hosts-file
  updateStrategy:
    rollingUpdate:
      maxSurge: 0
      maxUnavailable: 33%
    type: RollingUpdate
`)

func assetsComponentsOpenshiftDnsNodeResolverDaemonsetYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsNodeResolverDaemonsetYaml, nil
}

func assetsComponentsOpenshiftDnsNodeResolverDaemonsetYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsNodeResolverDaemonsetYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/node-resolver/daemonset.yaml", size: 4823, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftDnsNodeResolverServiceAccountYaml = []byte(`kind: ServiceAccount
apiVersion: v1
metadata:
  name: node-resolver
  namespace: openshift-dns
`)

func assetsComponentsOpenshiftDnsNodeResolverServiceAccountYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftDnsNodeResolverServiceAccountYaml, nil
}

func assetsComponentsOpenshiftDnsNodeResolverServiceAccountYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftDnsNodeResolverServiceAccountYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-dns/node-resolver/service-account.yaml", size: 95, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftRouterClusterRoleBindingYaml = []byte(`# Binds the router role to its Service Account.
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: openshift-ingress-router
subjects:
- kind: ServiceAccount
  name: router
  namespace: openshift-ingress
roleRef:
  kind: ClusterRole
  name: openshift-ingress-router
  namespace: openshift-ingress
`)

func assetsComponentsOpenshiftRouterClusterRoleBindingYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftRouterClusterRoleBindingYaml, nil
}

func assetsComponentsOpenshiftRouterClusterRoleBindingYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftRouterClusterRoleBindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-router/cluster-role-binding.yaml", size: 329, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftRouterClusterRoleYaml = []byte(`# Cluster scoped role for routers. This should be as restrictive as possible.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: openshift-ingress-router
rules:
- apiGroups:
  - ""
  resources:
  - endpoints
  - namespaces
  - services
  verbs:
  - list
  - watch

- apiGroups:
  - authentication.k8s.io
  resources:
  - tokenreviews
  verbs:
  - create

- apiGroups:
  - authorization.k8s.io
  resources:
  - subjectaccessreviews
  verbs:
  - create

- apiGroups:
  - route.openshift.io
  resources:
  - routes
  verbs:
  - list
  - watch

- apiGroups:
  - route.openshift.io
  resources:
  - routes/status
  verbs:
  - update

- apiGroups:
  - security.openshift.io
  resources:
  - securitycontextconstraints
  verbs:
  - use
  resourceNames:
  - hostnetwork

- apiGroups:
  - discovery.k8s.io
  resources:
  - endpointslices
  verbs:
  - list
  - watch
`)

func assetsComponentsOpenshiftRouterClusterRoleYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftRouterClusterRoleYaml, nil
}

func assetsComponentsOpenshiftRouterClusterRoleYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftRouterClusterRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-router/cluster-role.yaml", size: 883, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftRouterConfigmapYaml = []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  namespace: openshift-ingress
  name: service-ca-bundle 
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
`)

func assetsComponentsOpenshiftRouterConfigmapYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftRouterConfigmapYaml, nil
}

func assetsComponentsOpenshiftRouterConfigmapYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftRouterConfigmapYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-router/configmap.yaml", size: 168, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftRouterDeploymentYaml = []byte(`# Deployment with default values
# Ingress Controller specific values are applied at runtime.
kind: Deployment
apiVersion: apps/v1
metadata:
  name: router-default
  namespace: openshift-ingress
  labels:
    ingresscontroller.operator.openshift.io/deployment-ingresscontroller: default
spec:
  progressDeadlineSeconds: 600
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      ingresscontroller.operator.openshift.io/deployment-ingresscontroller: default
  strategy:
    rollingUpdate:
      maxSurge: 0
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      annotations:
        "unsupported.do-not-use.openshift.io/override-liveness-grace-period-seconds": "10"
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
      labels:
        ingresscontroller.operator.openshift.io/deployment-ingresscontroller: default
    spec:
      serviceAccountName: router
      # nodeSelector is set at runtime.
      priorityClassName: system-cluster-critical
      containers:
        - name: router
          image: {{ .ReleaseImage.haproxy_router }}
          imagePullPolicy: IfNotPresent
          terminationMessagePolicy: FallbackToLogsOnError
          ports:
          - name: http
            containerPort: 80
            hostPort: 80
            protocol: TCP
          - name: https
            containerPort: 443
            hostPort: 443
            protocol: TCP
          - name: metrics
            containerPort: 1936
            hostPort: 1936
            protocol: TCP
          # Merged at runtime.
          env:
          # stats username and password are generated at runtime
          - name: STATS_PORT
            value: "1936"
          - name: ROUTER_SERVICE_NAMESPACE
            value: openshift-ingress
          - name: DEFAULT_CERTIFICATE_DIR
            value: /etc/pki/tls/private
          - name: DEFAULT_DESTINATION_CA_PATH
            value: /var/run/configmaps/service-ca/service-ca.crt
          - name: ROUTER_CIPHERS
            value: TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
          - name: ROUTER_DISABLE_HTTP2
            value: "true"
          - name: ROUTER_DISABLE_NAMESPACE_OWNERSHIP_CHECK
            value: "false"
          #FIXME: use metrics tls
          - name: ROUTER_METRICS_TLS_CERT_FILE
            value: /etc/pki/tls/private/tls.crt
          - name: ROUTER_METRICS_TLS_KEY_FILE
            value: /etc/pki/tls/private/tls.key
          - name: ROUTER_METRICS_TYPE
            value: haproxy
          - name: ROUTER_SERVICE_NAME
            value: default
          - name: ROUTER_SET_FORWARDED_HEADERS
            value: append
          - name: ROUTER_THREADS
            value: "4"
          - name: SSL_MIN_VERSION
            value: TLSv1.2
          livenessProbe:
            failureThreshold: 3
            httpGet:
              host: localhost
              path: /healthz
              port: 1936
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
          readinessProbe:
            failureThreshold: 3
            httpGet:
              host: localhost
              path: /healthz/ready
              port: 1936
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
          startupProbe:
            failureThreshold: 120
            httpGet:
              path: /healthz/ready
              port: 1936
            periodSeconds: 1
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
          volumeMounts:
          - mountPath: /etc/pki/tls/private
            name: default-certificate
            readOnly: true
          - mountPath: /var/run/configmaps/service-ca
            name: service-ca-bundle
            readOnly: true
      dnsPolicy: ClusterFirstWithHostNet
      hostNetwork: true
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      serviceAccount: router
      volumes:
      - name: default-certificate
        secret:
          defaultMode: 420
          secretName: router-certs-default
      - name: service-ca-bundle
        configMap:
          items:
          - key: service-ca.crt
            path: service-ca.crt
          name: service-ca-bundle
          optional: false
        defaultMode: 420
`)

func assetsComponentsOpenshiftRouterDeploymentYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftRouterDeploymentYaml, nil
}

func assetsComponentsOpenshiftRouterDeploymentYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftRouterDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-router/deployment.yaml", size: 4746, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftRouterNamespaceYaml = []byte(`kind: Namespace
apiVersion: v1
metadata:
  name: openshift-ingress
  annotations:
    openshift.io/node-selector: ""
    workload.openshift.io/allowed: "management"
  labels:
    # allow openshift-monitoring to look for ServiceMonitor objects in this namespace
    openshift.io/cluster-monitoring: "true"
    name: openshift-ingress
    # old and new forms of the label for matching with NetworkPolicy
    network.openshift.io/policy-group: ingress
    policy-group.network.openshift.io/ingress: ""
`)

func assetsComponentsOpenshiftRouterNamespaceYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftRouterNamespaceYaml, nil
}

func assetsComponentsOpenshiftRouterNamespaceYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftRouterNamespaceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-router/namespace.yaml", size: 499, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftRouterServiceAccountYaml = []byte(`# Account for routers created by the operator. It will require cluster scoped
# permissions related to Route processing.
kind: ServiceAccount
apiVersion: v1
metadata:
  name: router
  namespace: openshift-ingress
`)

func assetsComponentsOpenshiftRouterServiceAccountYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftRouterServiceAccountYaml, nil
}

func assetsComponentsOpenshiftRouterServiceAccountYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftRouterServiceAccountYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-router/service-account.yaml", size: 213, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftRouterServiceCloudYaml = []byte(`kind: Service
apiVersion: v1
metadata:
  annotations:
    service.alpha.openshift.io/serving-cert-secret-name: router-certs-default
  labels:
    ingresscontroller.operator.openshift.io/deployment-ingresscontroller: default
  name: router-external-default
  namespace: openshift-ingress
spec:
  selector:
    ingresscontroller.operator.openshift.io/deployment-ingresscontroller: default
  type: NodePort 
  ports:
    - name: http
      port: 80
      targetPort: 80
      nodePort: 30001
    - name: https
      port: 443
      targetPort: 443
      nodePort: 30002
`)

func assetsComponentsOpenshiftRouterServiceCloudYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftRouterServiceCloudYaml, nil
}

func assetsComponentsOpenshiftRouterServiceCloudYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftRouterServiceCloudYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-router/service-cloud.yaml", size: 567, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOpenshiftRouterServiceInternalYaml = []byte(`# Cluster Service with default values
# Ingress Controller specific annotations are applied at runtime.
kind: Service
apiVersion: v1
metadata:
  annotations:
    service.alpha.openshift.io/serving-cert-secret-name: router-certs-default
  labels:
    ingresscontroller.operator.openshift.io/deployment-ingresscontroller: default
  name: router-internal-default
  namespace: openshift-ingress
spec:
  selector:
    ingresscontroller.operator.openshift.io/deployment-ingresscontroller: default
  type: ClusterIP
  ports:
  - name: http
    port: 80
    protocol: TCP
    targetPort: http
  - name: https
    port: 443
    protocol: TCP
    targetPort: https
  - name: metrics
    port: 1936
    protocol: TCP
    targetPort: 1936
`)

func assetsComponentsOpenshiftRouterServiceInternalYamlBytes() ([]byte, error) {
	return _assetsComponentsOpenshiftRouterServiceInternalYaml, nil
}

func assetsComponentsOpenshiftRouterServiceInternalYaml() (*asset, error) {
	bytes, err := assetsComponentsOpenshiftRouterServiceInternalYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/openshift-router/service-internal.yaml", size: 727, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnClusterroleYaml = []byte(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: openshift-ovn-kubernetes-node
rules:
- apiGroups: [""]
  resources:
  - pods
  verbs:
  - get
  - list
  - watch
  - patch
- apiGroups: [""]
  resources:
  - namespaces
  - endpoints
  - services
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - discovery.k8s.io
  resources:
  - endpointslices
  verbs:
  - list
  - watch
- apiGroups: ["networking.k8s.io"]
  resources:
  - networkpolicies
  verbs:
  - get
  - list
  - watch
- apiGroups: ["", "events.k8s.io"]
  resources:
  - events
  verbs:
  - create
  - patch
  - update
- apiGroups: [""]
  resources:
  - nodes
  verbs:
  - get
  - list
  - watch
  - patch
  - update
- apiGroups: ["k8s.ovn.org"]
  resources:
  - egressips
  verbs:
  - get
  - list
  - watch
- apiGroups: ["apiextensions.k8s.io"]
  resources:
  - customresourcedefinitions
  verbs:
    - get
    - list
    - watch
- apiGroups: ['authentication.k8s.io']
  resources: ['tokenreviews']
  verbs: ['create']
- apiGroups: ['authorization.k8s.io']
  resources: ['subjectaccessreviews']
  verbs: ['create']

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: openshift-ovn-kubernetes-controller
rules:
- apiGroups: [""]
  resources:
  - namespaces
  - nodes
  - pods
  verbs:
  - get
  - list
  - patch
  - watch
  - update
- apiGroups: [""]
  resources:
  - pods
  verbs:
  - get
  - list
  - patch
  - watch
  - delete
- apiGroups: [""]
  resources:
  - configmaps
  verbs:
  - get
  - create
  - update
  - patch
- apiGroups: [""]
  resources:
  - services
  - endpoints
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - discovery.k8s.io
  resources:
  - endpointslices
  verbs:
  - list
  - watch
- apiGroups: ["networking.k8s.io"]
  resources:
  - networkpolicies
  verbs:
  - get
  - list
  - watch
- apiGroups: ["", "events.k8s.io"]
  resources:
  - events
  verbs:
  - create
  - patch
  - update
- apiGroups: ["security.openshift.io"]
  resources:
  - securitycontextconstraints
  verbs:
  - use
  resourceNames:
  - privileged
- apiGroups: [""]
  resources:
  - "nodes/status"
  verbs:
  - patch
  - update
- apiGroups: ["k8s.ovn.org"]
  resources:
  - egressfirewalls
  - egressips
  - egressqoses
  verbs:
  - get
  - list
  - watch
  - update
  - patch
- apiGroups: ["cloud.network.openshift.io"]
  resources:
  - cloudprivateipconfigs
  verbs:
  - create
  - patch
  - update
  - delete
  - get
  - list
  - watch
- apiGroups: ["apiextensions.k8s.io"]
  resources:
  - customresourcedefinitions
  verbs:
    - get
    - list
    - watch
- apiGroups: ['authentication.k8s.io']
  resources: ['tokenreviews']
  verbs: ['create']
- apiGroups: ['authorization.k8s.io']
  resources: ['subjectaccessreviews']
  verbs: ['create']
`)

func assetsComponentsOvnClusterroleYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnClusterroleYaml, nil
}

func assetsComponentsOvnClusterroleYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnClusterroleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/clusterrole.yaml", size: 2771, mode: os.FileMode(436), modTime: time.Unix(1653813555, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnClusterrolebindingYaml = []byte(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: openshift-ovn-kubernetes-node
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: openshift-ovn-kubernetes-node
subjects:
- kind: ServiceAccount
  name: ovn-kubernetes-node
  namespace: openshift-ovn-kubernetes

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: openshift-ovn-kubernetes-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: openshift-ovn-kubernetes-controller
subjects:
- kind: ServiceAccount
  name: ovn-kubernetes-controller
  namespace: openshift-ovn-kubernetes
`)

func assetsComponentsOvnClusterrolebindingYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnClusterrolebindingYaml, nil
}

func assetsComponentsOvnClusterrolebindingYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnClusterrolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/clusterrolebinding.yaml", size: 663, mode: os.FileMode(436), modTime: time.Unix(1653813572, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnConfigmapOvnCaYaml = []byte(`apiVersion: v1
data:
  ca-bundle.crt: |
    -----BEGIN CERTIFICATE-----
    MIIDTzCCAjegAwIBAgIIFdR7cyl+zQcwDQYJKoZIhvcNAQELBQAwNTEzMDEGA1UE
    Awwqb3BlbnNoaWZ0LW92bi1rdWJlcm5ldGVzX292bi1jYUAxNjUzMzEyMTA4MB4X
    DTIyMDUyMzEzMjE0N1oXDTMyMDUyMDEzMjE0OFowNTEzMDEGA1UEAwwqb3BlbnNo
    aWZ0LW92bi1rdWJlcm5ldGVzX292bi1jYUAxNjUzMzEyMTA4MIIBIjANBgkqhkiG
    9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz9xtIk8t19f1CbNCJTtdg6uTRcaO5TWiwv8t
    fp/BJeOV3HoLImC3ok9UyKaO/BPSOgBy7X2E9E0hodgggsNXVwvAyqTLpxU5gPQS
    QSNaOQM2HkWJJWW8GeYvq7+7ZSIJD2gXEnZHwI/FluN6Q41qMScV4BZHFX5xiTbm
    PcELZyCXDInXyFoW23yCSJ68LFFAct2rpeK2TvM3affrQ/xAp4oIwYZvZ3Fn835I
    A4hYhw0iEgkKewZVgWBNbbMy/l9qnwaboYXBa92WsgS/9UJqRwlxvBkCDJ08AGBn
    0OlF+PJI204t8F2tL2JrHqN1WtkWgYf6Tur1vITKq7G3ngmW0wIDAQABo2MwYTAO
    BgNVHQ8BAf8EBAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUvjmJcaPn
    UOevhPI6iJM0I1Ux2ZUwHwYDVR0jBBgwFoAUvjmJcaPnUOevhPI6iJM0I1Ux2ZUw
    DQYJKoZIhvcNAQELBQADggEBAGuu3uOP4yzy6OaK1vdy7k5xH1JCwhbkygG8C3NO
    0A9cDTGrCbR+3F8blv+TopV49xOrP/82X9GaQBpfnsYC44FL5P4oppYDJh3YPITV
    mrOhx376hAs4e1WMFbgRNdHxDSzQr5+Xb+wcwBy2Bqfp2v53SRKX5m5ZKU8lYWqq
    YEHRCtTZWlmOQo1AThJHgx5QesLnJsk4ikGtiVkFr+Hpv1MrrTwmKy3n2Ytu2Zrj
    xOdBhakRaqdSN8R3ZvFnQcqNGqShq9gCG10KriTjLEmBlZXsJ7y84TKvH8IJS8WT
    jzeF3oIxeCrkL7zXiq3veFasmEceip93h+zKLbZakLN4B+k=
    -----END CERTIFICATE-----
kind: ConfigMap
metadata:
  labels:
    auth.openshift.io/managed-certificate-type: ca-bundle
  name: ovn-ca
  namespace: openshift-ovn-kubernetes
`)

func assetsComponentsOvnConfigmapOvnCaYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnConfigmapOvnCaYaml, nil
}

func assetsComponentsOvnConfigmapOvnCaYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnConfigmapOvnCaYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/configmap-ovn-ca.yaml", size: 1475, mode: os.FileMode(436), modTime: time.Unix(1653813524, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnConfigmapYaml = []byte(`---
# The ovnconfig config file. Used by both node and master processes.
kind: ConfigMap
apiVersion: v1
metadata:
  name: ovnkube-config
  namespace: openshift-ovn-kubernetes
data:
  ovnkube.conf:   |-
    [default]
    mtu="1400"
    cluster-subnets="10.128.0.0/14/23"
    encap-port="6081"
    enable-lflow-cache=true
    lflow-cache-limit-kb=1048576

    [kubernetes]
    service-cidrs="172.30.0.0/16"
    ovn-config-namespace="openshift-ovn-kubernetes"
    # apiserver="https://10.73.116.66:6443"
    kubeconfig="/var/lib/microshift/resources/kubeadmin/kubeconfig"
    host-network-namespace="openshift-host-network"
    platform-type="BareMetal"
 
    [ovnkubernetesfeature]
    enable-egress-ip=true
    enable-egress-firewall=true
    enable-egress-qos=true

    [gateway]
    mode=shared
    nodeport=true

    [masterha]
    election-lease-duration=137
    election-renew-deadline=107
    election-retry-period=26
`)

func assetsComponentsOvnConfigmapYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnConfigmapYaml, nil
}

func assetsComponentsOvnConfigmapYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnConfigmapYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/configmap.yaml", size: 923, mode: os.FileMode(436), modTime: time.Unix(1653813505, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnMasterDaemonsetYamlSwp = []byte("b0VIM 8.2\x00\x00\x00\x00\x10\x00\x00 5\x93bt~f\x00\x92\x92\x12\x00zshi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00localhost.localdomain\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00~zshi/git/openshift/microshift/assets/components/ovn/master/daemonset.yaml\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00utf-8\r\x003210\x00\x00\x00\x00#\"! \x13\x12U\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00tp\t\x00\u007f\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00p\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\a\x00\x00\x00\x00\x00\x00\x00W\x00\x00\x00\x00\x00\x00\x00q\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\b\x00\x00\x00\x00\x00\x00\x00X\x00\x00\x00\x00\x00\x00\x00\xc8\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00M\x00\x00\x00\x00\x00\x00\x00 \x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00h\x00\x00\x00\x00\x00\x00\x00m\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00R\x00\x00\x00\x00\x00\x00\x00\xd5\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00V\x00\x00\x00\x00\x00\x00\x00'\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00l\x00\x00\x00\x00\x00\x00\x00}\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00-\x00\x00\x00\x00\x00\x00\x00\xe9\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ad\x00\x00-\x00\x00\x00\t\x02\x00\x00\x00\x10\x00\x00p\x00\x00\x00\x00\x00\x00\x00\xfc\x0f\x00\x00\xd5\x0f\x00\x00\xd4\x0f\x00\x00\xc4\x0f\x00\x00\xb0\x0f\x00\x00\xa6\x0f\x00\x00\x8f\x0f\x00\x00i\x0f\x00\x00Z\x0f\x00\x009\x0f\x00\x00\xdd\x0e\x00\x00\xb4\x0e\x00\x00\xae\x0e\x00\x00\xa2\x0e\x00\x00\x91\x0e\x00\x00w\x0e\x00\x00e\x0e\x00\x00M\x0e\x00\x00:\x0e\x00\x00\xe7\r\x00\x00\xa8\r\x00\x00\x96\r\x00\x00~\r\x00\x00r\r\x00\x00d\r\x00\x00Q\r\x00\x00\xf6\f\x00\x00\xe8\f\x00\x00\xcc\f\x00\x00\xb1\f\x00\x00\x96\f\x00\x00\x82\f\x00\x00Z\f\x00\x008\f\x00\x00.\f\x00\x00\xfa\v\x00\x00\xe2\v\x00\x00\xc9\v\x00\x00\x96\v\x00\x00s\v\x00\x00U\v\x00\x00\x1b\v\x00\x00\xd7\n\x00\x00\xab\n\x00\x00q\n\x00\x00_\n\x00\x00\x1a\n\x00\x00\x05\n\x00\x00\xce\t\x00\x00\xbd\t\x00\x00\xa9\t\x00\x00\x9c\t\x00\x00\x90\t\x00\x00}\t\x00\x00T\t\x00\x007\t\x00\x00\x17\t\x00\x00\xfa\b\x00\x00\xed\b\x00\x00\xec\b\x00\x00\xd9\b\x00\x00\x9e\b\x00\x00S\b\x00\x00\x19\b\x00\x00\xeb\a\x00\x00\xd8\a\x00\x00\xcc\a\x00\x00\xb4\a\x00\x00\x97\a\x00\x00\x96\a\x00\x00]\a\x00\x00A\a\x00\x00\xc1\x06\x00\x00\x90\x06\x00\x00_\x06\x00\x00+\x06\x00\x00\b\x06\x00\x00\xe5\x05\x00\x00\xbe\x05\x00\x00\xbd\x05\x00\x00\xab\x05\x00\x00\x98\x05\x00\x00\x85\x05\x00\x00s\x05\x00\x00\\\x05\x00\x00@\x05\x00\x00+\x05\x00\x00\xda\x04\x00\x00\xcd\x04\x00\x00\xaf\x04\x00\x00\x98\x04\x00\x00\x82\x04\x00\x00[\x04\x00\x00;\x04\x00\x00\x10\x04\x00\x00\xec\x03\x00\x00\xc5\x03\x00\x00\xa5\x03\x00\x00\x86\x03\x00\x00n\x03\x00\x00T\x03\x00\x006\x03\x00\x00\xe5\x02\x00\x00\xcc\x02\x00\x00\xaf\x02\x00\x00\x98\x02\x00\x00\x85\x02\x00\x00q\x02\x00\x00\\\x02\x00\x00B\x02\x00\x00\n\x02\x00\x00\t\x02\x00\x00\b\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00        terminationMessagePolicy: FallbackToLogsOnError\x00            memory: 300Mi\x00            cpu: 10m\x00          requests:\x00        resources:\x00          name: ovn-ca\x00        - mountPath: /ovn-ca\x00          name: ovn-cert\x00        - mountPath: /ovn-cert # not needed, but useful when exec'ing in to pod.\x00          name: env-overrides\x00        - mountPath: /env\x00          name: run-ovn\x00        - mountPath: /run/ovn/\x00          name: run-openvswitch\x00        - mountPath: /run/openvswitch/\x00          name: var-lib-openvswitch\x00        - mountPath: /var/lib/openvswitch/\x00          name: etc-openvswitch\x00        - mountPath: /etc/openvswitch/\x00        volumeMounts:\x00          value: info \x00        - name: OVN_LOG_LEVEL\x00        env:\x00                - OVN_MANAGE_OVSDB=no /usr/share/ovn/scripts/ovn-ctl stop_northd\x00                - -c\x00                - /bin/bash\x00              command:\x00            exec:\x00          preStop:\x00        lifecycle:\x00          wait $!\x00\x00            -C /ovn-ca/ca-bundle.crt &\x00            -c /ovn-cert/tls.crt \\\x00            -p /ovn-cert/tls.key \\\x00            --pidfile /var/run/ovn/ovn-northd.pid \\\x00            --ovnsb-db \"ssl:10.73.116.66:9642\" \\\x00            --ovnnb-db \"ssl:10.73.116.66:9641\" \\\x00            --no-chdir \"-vconsole:${OVN_LOG_LEVEL}\" -vfile:off \"-vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00          exec ovn-northd \\\x00          echo \"$(date -Iseconds) - starting ovn-northd\"\x00\x00          trap quit TERM INT\x00          # end of quit\x00          }\x00            exit 0\x00            rm -f /var/run/ovn/ovn-northd.pid\x00            echo \"$(date -Iseconds) - ovn-northd stopped\"\x00            OVN_MANAGE_OVSDB=no /usr/share/ovn/scripts/ovn-ctl stop_northd\x00            echo \"$(date -Iseconds) - stopping ovn-northd\"\x00          quit() {\x00\x00          fi\x00            set +o allexport\x00            source /env/_master\x00            set -o allexport\x00          if [[ -f /env/_master ]]; then\x00          set -xem\x00        - |\x00        - -c\x00        - /bin/bash\x00        command:\x00        image: \"quay.io/zshi/ovn-daemonset:microshift\"\x00      - name: northd\x00      # ovn-northd: convert network objects in nbdb to flows in sbdb\x00      containers:\x00      # /env -> configmap env-overrides - debug overrides\x00      # /run/openvswitch -> tmpfs - sockets\x00      # /var/lib/openvswitch -> /var/lib/ovn/data - ovsdb pki state\x00      # /etc/openvswitch -> /var/lib/ovn/etc - ovsdb data\x00      # (container) -> (host)\x00      # volumes in all containers:\x00      priorityClassName: \"system-cluster-critical\"\x00      dnsPolicy: Default\x00      hostNetwork: true\x00      serviceAccountName: ovn-kubernetes-controller\x00    spec:\x00        kubernetes.io/os: \"linux\"\x00        openshift.io/component: network\x00        type: infra\x00        component: network\x00        ovn-db-pod: \"true\"\x00        app: ovnkube-master\x00      labels:\x00        target.workload.openshift.io/management: '{\"effect\": \"PreferredDuringScheduling\"}'\x00      annotations:\x00    metadata:\x00  template:\x00      maxUnavailable: 1\x00      maxSurge: 0\x00      # but we don't want that - because ovsdb holds the lock.\x00      # by default, Deployments spin up the new pod before terminating the old one\x00    rollingUpdate:\x00    type: RollingUpdate\x00  updateStrategy:\x00      app: ovnkube-master\x00    matchLabels:\x00  selector:\x00spec:\x00    release.openshift.io/version: \"4.11\"\x00      This daemonset launches the ovn-kubernetes controller (master) networking components.\x00    kubernetes.io/description: |\x00  annotations:\x00  namespace: openshift-ovn-kubernetes\x00  name: ovnkube-master\x00metadata:\x00apiVersion: apps/v1\x00kind: DaemonSet\x00\x00# The ovnkube control-plane components\x00---\x00ad\x00\x00\x17\n\x00\x00\xe7\n\x00\x00\x00\x10\x00\x00-\x00\x00\x00\x00\x00\x00\x00\xd1\x0f\x00\x00\xb5\x0f\x00\x00\xa3\x0f\x00\x00\u007f\x0f\x00\x00a\x0f\x00\x00O\x0f\x00\x00.\x0f\x00\x00\f\x0f\x00\x00\xfa\x0e\x00\x00\xd8\x0e\x00\x00\xba\x0e\x00\x00\xa8\x0e\x00\x00\x83\x0e\x00\x00m\x0e\x00\x00[\x0e\x00\x00>\x0e\x00\x00%\x0e\x00\x00\x13\x0e\x00\x00\xdb\r\x00\x00\xbe\r\x00\x00\xab\r\x00\x00\x8c\r\x00\x00p\r\x00\x00]\r\x00\x00?\r\x00\x00&\r\x00\x00\x11\r\x00\x00\xfe\f\x00\x00\xe7\f\x00\x00\xd0\f\x00\x00\xc0\f\x00\x00\xa1\f\x00\x00{\f\x00\x00k\f\x00\x00=\f\x00\x00$\f\x00\x00\x11\f\x00\x00\xe3\v\x00\x00\xc8\v\x00\x00\x9c\v\x00\x00\x81\v\x00\x00S\v\x00\x008\v\x00\x00\x02\v\x00\x00\xe7\n\x00\x00\xe6\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00        operator: \"Exists\"\x00      - key: \"node.kubernetes.io/network-unavailable\"\x00        operator: \"Exists\"\x00      - key: \"node.kubernetes.io/unreachable\"\x00        operator: \"Exists\"\x00      - key: \"node.kubernetes.io/not-ready\"\x00        operator: \"Exists\"\x00      - key: \"node-role.kubernetes.io/master\"\x00      tolerations:\x00          optional: true\x00          secretName: ovn-master-metrics-cert\x00        secret:\x00      - name: ovn-master-metrics-cert\x00          secretName: ovn-cert\x00        secret:\x00      - name: ovn-cert\x00          name: ovn-ca\x00        configMap:\x00      - name: ovn-ca\x00          optional: true\x00          name: env-overrides\x00        configMap:\x00      - name: env-overrides\x00          name: ovnkube-config\x00        configMap:\x00      - name: ovnkube-config\x00          path: /var/lib/microshift/resources/kubeadmin\x00        hostPath:\x00      - name: kubeconfig\x00          path: /var/run/ovn\x00        hostPath:\x00      - name: run-ovn\x00          path: /var/run/openvswitch\x00        hostPath:\x00      - name: run-openvswitch\x00          path: /var/lib/ovn/data\x00        hostPath:\x00      - name: var-lib-openvswitch\x00          path: /var/lib/ovn/etc\x00        hostPath:\x00      - name: etc-openvswitch\x00          path: /etc/systemd/system\x00        hostPath:\x00      - name: systemd-units\x00      # for checking ovs-configuration service\x00ad\x00\x00\x1a\x00\x00\x00\xd6\x01\x00\x00\x00\x10\x00\x00h\x00\x00\x00\x00\x00\x00\x00\xe9\x0f\x00\x00\xd6\x0f\x00\x00S\x0f\x00\x00B\x0f\x00\x00A\x0f\x00\x004\x0f\x00\x00\x16\x0f\x00\x00\xff\x0e\x00\x00\xd5\x0e\x00\x00\xbd\x0e\x00\x00\xa1\x0e\x00\x00\x8c\x0e\x00\x00v\x0e\x00\x00O\x0e\x00\x009\x0e\x00\x00\x12\x0e\x00\x00\xf2\r\x00\x00\xd3\r\x00\x00\xb3\r\x00\x00\x88\r\x00\x00d\r\x00\x00=\r\x00\x00\x1d\r\x00\x00\xfe\f\x00\x00\xe6\f\x00\x00\xcc\f\x00\x00\xae\f\x00\x00\x8f\f\x00\x00v\f\x00\x00Y\f\x00\x00B\f\x00\x00/\f\x00\x00\x1b\f\x00\x00\x06\f\x00\x00\xec\v\x00\x00\xdd\v\x00\x00\xc2\v\x00\x00\xa4\v\x00\x00\x84\v\x00\x00f\v\x00\x00.\v\x00\x00-\v\x00\x00\xf6\n\x00\x00\xe3\n\x00\x00\xac\n\x00\x00\x9b\n\x00\x00\x87\n\x00\x00z\n\x00\x00n\n\x00\x00\\\n\x00\x003\n\x00\x00\x16\n\x00\x00\xf6\t\x00\x00\xd9\t\x00\x00\xcc\t\x00\x00\xcb\t\x00\x00\xb8\t\x00\x00\x83\t\x00\x00J\t\x00\x00\x16\t\x00\x00\xea\b\x00\x00\xd7\b\x00\x00\xcb\b\x00\x00\xb3\b\x00\x00\x96\b\x00\x00\x95\b\x00\x00D\b\x00\x00C\b\x00\x00\"\b\x00\x00\xe6\a\x00\x00\x84\a\x00\x00j\a\x00\x00A\a\x00\x00\x0e\a\x00\x00\xde\x06\x00\x00\xd1\x06\x00\x00\xbf\x06\x00\x00\xa6\x06\x00\x00v\x06\x00\x00:\x06\x00\x00\x19\x06\x00\x00\xfe\x05\x00\x00\xe4\x05\x00\x00\xc8\x05\x00\x00\x8f\x05\x00\x00\x11\x05\x00\x00\x9c\x04\x00\x00y\x04\x00\x00K\x04\x00\x004\x04\x00\x00%\x04\x00\x00\xf8\x03\x00\x00\xcd\x03\x00\x00b\x03\x00\x00\x10\x03\x00\x00\xb0\x02\x00\x00q\x02\x00\x00Z\x02\x00\x00K\x02\x00\x00\x1e\x02\x00\x00\t\x02\x00\x00\xfd\x01\x00\x00\xd7\x01\x00\x00\xd6\x01\x00\x00\xcb\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00          \x00          # end of db_part_of_cluster\x00          }\x00            return 0\x00            echo \"${pod} is part of cluster\"\x00            fi\x00              return 1\x00              echo \"Unable to check correct target ${target} \"\x00            if [[ \"${target}\" != \"p${transport}:${port}${ovn_raft_conn_ip_url_suffix}\" ]]; then\x00                      --data=bare --no-headings --columns=target list connection)\x00            target=$(ovn-${db}ctl --timeout=5 --db=${transport}:${init_ip}:${port} ${ovndb_ctl_ssl_opts} \\\x00            init_ip=$(bracketify $init_ip)\x00            echo \"Found ${pod} ip: $init_ip\"\x00            fi\x00              return 1\x00              echo \"Unable to get ${pod} ip \"\x00            if [[ $? != 0 ]]; then\x00            init_ip=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} ${pod} -o=jsonpath='{.status.podIP}')\x00            # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed. \x00            echo \"Checking if ${pod} is part of cluster\"\x00            local port=${3}\x00            local db=${2}\x00            local pod=${1}\x00          db_part_of_cluster() {\x00          # checks if a db pod is part of a current cluster\x00          ovn_db_file=\"/etc/ovn/ovn${db}_db.db\"\x00          db_port=\"9642\"\x00          db=\"sb\"\x00          fi\x00            ovn_raft_conn_ip_url_suffix=\":[::]\"\x00          if [[ \"${K8S_NODE_IP}\" == *\":\"* ]]; then\x00          ovn_raft_conn_ip_url_suffix=\"\"\x00          transport=\"ssl\"\x00          ovndb_ctl_ssl_opts=\"-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt\"\x00          ovn_kubernetes_namespace=openshift-ovn-kubernetes\x00          # initialize variables\x00\x00          bracketify() { case \"$1\" in *:*) echo \"[$1]\" ;; *) echo \"$1\" ;; esac }\x00\x00          trap quit TERM INT\x00          # end of quit\x00          }\x00            exit 0\x00            rm -f /var/run/ovn/ovnsb_db.pid\x00            echo \"$(date -Iseconds) - sbdb stopped\"\x00            /usr/share/ovn/scripts/ovn-ctl stop_sb_ovsdb\x00            echo \"$(date -Iseconds) - stopping sbdb\"\x00          quit() {\x00\x00          fi\x00            set +o allexport\x00            source /env/_master\x00            set -o allexport\x00          if [[ -f /env/_master ]]; then\x00          set -xm\x00        - |\x00        - -c\x00        - /bin/bash\x00        command:\x00        image: \"quay.io/zshi/ovn-daemonset:microshift\"\x00      - name: sbdb\x00      # sbdb: The southbound, or flow DB. In raft mode\x00\x00        terminationMessagePolicy: FallbackToLogsOnError\x00          containerPort: 9643\x00        - name: nb-db-raft-port\x00          containerPort: 9641\x00        - name: nb-db-port\x00        ports:\x00            memory: 300Mi\x00            cpu: 10m\x00          requests:\x00        resources:\x00          name: ovn-ca\x00        - mountPath: /ovn-ca\x00          name: ovn-cert\x00        - mountPath: /ovn-cert\x00          name: env-overrides\x00        - mountPath: /env\x00          name: run-ovn\x00        - mountPath: /run/ovn/\x00          name: run-openvswitch\x00        - mountPath: /run/openvswitch/\x00          name: var-lib-openvswitch\x00        - mountPath: /var/lib/openvswitch/\x00          name: etc-openvswitch\x00        - mountPath: /etc/ovn/\x00          name: etc-openvswitch\x00        - mountPath: /etc/openvswitch/\x00        volumeMounts:\x00              fieldPath: status.hostIP\x00            fieldRef:\x00          valueFrom:\x00        - name: K8S_NODE_IP\x00          value: \"5000\"\x00        - name: OVN_NORTHD_PROBE_INTERVAL\x00          value: info \x00        - name: OVN_LOG_LEVEL\x00        env:\x00\x00              fi\x00                /usr/bin/ovn-appctl -t /var/run/ovn/ovnnb_db.ctl --timeout=5 ovsdb-server/memory-trim-on-compaction on 2>/dev/null\x00              else\x00                exit 1\x00ad\x00\x00\x0f\x00\x00\x00\x83\x01\x00\x00\x00\x10\x00\x00V\x00\x00\x00\x00\x00\x00\x00|\x0f\x00\x00]\x0f\x00\x00\\\x0f\x00\x00D\x0f\x00\x003\x0f\x00\x00$\x0f\x00\x00\x15\x0f\x00\x00\xd7\x0e\x00\x00W\x0e\x00\x00<\x0e\x00\x00;\x0e\x00\x00'\x0e\x00\x00\x1a\x0e\x00\x00\a\x0e\x00\x00\xf2\r\x00\x00\xe0\r\x00\x00\xc9\r\x00\x00\xaf\r\x00\x00\x9c\r\x00\x00\x8a\r\x00\x00s\r\x00\x00?\r\x00\x00\x0f\r\x00\x00\xc2\f\x00\x00a\f\x00\x00`\f\x00\x00$\f\x00\x00\b\f\x00\x00\x85\v\x00\x00^\v\x00\x00)\v\x00\x00\xb2\n\x00\x00\x95\n\x00\x00\x80\n\x00\x00f\n\x00\x00O\n\x00\x00N\n\x00\x00\x1e\n\x00\x00\xe0\t\x00\x00\xa2\t\x00\x00_\t\x00\x00\xfd\b\x00\x00\xb2\b\x00\x00\xb1\b\x00\x00W\b\x00\x00A\b\x00\x00\xe4\a\x00\x006\a\x00\x00\x1f\a\x00\x00\xaf\x06\x00\x00d\x06\x00\x00O\x06\x00\x00<\x06\x00\x00)\x06\x00\x00\x17\x06\x00\x00\x00\x06\x00\x00\xe6\x05\x00\x00\xd3\x05\x00\x00\xc1\x05\x00\x00\x88\x05\x00\x00K\x05\x00\x00\x13\x05\x00\x00\xe3\x04\x00\x00\xcb\x04\x00\x00\xaf\x04\x00\x00\x9f\x04\x00\x00\x8a\x04\x00\x00r\x04\x00\x00a\x04\x00\x00Q\x04\x00\x001\x04\x00\x00\x84\x03\x00\x00O\x03\x00\x00\x06\x03\x00\x00\xef\x02\x00\x00\xdc\x02\x00\x00Y\x02\x00\x00H\x02\x00\x00;\x02\x00\x00\x1d\x02\x00\x00\a\x02\x00\x00\xeb\x01\x00\x00\xd6\x01\x00\x00\xc0\x01\x00\x00\x99\x01\x00\x00\x83\x01\x00\x00\x82\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00         volumeMounts:\x00              fieldPath: status.hostIP\x00            fieldRef:\x00          valueFrom:\x00        - name: K8S_NODE_IP\x00          value: info\x00        - name: OVN_LOG_LEVEL\x00        env:\x00              fi\x00                /usr/bin/ovn-appctl -t /var/run/ovn/ovnsb_db.ctl --timeout=5 ovsdb-server/memory-trim-on-compaction on 2>/dev/null\x00              else\x00                exit 1\x00                echo \"SB DB Raft leader is unknown to the cluster node.\"\x00              if [[ ! -z \"${leader_status}\" ]]; then\x00              leader_status=$(/usr/bin/ovn-appctl -t /var/run/ovn/ovnsb_db.ctl --timeout=3 cluster/status OVN_Southbound  2>/dev/null | { grep \"Leader: unknown\" || true; })\x00              set -xeo pipefail\x00            - |\x00            - -c\x00            - /bin/bash\x00            command:\x00          exec:\x00          timeoutSeconds: 5\x00        readinessProbe:\x00                rm -f /var/run/ovn/ovnsb_db.pid\x00                echo \"$(date -Iseconds) - sbdb stopped\"\x00                /usr/share/ovn/scripts/ovn-ctl stop_sb_ovsdb\x00                echo \"$(date -Iseconds) - stopping sbdb\"\x00              - |\x00              - -c\x00              - /bin/bash\x00              command:\x00            exec:\x00          preStop:\x00                fi\x00                  fi\x00                      ovsdb-client -t 30 convert \"$DB_SERVER\" \"$DB_SCHEMA\"\x00                      echo \"Upgrading database $schema_name from schema version $db_version to $target_version\"\x00                  else\x00                      echo \"Database $schema_name has newer schema version ($db_version) than our local schema ($target_version), possibly an upgrade is partially complete?\"\x00                  elif ovsdb-tool compare-versions \"$db_version\" \">\" \"$target_version\"; then\x00                    :\x00                  if ovsdb-tool compare-versions \"$db_version\" == \"$target_version\"; then\x00\x00                  target_version=$(ovsdb-tool schema-version \"$DB_SCHEMA\")\x00                  db_version=$(ovsdb-client -t 10 get-schema-version \"$DB_SERVER\" \"$schema_name\")\x00                  schema_name=$(ovsdb-tool schema-name $DB_SCHEMA)\x00                  DB_SERVER=\"unix:/var/run/ovn/ovnsb_db.sock\"\x00                  DB_SCHEMA=\"/usr/share/ovn/ovn-sb.ovsschema\"\x00                  # Upgrade the db if required.\x00\x00                  done\x00                  sleep 2\x00                  fi\x00                      exit 1\x00                    echo \"$(date -Iseconds) - ERROR RESTARTING - sbdb - too many failed ovn-sbctl attempts, giving up\"\x00                  if [[ \"${retries}\" -gt 40 ]]; then\x00                    (( retries += 1 ))\x00                  while ! ovn-sbctl --no-leader-only -t 5 set-connection pssl:9642 -- set connection . inactivity_probe=180000; do\x00                  retries=0\x00                  # set the connection and inactivity probe\x00\x00                  echo \"$(date -Iseconds) - sdb - postStart - waiting for master to be selected\"\x00                if [[ \"${K8S_NODE_IP}\" == \"${CLUSTER_INITIATOR_IP}\" ]]; then\x00                rm -f /var/run/ovn/ovnsb_db.pid\x00                CLUSTER_INITIATOR_IP=\"10.73.116.66\"\x00                set -x\x00              - |\x00              - -c\x00              - /bin/bash\x00              command:\x00            exec:\x00          postStart:\x00        lifecycle:\x00          fi\x00            wait $!\x00\x00            run_sb_ovsdb &\x00            --ovn-sb-log=\"-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00            exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \\\x00          else\x00            fi\x00              fi\x00                wait $!\x00\x00                run_sb_ovsdb &\x00                --ovn-sb-log=\"-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00ad\x00\x00\x05\x00\x00\x00\xd1\x01\x00\x00\x00\x10\x00\x00l\x00\x00\x00\x00\x00\x00\x00\xd9\x0f\x00\x00\xb9\x0f\x00\x00\x9a\x0f\x00\x00z\x0f\x00\x00O\x0f\x00\x00+\x0f\x00\x00\x04\x0f\x00\x00\xe4\x0e\x00\x00\xc5\x0e\x00\x00\xad\x0e\x00\x00\x93\x0e\x00\x00u\x0e\x00\x00V\x0e\x00\x00=\x0e\x00\x00 \x0e\x00\x00\t\x0e\x00\x00\xfa\r\x00\x00\xdf\r\x00\x00\xc1\r\x00\x00\xa1\r\x00\x00\x83\r\x00\x00p\r\x00\x00\\\r\x00\x00G\r\x00\x00-\r\x00\x00\xf5\f\x00\x00\xf4\f\x00\x00\x9b\f\x00\x00~\f\x00\x00G\f\x00\x006\f\x00\x00\"\f\x00\x00\x15\f\x00\x00\t\f\x00\x00\xf7\v\x00\x00\xcc\v\x00\x00\xaf\v\x00\x00\x8d\v\x00\x00p\v\x00\x00c\v\x00\x00b\v\x00\x00\x13\v\x00\x00\x12\v\x00\x00\xa9\n\x00\x00\x87\n\x00\x00]\n\x00\x00 \n\x00\x00\xfc\t\x00\x00\xcb\t\x00\x00\x94\t\x00\x00o\t\x00\x00K\t\x00\x00\x18\t\x00\x00\xe4\b\x00\x00\xb3\b\x00\x00|\b\x00\x00R\b\x00\x00\x1f\b\x00\x00\xeb\a\x00\x00\xba\a\x00\x00\x83\a\x00\x00Y\a\x00\x008\a\x00\x00\x0e\a\x00\x00\xe4\x06\x00\x00\xce\x06\x00\x00\x9d\x06\x00\x00t\x06\x00\x00V\x06\x00\x00=\x06\x00\x00\x16\x06\x00\x00\xf6\x05\x00\x00\xd7\x05\x00\x00\xb7\x05\x00\x00\x8c\x05\x00\x00h\x05\x00\x00A\x05\x00\x00!\x05\x00\x00\x02\x05\x00\x00\xea\x04\x00\x00\xc0\x04\x00\x00\xa1\x04\x00\x00c\x04\x00\x00H\x04\x00\x00.\x04\x00\x00\x10\x04\x00\x00\xf1\x03\x00\x00\xd8\x03\x00\x00\xbb\x03\x00\x00\xa4\x03\x00\x00\x91\x03\x00\x00}\x03\x00\x00h\x03\x00\x00N\x03\x00\x00A\x03\x00\x00\x1e\x03\x00\x00\t\x03\x00\x00\xf0\x02\x00\x00\xdb\x02\x00\x00\xc5\x02\x00\x00\x9e\x02\x00\x00\x8f\x02\x00\x00r\x02\x00\x00S\x02\x00\x00\x1b\x02\x00\x00\a\x02\x00\x00\xe0\x01\x00\x00\xd1\x01\x00\x00\xd0\x01\x00\x00\x00\x00\x00\x00\x00      volumes:\x00        beta.kubernetes.io/os: \"linux\"\x00      nodeSelector:\x00        terminationMessagePolicy: FallbackToLogsOnError\x00          containerPort: 29102\x00        - name: metrics-port\x00        ports:\x00              fieldPath: spec.nodeName\x00            fieldRef:\x00          valueFrom:\x00        - name: K8S_NODE\x00          value: \"4\"\x00        - name: OVN_KUBE_LOG_LEVEL\x00        env:\x00            memory: 300Mi\x00            cpu: 10m\x00          requests:\x00        resources:\x00          name: ovn-ca\x00        - mountPath: /ovn-ca\x00          name: ovn-cert\x00        - mountPath: /ovn-cert\x00          name: env-overrides\x00        - mountPath: /env\x00          name: kubeconfig\x00        - mountPath: /var/lib/microshift/resources/kubeadmin/\x00          name: ovnkube-config\x00        - mountPath: /run/ovnkube-config/\x00          name: run-ovn\x00        - mountPath: /run/ovn/\x00          name: run-openvswitch\x00        - mountPath: /run/openvswitch/\x00          name: var-lib-openvswitch\x00        - mountPath: /var/lib/openvswitch/\x00          name: etc-openvswitch\x00        - mountPath: /etc/ovn/\x00          name: etc-openvswitch\x00        - mountPath: /etc/openvswitch/\x00          readOnly: true\x00          name: systemd-units\x00        - mountPath: /etc/systemd/system\x00        # for checking ovs-configuration service\x00        volumeMounts:\x00            --acl-logging-rate-limit \"20\"\x00            --disable-snat-multiple-gws \\\x00            --enable-multicast \\\x00            --nb-cert-common-name \"ovn\" \\\x00            --nb-client-cacert /ovn-ca/ca-bundle.crt \\\x00            --nb-client-cert /ovn-cert/tls.crt \\\x00            --nb-client-privkey /ovn-cert/tls.key \\\x00            --nb-address \"ssl:10.73.116.66:9641\" \\\x00            --sb-cert-common-name \"ovn\" \\\x00            --sb-client-cacert /ovn-ca/ca-bundle.crt \\\x00            --sb-client-cert /ovn-cert/tls.crt \\\x00            --sb-client-privkey /ovn-cert/tls.key \\\x00            --sb-address \"ssl:10.73.116.66:9642\" \\\x00            ${gateway_mode_flags} \\\x00            --metrics-enable-pprof \\\x00            --metrics-bind-address \"127.0.0.1:29102\" \\\x00            --loglevel \"${OVN_KUBE_LOG_LEVEL}\" \\\x00            --ovn-empty-lb-events \\\x00            --config-file=/run/ovnkube-config/ovnkube.conf \\\x00            --init-master \"${K8S_NODE}\" \\\x00          exec /usr/bin/ovnkube \\\x00          echo \"I$(date \"+%m%d %H:%M:%S.%N\") - ovnkube-master - start ovnkube --init-master ${K8S_NODE}\"\x00\x00          gateway_mode_flags=\"--gateway-mode shared --gateway-interface br-ex\"\x00\x00          fi\x00            set +o allexport\x00            source \"/env/_master\"\x00            set -o allexport\x00          if [[ -f \"/env/_master\" ]]; then\x00          set -xe\x00        - |\x00        - -c\x00        - /bin/bash\x00        command:\x00        image: \"quay.io/zshi/ovn-daemonset:microshift\"\x00      - name: ovnkube-master\x00      # ovnkube master: convert kubernetes objects in to nbdb logical network components\x00\x00        terminationMessagePolicy: FallbackToLogsOnError\x00            memory: 300Mi\x00            cpu: 10m\x00          requests:\x00        resources:\x00          containerPort: 9644\x00        - name: sb-db-raft-port\x00          containerPort: 9642\x00        - name: sb-db-port\x00        ports:\x00          name: ovn-ca\x00        - mountPath: /ovn-ca\x00          name: ovn-cert\x00        - mountPath: /ovn-cert\x00          name: env-overrides\x00        - mountPath: /env\x00          name: run-ovn\x00        - mountPath: /run/ovn/\x00          name: run-openvswitch\x00        - mountPath: /run/openvswitch/\x00          name: var-lib-openvswitch\x00        - mountPath: /var/lib/openvswitch/\x00          name: etc-openvswitch\x00        - mountPath: /etc/ovn/\x00          name: etc-openvswitch\x00        - mountPath: /etc/openvswitch/\x00ad\x00\x00'\x00\x00\x00\x9f\x01\x00\x00\x00\x10\x00\x00W\x00\x00\x00\x00\x00\x00\x00\xb6\x0f\x00\x00\xa3\x0f\x00\x00l\x0f\x00\x00[\x0f\x00\x00G\x0f\x00\x00:\x0f\x00\x00.\x0f\x00\x00\x1b\x0f\x00\x00\xf2\x0e\x00\x00\xd5\x0e\x00\x00\xb5\x0e\x00\x00\x98\x0e\x00\x00\x8b\x0e\x00\x00\x8a\x0e\x00\x00w\x0e\x00\x00B\x0e\x00\x00\t\x0e\x00\x00\xd5\r\x00\x00\xa9\r\x00\x00\x96\r\x00\x00\x8a\r\x00\x00r\r\x00\x00U\r\x00\x00T\r\x00\x00\x03\r\x00\x00\xe2\f\x00\x00\xa6\f\x00\x00D\f\x00\x00*\f\x00\x00\x01\f\x00\x00\xce\v\x00\x00\x9e\v\x00\x00\x91\v\x00\x00\u007f\v\x00\x00f\v\x00\x006\v\x00\x00\xfa\n\x00\x00\xd9\n\x00\x00\xbe\n\x00\x00\xa4\n\x00\x00\x88\n\x00\x00O\n\x00\x00\xd1\t\x00\x00\\\t\x00\x009\t\x00\x00\v\t\x00\x00\xf4\b\x00\x00\xe5\b\x00\x00\xb8\b\x00\x00\x8d\b\x00\x00\"\b\x00\x00\xd0\a\x00\x00p\a\x00\x001\a\x00\x00\x1a\a\x00\x00\v\a\x00\x00\xde\x06\x00\x00\xc9\x06\x00\x00\xbd\x06\x00\x00\x97\x06\x00\x00\x8c\x06\x00\x00P\x06\x00\x00\x03\x06\x00\x00\xe6\x05\x00\x00\xcc\x05\x00\x00\xb0\x05\x00\x002\x05\x00\x00\x86\x04\x00\x00\x85\x04\x00\x00^\x04\x00\x00\"\x04\x00\x00\xd1\x03\x00\x00\xb8\x03\x00\x00\xa7\x03\x00\x00\x96\x03\x00\x00K\x03\x00\x00\x13\x03\x00\x00\xfe\x02\x00\x00\xf2\x02\x00\x00\xce\x02\x00\x00\xcd\x02\x00\x00\x97\x02\x00\x00Q\x02\x00\x006\x02\x00\x00\b\x02\x00\x00\xd4\x01\x00\x00\x9f\x01\x00\x00\x9e\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00            --ovn-nb-db-ssl-cert=/ovn-cert/tls.crt \\\x00            --ovn-nb-db-ssl-key=/ovn-cert/tls.key \\\x00            --db-nb-cluster-local-proto=ssl \\\x00            --no-monitor \\\x00            --db-nb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \\\x00          OVN_ARGS=\"--db-nb-cluster-local-port=9644 \\\x00\x00          # end of cluster_exists()\x00          }\x00            return 1\x00            init_ip=$(bracketify $CLUSTER_INITIATOR_IP)\x00            # if we get here  there is no cluster, set init_ip and get out\x00            done\x00              fi\x00                return 0\x00                echo \"${db_pod} is part of current cluster with ip: ${init_ip}!\"\x00              if db_part_of_cluster $db_pod $db $port; then\x00            for db_pod in $db_pods; do\x00\x00            db_pods=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} -o=jsonpath='{.items[*].metadata.name}' | egrep -o 'ovnkube-master-\\w+' | grep -v \"metrics\")\x00            # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed. \x00            local port=${2}\x00            local db=${1}\x00          cluster_exists() {\x00          # If not it returns false and sets init_ip to CLUSTER_INITIATOR_IP\x00          # Checks if cluster has already been initialized.\x00          \x00          # end of db_part_of_cluster\x00          }\x00            return 0\x00            echo \"${pod} is part of cluster\"\x00            fi\x00              return 1\x00              echo \"Unable to check correct target ${target} \"\x00            if [[ \"${target}\" != \"p${transport}:${port}${ovn_raft_conn_ip_url_suffix}\" ]]; then\x00                      --data=bare --no-headings --columns=target list connection)\x00            target=$(ovn-${db}ctl --timeout=5 --db=${transport}:${init_ip}:${port} ${ovndb_ctl_ssl_opts} \\\x00            init_ip=$(bracketify $init_ip)\x00            echo \"Found ${pod} ip: $init_ip\"\x00            fi\x00              return 1\x00              echo \"Unable to get ${pod} ip \"\x00            if [[ $? != 0 ]]; then\x00            init_ip=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} ${pod} -o=jsonpath='{.status.podIP}')\x00            # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed. \x00            echo \"Checking if ${pod} is part of cluster\"\x00            local port=${3}\x00            local db=${2}\x00            local pod=${1}\x00          db_part_of_cluster() {\x00          # checks if a db pod is part of a current cluster\x00          ovn_db_file=\"/etc/ovn/ovn${db}_db.db\"\x00          db_port=\"9641\"\x00          db=\"nb\"\x00          fi\x00            ovn_raft_conn_ip_url_suffix=\":[::]\"\x00          if [[ \"${K8S_NODE_IP}\" == *\":\"* ]]; then\x00          ovn_raft_conn_ip_url_suffix=\"\"\x00          transport=\"ssl\"\x00          ovndb_ctl_ssl_opts=\"-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt\"\x00          ovn_kubernetes_namespace=openshift-ovn-kubernetes\x00          # initialize variables\x00          bracketify() { case \"$1\" in *:*) echo \"[$1]\" ;; *) echo \"$1\" ;; esac }\x00\x00          trap quit TERM INT\x00          # end of quit\x00          }\x00            exit 0\x00            rm -f /var/run/ovn/ovnnb_db.pid\x00            echo \"$(date -Iseconds) - nbdb stopped\"\x00            /usr/share/ovn/scripts/ovn-ctl stop_nb_ovsdb\x00            echo \"$(date -Iseconds) - stopping nbdb\"\x00          quit() {\x00\x00          fi\x00            set +o allexport\x00            source /env/_master\x00            set -o allexport\x00          if [[ -f /env/_master ]]; then\x00          set -xem\x00        - |\x00        - -c\x00        - /bin/bash\x00        command:\x00        image: \"quay.io/zshi/ovn-daemonset:microshift\"\x00      - name: nbdb\x00      # nbdb: the northbound, or logical network object DB. In raft mode \x00ad\x00\x00\r\x00\x00\x00\x89\x01\x00\x00\x00\x10\x00\x00X\x00\x00\x00\x00\x00\x00\x00\xc5\x0f\x00\x00\xc4\x0f\x00\x00\x96\x0f\x00\x00\x19\x0f\x00\x00\xf6\x0e\x00\x00\xd9\x0e\x00\x00\xce\x0e\x00\x00\xa1\x0e\x00\x00\x83\x0e\x00\x00v\x0e\x00\x00u\x0e\x00\x00B\x0e\x00\x00\xf0\r\x00\x00\xda\r\x00\x00\xba\r\x00\x00\x91\r\x00\x00Z\r\x00\x007\r\x00\x00!\r\x00\x00\x10\r\x00\x00\xfa\f\x00\x00\xd5\f\x00\x00\xc4\f\x00\x00\xc3\f\x00\x00\x9d\f\x00\x00c\f\x00\x00;\f\x00\x00\x15\f\x00\x00\xd5\v\x00\x00\xa4\v\x00\x00m\v\x00\x00<\v\x00\x00\xba\n\x00\x00\x9d\n\x00\x00\x9c\n\x00\x00\x86\n\x00\x00u\n\x00\x00\x1a\n\x00\x00\xcf\t\x00\x00\x80\t\x00\x00`\t\x00\x00\xee\b\x00\x00\xa7\b\x00\x00\x94\b\x00\x00\x93\b\x00\x00Q\b\x00\x00\xcd\a\x00\x00\xa9\a\x00\x00\x8a\a\x00\x00\x89\a\x00\x00q\a\x00\x00^\a\x00\x00\x13\a\x00\x00\xd1\x06\x00\x00\x9e\x06\x00\x00e\x06\x00\x002\x06\x00\x00\xae\x05\x00\x00\x8f\x05\x00\x00\x8e\x05\x00\x00v\x05\x00\x00e\x05\x00\x00V\x05\x00\x00G\x05\x00\x00\t\x05\x00\x00\x87\x04\x00\x00j\x04\x00\x00i\x04\x00\x00S\x04\x00\x00F\x04\x00\x00E\x04\x00\x002\x04\x00\x00\x1d\x04\x00\x00\v\x04\x00\x00\xf4\x03\x00\x00\xda\x03\x00\x00\xc7\x03\x00\x00\xb5\x03\x00\x00\x9e\x03\x00\x00j\x03\x00\x00:\x03\x00\x00\xed\x02\x00\x00\x8b\x02\x00\x00\x8a\x02\x00\x00N\x02\x00\x002\x02\x00\x00\xb0\x01\x00\x00\x89\x01\x00\x00\x88\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00                    (( retries += 1 ))\x00                  while ! ovn-nbctl --no-leader-only -t 5 set-connection pssl:9641 -- set connection . inactivity_probe=60000; do\x00                  retries=0\x00                  # set the connection and inactivity probe\x00\x00                  echo \"$(date -Iseconds) - nbdb - postStart - waiting for master to be selected\"\x00                if [[ \"${K8S_NODE_IP}\" == \"${CLUSTER_INITIATOR_IP}\" ]]; then\x00                rm -f /var/run/ovn/ovnnb_db.pid\x00                CLUSTER_INITIATOR_IP=\"10.73.116.66\"\x00                set -x\x00              - |\x00              - -c\x00              - /bin/bash\x00              command:\x00            exec:\x00          postStart:\x00        lifecycle:\x00\x00          fi\x00              wait $!\x00\x00              run_nb_ovsdb &\x00              --ovn-nb-log=\"-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00            exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \\\x00          else\x00            fi\x00              fi\x00                wait $!\x00\x00                run_nb_ovsdb &\x00                --ovn-nb-log=\"-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00                --db-nb-cluster-remote-proto=ssl \\\x00                --db-nb-cluster-remote-addr=${init_ip} \\\x00                --db-nb-cluster-remote-port=9643 \\\x00                exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \\\x00                echo \"Joining the nbdb cluster with init_ip=${init_ip}...\"\x00              else\x00                wait $!\x00\x00                run_nb_ovsdb &\x00                ${election_timer} \\\x00                --ovn-nb-log=\"-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00                exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \\\x00\x00                fi\x00                  election_timer=\"--db-nb-election-timer=$((10*1000))\"\x00                if test -n \"$(/usr/share/ovn/scripts/ovn-ctl --help 2>&1 | grep \"\\--db-nb-election-timer\")\"; then\x00                election_timer=\x00                # set DB election timer at DB creation time if OVN supports it\x00              if [[ \"${K8S_NODE_IP}\" == \"${CLUSTER_INITIATOR_IP}\" ]]; then\x00              # either we need to initialize a new cluster or wait for master to create it\x00            else\x00              wait $!\x00\x00              run_nb_ovsdb &\x00              --ovn-nb-log=\"-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00              --db-nb-cluster-remote-proto=ssl \\\x00              --db-nb-cluster-remote-addr=${init_ip} \\\x00              --db-nb-cluster-remote-port=9643 \\\x00              exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \\\x00              # join existing cluster\x00              initial_raft_create=false\x00              echo \"Cluster already exists for DB: ${db}\"\x00            if ${cluster_found}; then\x00\x00            done\x00              counter=$((counter+1))\x00              sleep 1\x00              fi\x00                break\x00                cluster_found=true\x00              if cluster_exists ${db} ${db_port}; then\x00            while [ $counter -lt 5 ]; do\x00            cluster_found=false\x00            counter=0\x00            # check to see if a cluster already exists. If it does, just join it.\x00          if [[ \"${initialize}\" == \"true\" ]]; then\x00\x00          fi\x00            initialize=\"true\"\x00          if [[ ! -e ${ovn_db_file} ]]; then\x00          \x00          initialize=\"false\"\x00          initial_raft_create=true\x00          echo \"$(date -Iseconds) - starting nbdb  CLUSTER_INITIATOR_IP=${CLUSTER_INITIATOR_IP}, K8S_NODE_IP=${K8S_NODE_IP}\"\x00          CLUSTER_INITIATOR_IP=\"10.73.116.66\"\x00\x00            --ovn-nb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt\"\x00ad\x00\x00\v\x00\x00\x00[\x01\x00\x00\x00\x10\x00\x00M\x00\x00\x00\x00\x00\x00\x00\xcb\x0f\x00\x00T\x0f\x00\x007\x0f\x00\x00\"\x0f\x00\x00\b\x0f\x00\x00\xf1\x0e\x00\x00\xf0\x0e\x00\x00\xc0\x0e\x00\x00\x82\x0e\x00\x00D\x0e\x00\x00\x01\x0e\x00\x00\x9f\r\x00\x00T\r\x00\x00S\r\x00\x00\xf9\f\x00\x00\xe3\f\x00\x00\x86\f\x00\x00\xd8\v\x00\x00\xc1\v\x00\x00Q\v\x00\x00\x06\v\x00\x00\xf1\n\x00\x00\xde\n\x00\x00\xad\n\x00\x00B\n\x00\x00\b\n\x00\x00\xbe\t\x00\x00j\t\x00\x00P\t\x00\x00'\t\x00\x00\xf3\b\x00\x00\u007f\b\x00\x00V\b\x00\x00\xfc\a\x00\x00\xe2\a\x00\x00\xcb\a\x00\x00\xaf\a\x00\x00\x88\a\x00\x00s\a\x00\x00^\a\x00\x00]\a\x00\x00\x04\a\x00\x00\xe8\x06\x00\x00\xb2\x06\x00\x00I\x06\x00\x00\x1e\x06\x00\x00\xb2\x05\x00\x00\x94\x05\x00\x00k\x05\x00\x00R\x05\x00\x00\xef\x04\x00\x00\xd3\x04\x00\x00\xbc\x04\x00\x00\xa5\x04\x00\x00\x92\x04\x00\x00\x91\x04\x00\x00~\x04\x00\x00l\x04\x00\x00U\x04\x00\x00;\x04\x00\x00(\x04\x00\x00\x16\x04\x00\x00\xdd\x03\x00\x00\xa0\x03\x00\x00h\x03\x00\x008\x03\x00\x00 \x03\x00\x00\x04\x03\x00\x00\xf4\x02\x00\x00\xdf\x02\x00\x00\xc7\x02\x00\x00\xb6\x02\x00\x00\xa6\x02\x00\x00\x86\x02\x00\x00\xd9\x01\x00\x00\xa4\x01\x00\x00[\x01\x00\x00Z\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00                echo \"NB DB Raft leader is unknown to the cluster node.\"\x00              if [[ ! -z \"${leader_status}\" ]]; then\x00              leader_status=$(/usr/bin/ovn-appctl -t /var/run/ovn/ovnnb_db.ctl --timeout=3 cluster/status OVN_Northbound  2>/dev/null | { grep \"Leader: unknown\" || true; })\x00              set -xeo pipefail\x00            - |\x00            - -c\x00            - /bin/bash\x00            command:\x00          exec:\x00          timeoutSeconds: 5\x00        readinessProbe:\x00                rm -f /var/run/ovn/ovnnb_db.pid\x00                echo \"$(date -Iseconds) - nbdb stopped\"\x00                /usr/share/ovn/scripts/ovn-ctl stop_nb_ovsdb\x00                echo \"$(date -Iseconds) - stopping nbdb\"\x00              - |\x00              - -c\x00              - /bin/bash\x00              command:\x00            exec:\x00          preStop:\x00\x00                fi\x00                  done\x00                    fi\x00                      break\x00                      echo \"Successfully set northd probe interval to ${northd_probe_interval} ms\"\x00                    else\x00                      (( retries += 1 ))\x00                      sleep 2\x00                      echo \"Failed to set northd probe interval to ${northd_probe_interval}. retrying.....\"\x00                    if [[ $? != 0 ]]; then\x00                    ${OVN_NB_CTL} set NB_GLOBAL . options:northd_probe_interval=${northd_probe_interval}\x00                  while [[ \"${retries}\" -lt 10 ]]; do\x00                  retries=0\x00                if [[ \"${current_probe_interval}\" != \"${northd_probe_interval}\" ]]; then\x00\x00                done\x00                  fi\x00                    (( retries += 1 ))\x00                    sleep 2\x00                  else\x00                    break\x00                    current_probe_interval=$(echo ${current_probe_interval} | tr -d '\\\"')\x00                  if [[ $? == 0 ]]; then\x00                  current_probe_interval=$(${OVN_NB_CTL} --if-exists get NB_GLOBAL . options:northd_probe_interval)\x00                while [[ \"${retries}\" -lt 10 ]]; do\x00                current_probe_interval=0\x00                retries=0\x00                echo \"Setting northd probe interval to ${northd_probe_interval} ms\"\x00                northd_probe_interval=${OVN_NORTHD_PROBE_INTERVAL:-10000}\x00                            --db \"ssl:10.73.116.66:9641\"\"\x00                OVN_NB_CTL=\"ovn-nbctl -p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt \\\x00                #configure northd_probe_interval\x00                fi\x00                  fi\x00                      ovsdb-client -t 30 convert \"$DB_SERVER\" \"$DB_SCHEMA\"\x00                      echo \"Upgrading database $schema_name from schema version $db_version to $target_version\"\x00                  else\x00                      echo \"Database $schema_name has newer schema version ($db_version) than our local schema ($target_version), possibly an upgrade is partially complete?\"\x00                  elif ovsdb-tool compare-versions \"$db_version\" \">\" \"$target_version\"; then\x00                    :\x00                  if ovsdb-tool compare-versions \"$db_version\" == \"$target_version\"; then\x00\x00                  target_version=$(ovsdb-tool schema-version \"$DB_SCHEMA\")\x00                  db_version=$(ovsdb-client -t 10 get-schema-version \"$DB_SERVER\" \"$schema_name\")\x00                  schema_name=$(ovsdb-tool schema-name $DB_SCHEMA)\x00                  DB_SERVER=\"unix:/var/run/ovn/ovnnb_db.sock\"\x00                  DB_SCHEMA=\"/usr/share/ovn/ovn-nb.ovsschema\"\x00                  # Upgrade the db if required.\x00\x00                  done\x00                  sleep 2\x00                  fi\x00                      exit 1\x00                    echo \"$(date -Iseconds) - ERROR RESTARTING - nbdb - too many failed ovn-nbctl attempts, giving up\"\x00                  if [[ \"${retries}\" -gt 40 ]]; then\x00ad\x00\x00R\x00\x00\x00\xb6\x01\x00\x00\x00\x10\x00\x00R\x00\x00\x00\x00\x00\x00\x00\xc4\x0f\x00\x00w\x0f\x00\x00Z\x0f\x00\x00@\x0f\x00\x00$\x0f\x00\x00\xa6\x0e\x00\x00\xfa\r\x00\x00\xf9\r\x00\x00\xd2\r\x00\x00\x96\r\x00\x00E\r\x00\x00,\r\x00\x00\x1b\r\x00\x00\n\r\x00\x00\xbf\f\x00\x00\x87\f\x00\x00r\f\x00\x00f\f\x00\x00B\f\x00\x00A\f\x00\x00\v\f\x00\x00\xc5\v\x00\x00\xaa\v\x00\x00|\v\x00\x00H\v\x00\x00\x13\v\x00\x00\xd8\n\x00\x00\xd7\n\x00\x00\xa9\n\x00\x00H\n\x00\x00%\n\x00\x00\b\n\x00\x00\a\n\x00\x00\xda\t\x00\x00\xbc\t\x00\x00\xaf\t\x00\x00\xae\t\x00\x00{\t\x00\x00)\t\x00\x00\x13\t\x00\x00\xf3\b\x00\x00\xca\b\x00\x00\x93\b\x00\x00p\b\x00\x00Z\b\x00\x00I\b\x00\x003\b\x00\x00\x0e\b\x00\x00\xfd\a\x00\x00\xfc\a\x00\x00\xd6\a\x00\x00\x9c\a\x00\x00t\a\x00\x00N\a\x00\x00\x0e\a\x00\x00\xdd\x06\x00\x00\xa6\x06\x00\x00u\x06\x00\x00\xf3\x05\x00\x00\xd6\x05\x00\x00\xd5\x05\x00\x00\xbf\x05\x00\x00\xae\x05\x00\x00S\x05\x00\x00\b\x05\x00\x00\xb9\x04\x00\x00\x99\x04\x00\x00'\x04\x00\x00\xe0\x03\x00\x00\xcd\x03\x00\x00\xcc\x03\x00\x00\x8a\x03\x00\x00\x06\x03\x00\x00\xe2\x02\x00\x00\xc3\x02\x00\x00\xc2\x02\x00\x00\xaa\x02\x00\x00\x97\x02\x00\x00U\x02\x00\x00\"\x02\x00\x00\xe9\x01\x00\x00\xb6\x01\x00\x00\xab\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00                          --db-sb-cluster-remote-proto=ssl \\\x00                --db-sb-cluster-remote-addr=${init_ip} \\\x00                --db-sb-cluster-remote-port=9644 \\\x00                exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \\\x00              else\x00                wait $!\x00\x00                run_sb_ovsdb &\x00                ${election_timer} \\\x00                --ovn-sb-log=\"-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00                exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \\\x00\x00                fi\x00                  election_timer=\"--db-sb-election-timer=$((16*1000))\"\x00                if test -n \"$(/usr/share/ovn/scripts/ovn-ctl --help 2>&1 | grep \"\\--db-sb-election-timer\")\"; then\x00                election_timer=\x00                # set DB election timer at DB creation time if OVN supports it\x00              if [[ \"${K8S_NODE_IP}\" == \"${CLUSTER_INITIATOR_IP}\" ]]; then\x00              # either we need to initialize a new cluster or wait for master to create it\x00            else\x00              wait $!\x00\x00              run_sb_ovsdb &\x00              --ovn-sb-log=\"-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m\" \\\x00              --db-sb-cluster-remote-proto=ssl \\\x00              --db-sb-cluster-remote-addr=${init_ip} \\\x00              --db-sb-cluster-remote-port=9644 \\\x00              exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \\\x00              # join existing cluster\x00              initial_raft_create=false\x00              echo \"Cluster already exists for DB: ${db}\"\x00            if ${cluster_found}; then\x00\x00            done\x00              counter=$((counter+1))\x00              sleep 1\x00              fi\x00                break\x00                cluster_found=true\x00              if cluster_exists ${db} ${db_port}; then\x00            while [ $counter -lt 5 ]; do\x00            cluster_found=false\x00            counter=0\x00            # check to see if a cluster already exists. If it does, just join it.\x00          if [[ \"${initialize}\" == \"true\" ]]; then\x00\x00          fi\x00            initialize=\"true\"\x00          if [[ ! -e ${ovn_db_file} ]]; then\x00\x00          initialize=\"false\"\x00          initial_raft_create=true\x00          echo \"$(date -Iseconds) - starting sbdb  CLUSTER_INITIATOR_IP=${CLUSTER_INITIATOR_IP}\"\x00          CLUSTER_INITIATOR_IP=\"10.73.116.66\"\x00\x00            --ovn-sb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt\"\x00            --ovn-sb-db-ssl-cert=/ovn-cert/tls.crt \\\x00            --ovn-sb-db-ssl-key=/ovn-cert/tls.key \\\x00            --db-sb-cluster-local-proto=ssl \\\x00            --no-monitor \\\x00            --db-sb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \\\x00          OVN_ARGS=\"--db-sb-cluster-local-port=9644 \\\x00\x00          # end of cluster_exists()\x00          }\x00            return 1\x00            init_ip=$(bracketify $CLUSTER_INITIATOR_IP)\x00            # if we get here  there is no cluster, set init_ip and get out\x00            done\x00              fi\x00                return 0\x00                echo \"${db_pod} is part of current cluster with ip: ${init_ip}!\"\x00              if db_part_of_cluster $db_pod $db $port; then\x00            for db_pod in $db_pods; do\x00\x00            db_pods=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} -o=jsonpath='{.items[*].metadata.name}' | egrep -o 'ovnkube-master-\\w+' | grep -v \"metrics\")\x00            # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed. \x00            local port=${2}\x00            local db=${1}\x00          cluster_exists() {\x00          # If not it returns false and sets init_ip to CLUSTER_INITIATOR_IP\x00          # Checks if cluster has already been initialized.\x00")

func assetsComponentsOvnMasterDaemonsetYamlSwpBytes() ([]byte, error) {
	return _assetsComponentsOvnMasterDaemonsetYamlSwp, nil
}

func assetsComponentsOvnMasterDaemonsetYamlSwp() (*asset, error) {
	bytes, err := assetsComponentsOvnMasterDaemonsetYamlSwpBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/master/.daemonset.yaml.swp", size: 45056, mode: os.FileMode(420), modTime: time.Unix(1653814560, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnMasterDaemonsetYaml = []byte(`---
# The ovnkube control-plane components

kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: ovnkube-master
  namespace: openshift-ovn-kubernetes
  annotations:
    kubernetes.io/description: |
      This daemonset launches the ovn-kubernetes controller (master) networking components.
    release.openshift.io/version: "4.11"
spec:
  selector:
    matchLabels:
      app: ovnkube-master
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      # by default, Deployments spin up the new pod before terminating the old one
      # but we don't want that - because ovsdb holds the lock.
      maxSurge: 0
      maxUnavailable: 1
  template:
    metadata:
      annotations:
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
      labels:
        app: ovnkube-master
        ovn-db-pod: "true"
        component: network
        type: infra
        openshift.io/component: network
        kubernetes.io/os: "linux"
    spec:
      serviceAccountName: ovn-kubernetes-controller
      hostNetwork: true
      dnsPolicy: Default
      priorityClassName: "system-cluster-critical"
      # volumes in all containers:
      # (container) -> (host)
      # /etc/openvswitch -> /var/lib/ovn/etc - ovsdb data
      # /var/lib/openvswitch -> /var/lib/ovn/data - ovsdb pki state
      # /run/openvswitch -> tmpfs - sockets
      # /env -> configmap env-overrides - debug overrides
      containers:
      # ovn-northd: convert network objects in nbdb to flows in sbdb
      - name: northd
        image: "quay.io/zshi/ovn-daemonset:microshift"
        command:
        - /bin/bash
        - -c
        - |
          set -xem
          if [[ -f /env/_master ]]; then
            set -o allexport
            source /env/_master
            set +o allexport
          fi

          quit() {
            echo "$(date -Iseconds) - stopping ovn-northd"
            OVN_MANAGE_OVSDB=no /usr/share/ovn/scripts/ovn-ctl stop_northd
            echo "$(date -Iseconds) - ovn-northd stopped"
            rm -f /var/run/ovn/ovn-northd.pid
            exit 0
          }
          # end of quit
          trap quit TERM INT

          echo "$(date -Iseconds) - starting ovn-northd"
          exec ovn-northd \
            --no-chdir "-vconsole:${OVN_LOG_LEVEL}" -vfile:off "-vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
            --ovnnb-db "ssl:10.73.116.66:9641" \
            --ovnsb-db "ssl:10.73.116.66:9642" \
            --pidfile /var/run/ovn/ovn-northd.pid \
            -p /ovn-cert/tls.key \
            -c /ovn-cert/tls.crt \
            -C /ovn-ca/ca-bundle.crt &

          wait $!
        lifecycle:
          preStop:
            exec:
              command:
                - /bin/bash
                - -c
                - OVN_MANAGE_OVSDB=no /usr/share/ovn/scripts/ovn-ctl stop_northd
        env:
        - name: OVN_LOG_LEVEL
          value: info 
        volumeMounts:
        - mountPath: /etc/openvswitch/
          name: etc-openvswitch
        - mountPath: /var/lib/openvswitch/
          name: var-lib-openvswitch
        - mountPath: /run/openvswitch/
          name: run-openvswitch
        - mountPath: /run/ovn/
          name: run-ovn
        - mountPath: /env
          name: env-overrides
        - mountPath: /ovn-cert # not needed, but useful when exec'ing in to pod.
          name: ovn-cert
        - mountPath: /ovn-ca
          name: ovn-ca
        resources:
          requests:
            cpu: 10m
            memory: 300Mi
        terminationMessagePolicy: FallbackToLogsOnError

      # nbdb: the northbound, or logical network object DB. In raft mode 
      - name: nbdb
        image: "quay.io/zshi/ovn-daemonset:microshift"
        command:
        - /bin/bash
        - -c
        - |
          set -xem
          if [[ -f /env/_master ]]; then
            set -o allexport
            source /env/_master
            set +o allexport
          fi

          quit() {
            echo "$(date -Iseconds) - stopping nbdb"
            /usr/share/ovn/scripts/ovn-ctl stop_nb_ovsdb
            echo "$(date -Iseconds) - nbdb stopped"
            rm -f /var/run/ovn/ovnnb_db.pid
            exit 0
          }
          # end of quit
          trap quit TERM INT

          bracketify() { case "$1" in *:*) echo "[$1]" ;; *) echo "$1" ;; esac }
          # initialize variables
          ovn_kubernetes_namespace=openshift-ovn-kubernetes
          ovndb_ctl_ssl_opts="-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt"
          transport="ssl"
          ovn_raft_conn_ip_url_suffix=""
          if [[ "${K8S_NODE_IP}" == *":"* ]]; then
            ovn_raft_conn_ip_url_suffix=":[::]"
          fi
          db="nb"
          db_port="9641"
          ovn_db_file="/etc/ovn/ovn${db}_db.db"
          # checks if a db pod is part of a current cluster
          db_part_of_cluster() {
            local pod=${1}
            local db=${2}
            local port=${3}
            echo "Checking if ${pod} is part of cluster"
            # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed. 
            init_ip=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} ${pod} -o=jsonpath='{.status.podIP}')
            if [[ $? != 0 ]]; then
              echo "Unable to get ${pod} ip "
              return 1
            fi
            echo "Found ${pod} ip: $init_ip"
            init_ip=$(bracketify $init_ip)
            target=$(ovn-${db}ctl --timeout=5 --db=${transport}:${init_ip}:${port} ${ovndb_ctl_ssl_opts} \
                      --data=bare --no-headings --columns=target list connection)
            if [[ "${target}" != "p${transport}:${port}${ovn_raft_conn_ip_url_suffix}" ]]; then
              echo "Unable to check correct target ${target} "
              return 1
            fi
            echo "${pod} is part of cluster"
            return 0
          }
          # end of db_part_of_cluster
          
          # Checks if cluster has already been initialized.
          # If not it returns false and sets init_ip to CLUSTER_INITIATOR_IP
          cluster_exists() {
            local db=${1}
            local port=${2}
            # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed. 
            db_pods=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} -o=jsonpath='{.items[*].metadata.name}' | egrep -o 'ovnkube-master-\w+' | grep -v "metrics")

            for db_pod in $db_pods; do
              if db_part_of_cluster $db_pod $db $port; then
                echo "${db_pod} is part of current cluster with ip: ${init_ip}!"
                return 0
              fi
            done
            # if we get here  there is no cluster, set init_ip and get out
            init_ip=$(bracketify $CLUSTER_INITIATOR_IP)
            return 1
          }
          # end of cluster_exists()

          OVN_ARGS="--db-nb-cluster-local-port=9644 \
            --db-nb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
            --no-monitor \
            --db-nb-cluster-local-proto=ssl \
            --ovn-nb-db-ssl-key=/ovn-cert/tls.key \
            --ovn-nb-db-ssl-cert=/ovn-cert/tls.crt \
            --ovn-nb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt"

          CLUSTER_INITIATOR_IP="10.73.116.66"
          echo "$(date -Iseconds) - starting nbdb  CLUSTER_INITIATOR_IP=${CLUSTER_INITIATOR_IP}, K8S_NODE_IP=${K8S_NODE_IP}"
          initial_raft_create=true
          initialize="false"
          
          if [[ ! -e ${ovn_db_file} ]]; then
            initialize="true"
          fi

          if [[ "${initialize}" == "true" ]]; then
            # check to see if a cluster already exists. If it does, just join it.
            counter=0
            cluster_found=false
            while [ $counter -lt 5 ]; do
              if cluster_exists ${db} ${db_port}; then
                cluster_found=true
                break
              fi
              sleep 1
              counter=$((counter+1))
            done

            if ${cluster_found}; then
              echo "Cluster already exists for DB: ${db}"
              initial_raft_create=false
              # join existing cluster
              exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \
              --db-nb-cluster-remote-port=9643 \
              --db-nb-cluster-remote-addr=${init_ip} \
              --db-nb-cluster-remote-proto=ssl \
              --ovn-nb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
              run_nb_ovsdb &

              wait $!
            else
              # either we need to initialize a new cluster or wait for master to create it
              if [[ "${K8S_NODE_IP}" == "${CLUSTER_INITIATOR_IP}" ]]; then
                # set DB election timer at DB creation time if OVN supports it
                election_timer=
                if test -n "$(/usr/share/ovn/scripts/ovn-ctl --help 2>&1 | grep "\--db-nb-election-timer")"; then
                  election_timer="--db-nb-election-timer=$((10*1000))"
                fi

                exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \
                --ovn-nb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
                ${election_timer} \
                run_nb_ovsdb &

                wait $!
              else
                echo "Joining the nbdb cluster with init_ip=${init_ip}..."
                exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \
                --db-nb-cluster-remote-port=9643 \
                --db-nb-cluster-remote-addr=${init_ip} \
                --db-nb-cluster-remote-proto=ssl \
                --ovn-nb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
                run_nb_ovsdb &

                wait $!
              fi
            fi
          else
            exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \
              --ovn-nb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
              run_nb_ovsdb &

              wait $!
          fi

        lifecycle:
          postStart:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                set -x
                CLUSTER_INITIATOR_IP="10.73.116.66"
                rm -f /var/run/ovn/ovnnb_db.pid
                if [[ "${K8S_NODE_IP}" == "${CLUSTER_INITIATOR_IP}" ]]; then
                  echo "$(date -Iseconds) - nbdb - postStart - waiting for master to be selected"

                  # set the connection and inactivity probe
                  retries=0
                  while ! ovn-nbctl --no-leader-only -t 5 set-connection pssl:9641 -- set connection . inactivity_probe=60000; do
                    (( retries += 1 ))
                  if [[ "${retries}" -gt 40 ]]; then
                    echo "$(date -Iseconds) - ERROR RESTARTING - nbdb - too many failed ovn-nbctl attempts, giving up"
                      exit 1
                  fi
                  sleep 2
                  done

                  # Upgrade the db if required.
                  DB_SCHEMA="/usr/share/ovn/ovn-nb.ovsschema"
                  DB_SERVER="unix:/var/run/ovn/ovnnb_db.sock"
                  schema_name=$(ovsdb-tool schema-name $DB_SCHEMA)
                  db_version=$(ovsdb-client -t 10 get-schema-version "$DB_SERVER" "$schema_name")
                  target_version=$(ovsdb-tool schema-version "$DB_SCHEMA")

                  if ovsdb-tool compare-versions "$db_version" == "$target_version"; then
                    :
                  elif ovsdb-tool compare-versions "$db_version" ">" "$target_version"; then
                      echo "Database $schema_name has newer schema version ($db_version) than our local schema ($target_version), possibly an upgrade is partially complete?"
                  else
                      echo "Upgrading database $schema_name from schema version $db_version to $target_version"
                      ovsdb-client -t 30 convert "$DB_SERVER" "$DB_SCHEMA"
                  fi
                fi
                #configure northd_probe_interval
                OVN_NB_CTL="ovn-nbctl -p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt \
                            --db "ssl:10.73.116.66:9641""
                northd_probe_interval=${OVN_NORTHD_PROBE_INTERVAL:-10000}
                echo "Setting northd probe interval to ${northd_probe_interval} ms"
                retries=0
                current_probe_interval=0
                while [[ "${retries}" -lt 10 ]]; do
                  current_probe_interval=$(${OVN_NB_CTL} --if-exists get NB_GLOBAL . options:northd_probe_interval)
                  if [[ $? == 0 ]]; then
                    current_probe_interval=$(echo ${current_probe_interval} | tr -d '\"')
                    break
                  else
                    sleep 2
                    (( retries += 1 ))
                  fi
                done

                if [[ "${current_probe_interval}" != "${northd_probe_interval}" ]]; then
                  retries=0
                  while [[ "${retries}" -lt 10 ]]; do
                    ${OVN_NB_CTL} set NB_GLOBAL . options:northd_probe_interval=${northd_probe_interval}
                    if [[ $? != 0 ]]; then
                      echo "Failed to set northd probe interval to ${northd_probe_interval}. retrying....."
                      sleep 2
                      (( retries += 1 ))
                    else
                      echo "Successfully set northd probe interval to ${northd_probe_interval} ms"
                      break
                    fi
                  done
                fi

          preStop:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                echo "$(date -Iseconds) - stopping nbdb"
                /usr/share/ovn/scripts/ovn-ctl stop_nb_ovsdb
                echo "$(date -Iseconds) - nbdb stopped"
                rm -f /var/run/ovn/ovnnb_db.pid
        readinessProbe:
          timeoutSeconds: 5
          exec:
            command:
            - /bin/bash
            - -c
            - |
              set -xeo pipefail
              leader_status=$(/usr/bin/ovn-appctl -t /var/run/ovn/ovnnb_db.ctl --timeout=3 cluster/status OVN_Northbound  2>/dev/null | { grep "Leader: unknown" || true; })
              if [[ ! -z "${leader_status}" ]]; then
                echo "NB DB Raft leader is unknown to the cluster node."
                exit 1
              else
                /usr/bin/ovn-appctl -t /var/run/ovn/ovnnb_db.ctl --timeout=5 ovsdb-server/memory-trim-on-compaction on 2>/dev/null
              fi

        env:
        - name: OVN_LOG_LEVEL
          value: info 
        - name: OVN_NORTHD_PROBE_INTERVAL
          value: "5000"
        - name: K8S_NODE_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
        volumeMounts:
        - mountPath: /etc/openvswitch/
          name: etc-openvswitch
        - mountPath: /etc/ovn/
          name: etc-openvswitch
        - mountPath: /var/lib/openvswitch/
          name: var-lib-openvswitch
        - mountPath: /run/openvswitch/
          name: run-openvswitch
        - mountPath: /run/ovn/
          name: run-ovn
        - mountPath: /env
          name: env-overrides
        - mountPath: /ovn-cert
          name: ovn-cert
        - mountPath: /ovn-ca
          name: ovn-ca
        resources:
          requests:
            cpu: 10m
            memory: 300Mi
        ports:
        - name: nb-db-port
          containerPort: 9641
        - name: nb-db-raft-port
          containerPort: 9643
        terminationMessagePolicy: FallbackToLogsOnError

      # sbdb: The southbound, or flow DB. In raft mode
      - name: sbdb
        image: "quay.io/zshi/ovn-daemonset:microshift"
        command:
        - /bin/bash
        - -c
        - |
          set -xm
          if [[ -f /env/_master ]]; then
            set -o allexport
            source /env/_master
            set +o allexport
          fi

          quit() {
            echo "$(date -Iseconds) - stopping sbdb"
            /usr/share/ovn/scripts/ovn-ctl stop_sb_ovsdb
            echo "$(date -Iseconds) - sbdb stopped"
            rm -f /var/run/ovn/ovnsb_db.pid
            exit 0
          }
          # end of quit
          trap quit TERM INT

          bracketify() { case "$1" in *:*) echo "[$1]" ;; *) echo "$1" ;; esac }

          # initialize variables
          ovn_kubernetes_namespace=openshift-ovn-kubernetes
          ovndb_ctl_ssl_opts="-p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt"
          transport="ssl"
          ovn_raft_conn_ip_url_suffix=""
          if [[ "${K8S_NODE_IP}" == *":"* ]]; then
            ovn_raft_conn_ip_url_suffix=":[::]"
          fi
          db="sb"
          db_port="9642"
          ovn_db_file="/etc/ovn/ovn${db}_db.db"
          # checks if a db pod is part of a current cluster
          db_part_of_cluster() {
            local pod=${1}
            local db=${2}
            local port=${3}
            echo "Checking if ${pod} is part of cluster"
            # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed. 
            init_ip=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} ${pod} -o=jsonpath='{.status.podIP}')
            if [[ $? != 0 ]]; then
              echo "Unable to get ${pod} ip "
              return 1
            fi
            echo "Found ${pod} ip: $init_ip"
            init_ip=$(bracketify $init_ip)
            target=$(ovn-${db}ctl --timeout=5 --db=${transport}:${init_ip}:${port} ${ovndb_ctl_ssl_opts} \
                      --data=bare --no-headings --columns=target list connection)
            if [[ "${target}" != "p${transport}:${port}${ovn_raft_conn_ip_url_suffix}" ]]; then
              echo "Unable to check correct target ${target} "
              return 1
            fi
            echo "${pod} is part of cluster"
            return 0
          }
          # end of db_part_of_cluster

          # Checks if cluster has already been initialized.
          # If not it returns false and sets init_ip to CLUSTER_INITIATOR_IP
          cluster_exists() {
            local db=${1}
            local port=${2}
            # TODO: change to use '--request-timeout=5s', if https://github.com/kubernetes/kubernetes/issues/49343 is fixed. 
            db_pods=$(timeout 5 kubectl get pod -n ${ovn_kubernetes_namespace} -o=jsonpath='{.items[*].metadata.name}' | egrep -o 'ovnkube-master-\w+' | grep -v "metrics")

            for db_pod in $db_pods; do
              if db_part_of_cluster $db_pod $db $port; then
                echo "${db_pod} is part of current cluster with ip: ${init_ip}!"
                return 0
              fi
            done
            # if we get here  there is no cluster, set init_ip and get out
            init_ip=$(bracketify $CLUSTER_INITIATOR_IP)
            return 1
          }
          # end of cluster_exists()

          OVN_ARGS="--db-sb-cluster-local-port=9644 \
            --db-sb-cluster-local-addr=$(bracketify ${K8S_NODE_IP}) \
            --no-monitor \
            --db-sb-cluster-local-proto=ssl \
            --ovn-sb-db-ssl-key=/ovn-cert/tls.key \
            --ovn-sb-db-ssl-cert=/ovn-cert/tls.crt \
            --ovn-sb-db-ssl-ca-cert=/ovn-ca/ca-bundle.crt"

          CLUSTER_INITIATOR_IP="10.73.116.66"
          echo "$(date -Iseconds) - starting sbdb  CLUSTER_INITIATOR_IP=${CLUSTER_INITIATOR_IP}"
          initial_raft_create=true
          initialize="false"

          if [[ ! -e ${ovn_db_file} ]]; then
            initialize="true"
          fi

          if [[ "${initialize}" == "true" ]]; then
            # check to see if a cluster already exists. If it does, just join it.
            counter=0
            cluster_found=false
            while [ $counter -lt 5 ]; do
              if cluster_exists ${db} ${db_port}; then
                cluster_found=true
                break
              fi
              sleep 1
              counter=$((counter+1))
            done

            if ${cluster_found}; then
              echo "Cluster already exists for DB: ${db}"
              initial_raft_create=false
              # join existing cluster
              exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \
              --db-sb-cluster-remote-port=9644 \
              --db-sb-cluster-remote-addr=${init_ip} \
              --db-sb-cluster-remote-proto=ssl \
              --ovn-sb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
              run_sb_ovsdb &

              wait $!
            else
              # either we need to initialize a new cluster or wait for master to create it
              if [[ "${K8S_NODE_IP}" == "${CLUSTER_INITIATOR_IP}" ]]; then
                # set DB election timer at DB creation time if OVN supports it
                election_timer=
                if test -n "$(/usr/share/ovn/scripts/ovn-ctl --help 2>&1 | grep "\--db-sb-election-timer")"; then
                  election_timer="--db-sb-election-timer=$((16*1000))"
                fi

                exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \
                --ovn-sb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
                ${election_timer} \
                run_sb_ovsdb &

                wait $!
              else
                exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \
                --db-sb-cluster-remote-port=9644 \
                --db-sb-cluster-remote-addr=${init_ip} \
                --db-sb-cluster-remote-proto=ssl \
                --ovn-sb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
                run_sb_ovsdb &

                wait $!
              fi
            fi
          else
            exec /usr/share/ovn/scripts/ovn-ctl ${OVN_ARGS} \
            --ovn-sb-log="-vconsole:${OVN_LOG_LEVEL} -vfile:off -vPATTERN:console:%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
            run_sb_ovsdb &

            wait $!
          fi
        lifecycle:
          postStart:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                set -x
                CLUSTER_INITIATOR_IP="10.73.116.66"
                rm -f /var/run/ovn/ovnsb_db.pid
                if [[ "${K8S_NODE_IP}" == "${CLUSTER_INITIATOR_IP}" ]]; then
                  echo "$(date -Iseconds) - sdb - postStart - waiting for master to be selected"

                  # set the connection and inactivity probe
                  retries=0
                  while ! ovn-sbctl --no-leader-only -t 5 set-connection pssl:9642 -- set connection . inactivity_probe=180000; do
                    (( retries += 1 ))
                  if [[ "${retries}" -gt 40 ]]; then
                    echo "$(date -Iseconds) - ERROR RESTARTING - sbdb - too many failed ovn-sbctl attempts, giving up"
                      exit 1
                  fi
                  sleep 2
                  done

                  # Upgrade the db if required.
                  DB_SCHEMA="/usr/share/ovn/ovn-sb.ovsschema"
                  DB_SERVER="unix:/var/run/ovn/ovnsb_db.sock"
                  schema_name=$(ovsdb-tool schema-name $DB_SCHEMA)
                  db_version=$(ovsdb-client -t 10 get-schema-version "$DB_SERVER" "$schema_name")
                  target_version=$(ovsdb-tool schema-version "$DB_SCHEMA")

                  if ovsdb-tool compare-versions "$db_version" == "$target_version"; then
                    :
                  elif ovsdb-tool compare-versions "$db_version" ">" "$target_version"; then
                      echo "Database $schema_name has newer schema version ($db_version) than our local schema ($target_version), possibly an upgrade is partially complete?"
                  else
                      echo "Upgrading database $schema_name from schema version $db_version to $target_version"
                      ovsdb-client -t 30 convert "$DB_SERVER" "$DB_SCHEMA"
                  fi
                fi
          preStop:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                echo "$(date -Iseconds) - stopping sbdb"
                /usr/share/ovn/scripts/ovn-ctl stop_sb_ovsdb
                echo "$(date -Iseconds) - sbdb stopped"
                rm -f /var/run/ovn/ovnsb_db.pid
        readinessProbe:
          timeoutSeconds: 5
          exec:
            command:
            - /bin/bash
            - -c
            - |
              set -xeo pipefail
              leader_status=$(/usr/bin/ovn-appctl -t /var/run/ovn/ovnsb_db.ctl --timeout=3 cluster/status OVN_Southbound  2>/dev/null | { grep "Leader: unknown" || true; })
              if [[ ! -z "${leader_status}" ]]; then
                echo "SB DB Raft leader is unknown to the cluster node."
                exit 1
              else
                /usr/bin/ovn-appctl -t /var/run/ovn/ovnsb_db.ctl --timeout=5 ovsdb-server/memory-trim-on-compaction on 2>/dev/null
              fi
        env:
        - name: OVN_LOG_LEVEL
          value: info
        - name: K8S_NODE_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
        volumeMounts:
        - mountPath: /etc/openvswitch/
          name: etc-openvswitch
        - mountPath: /etc/ovn/
          name: etc-openvswitch
        - mountPath: /var/lib/openvswitch/
          name: var-lib-openvswitch
        - mountPath: /run/openvswitch/
          name: run-openvswitch
        - mountPath: /run/ovn/
          name: run-ovn
        - mountPath: /env
          name: env-overrides
        - mountPath: /ovn-cert
          name: ovn-cert
        - mountPath: /ovn-ca
          name: ovn-ca
        ports:
        - name: sb-db-port
          containerPort: 9642
        - name: sb-db-raft-port
          containerPort: 9644
        resources:
          requests:
            cpu: 10m
            memory: 300Mi
        terminationMessagePolicy: FallbackToLogsOnError

      # ovnkube master: convert kubernetes objects in to nbdb logical network components
      - name: ovnkube-master
        image: "quay.io/zshi/ovn-daemonset:microshift"
        command:
        - /bin/bash
        - -c
        - |
          set -xe
          if [[ -f "/env/_master" ]]; then
            set -o allexport
            source "/env/_master"
            set +o allexport
          fi

          gateway_mode_flags="--gateway-mode shared --gateway-interface br-ex"

          echo "I$(date "+%m%d %H:%M:%S.%N") - ovnkube-master - start ovnkube --init-master ${K8S_NODE}"
          exec /usr/bin/ovnkube \
            --init-master "${K8S_NODE}" \
            --config-file=/run/ovnkube-config/ovnkube.conf \
            --ovn-empty-lb-events \
            --loglevel "${OVN_KUBE_LOG_LEVEL}" \
            --metrics-bind-address "127.0.0.1:29102" \
            --metrics-enable-pprof \
            ${gateway_mode_flags} \
            --sb-address "ssl:10.73.116.66:9642" \
            --sb-client-privkey /ovn-cert/tls.key \
            --sb-client-cert /ovn-cert/tls.crt \
            --sb-client-cacert /ovn-ca/ca-bundle.crt \
            --sb-cert-common-name "ovn" \
            --nb-address "ssl:10.73.116.66:9641" \
            --nb-client-privkey /ovn-cert/tls.key \
            --nb-client-cert /ovn-cert/tls.crt \
            --nb-client-cacert /ovn-ca/ca-bundle.crt \
            --nb-cert-common-name "ovn" \
            --enable-multicast \
            --disable-snat-multiple-gws \
            --acl-logging-rate-limit "20"
        volumeMounts:
        # for checking ovs-configuration service
        - mountPath: /etc/systemd/system
          name: systemd-units
          readOnly: true
        - mountPath: /etc/openvswitch/
          name: etc-openvswitch
        - mountPath: /etc/ovn/
          name: etc-openvswitch
        - mountPath: /var/lib/openvswitch/
          name: var-lib-openvswitch
        - mountPath: /run/openvswitch/
          name: run-openvswitch
        - mountPath: /run/ovn/
          name: run-ovn
        - mountPath: /run/ovnkube-config/
          name: ovnkube-config
        - mountPath: /var/lib/microshift/resources/kubeadmin/
          name: kubeconfig
        - mountPath: /env
          name: env-overrides
        - mountPath: /ovn-cert
          name: ovn-cert
        - mountPath: /ovn-ca
          name: ovn-ca
        resources:
          requests:
            cpu: 10m
            memory: 300Mi
        env:
        - name: OVN_KUBE_LOG_LEVEL
          value: "4"
        - name: K8S_NODE
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        ports:
        - name: metrics-port
          containerPort: 29102
        terminationMessagePolicy: FallbackToLogsOnError
      nodeSelector:
        beta.kubernetes.io/os: "linux"
      volumes:
      # for checking ovs-configuration service
      - name: systemd-units
        hostPath:
          path: /etc/systemd/system
      - name: etc-openvswitch
        hostPath:
          path: /var/lib/ovn/etc
      - name: var-lib-openvswitch
        hostPath:
          path: /var/lib/ovn/data
      - name: run-openvswitch
        hostPath:
          path: /var/run/openvswitch
      - name: run-ovn
        hostPath:
          path: /var/run/ovn
      - name: kubeconfig
        hostPath:
          path: /var/lib/microshift/resources/kubeadmin
      - name: ovnkube-config
        configMap:
          name: ovnkube-config
      - name: env-overrides
        configMap:
          name: env-overrides
          optional: true
      - name: ovn-ca
        configMap:
          name: ovn-ca
      - name: ovn-cert
        secret:
          secretName: ovn-cert
      - name: ovn-master-metrics-cert
        secret:
          secretName: ovn-master-metrics-cert
          optional: true
      tolerations:
      - key: "node-role.kubernetes.io/master"
        operator: "Exists"
      - key: "node.kubernetes.io/not-ready"
        operator: "Exists"
      - key: "node.kubernetes.io/unreachable"
        operator: "Exists"
      - key: "node.kubernetes.io/network-unavailable"
        operator: "Exists"
`)

func assetsComponentsOvnMasterDaemonsetYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnMasterDaemonsetYaml, nil
}

func assetsComponentsOvnMasterDaemonsetYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnMasterDaemonsetYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/master/daemonset.yaml", size: 30637, mode: os.FileMode(436), modTime: time.Unix(1653814560, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnMasterServiceaccountYaml = []byte(`---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ovn-kubernetes-controller
  namespace: openshift-ovn-kubernetes
`)

func assetsComponentsOvnMasterServiceaccountYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnMasterServiceaccountYaml, nil
}

func assetsComponentsOvnMasterServiceaccountYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnMasterServiceaccountYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/master/serviceaccount.yaml", size: 122, mode: os.FileMode(436), modTime: time.Unix(1653813677, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnNamespaceYaml = []byte(`apiVersion: v1
kind: Namespace
metadata:
  # NOTE: ovnkube.sh in the OVN image currently hardcodes this namespace name
  name: openshift-ovn-kubernetes
  labels:
    openshift.io/run-level: "0"
    openshift.io/cluster-monitoring: "true"
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
  annotations:
    openshift.io/node-selector: ""
    openshift.io/description: "OVN Kubernetes components"
    workload.openshift.io/allowed: "management"
`)

func assetsComponentsOvnNamespaceYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnNamespaceYaml, nil
}

func assetsComponentsOvnNamespaceYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnNamespaceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/namespace.yaml", size: 542, mode: os.FileMode(436), modTime: time.Unix(1653813484, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnNodeDaemonsetYaml = []byte(`---
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: ovnkube-node
  namespace: openshift-ovn-kubernetes
  annotations:
    kubernetes.io/description: |
      This daemonset launches the ovn-kubernetes per node networking components.
    release.openshift.io/version: "4.11"
spec:
  selector:
    matchLabels:
      app: ovnkube-node
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 10%
  template:
    metadata:
      annotations:
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
      labels:
        app: ovnkube-node
        component: network
        type: infra
        openshift.io/component: network
        kubernetes.io/os: "linux"
    spec:
      serviceAccountName: ovn-kubernetes-node
      hostNetwork: true
      dnsPolicy: Default
      hostPID: true
      priorityClassName: "system-node-critical"
      # volumes in all containers:
      # (container) -> (host)
      # /etc/openvswitch -> /etc/openvswitch - ovsdb system id
      # /var/lib/openvswitch -> /var/lib/openvswitch/data - ovsdb data
      # /run/openvswitch -> tmpfs - ovsdb sockets
      # /env -> configmap env-overrides - debug overrides
      containers:
      # ovn-controller: programs the vswitch with flows from the sbdb
      - name: ovn-controller
        image: "quay.io/zshi/ovn-daemonset:microshift"
        command:
        - /bin/bash
        - -c
        - |
          set -e
          if [[ -f "/env/${K8S_NODE}" ]]; then
            set -o allexport
            source "/env/${K8S_NODE}"
            set +o allexport
          fi

          echo "$(date -Iseconds) - starting ovn-controller"
          exec ovn-controller unix:/var/run/openvswitch/db.sock -vfile:off \
            --no-chdir --pidfile=/var/run/ovn/ovn-controller.pid \
            --syslog-method="null" \
            --log-file=/var/log/ovn/acl-audit-log.log \
            -vFACILITY:"local0" \
            -p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt \
            -vconsole:"${OVN_LOG_LEVEL}" -vconsole:"acl_log:off" \
            -vPATTERN:console:"%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m" \
            -vsyslog:"acl_log:info" \
            -vfile:"acl_log:info"
        securityContext:
          privileged: true
        env:
        - name: OVN_LOG_LEVEL
          value: info
        - name: K8S_NODE
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - mountPath: /run/openvswitch
          name: run-openvswitch
        - mountPath: /run/ovn/
          name: run-ovn
        - mountPath: /etc/openvswitch
          name: etc-openvswitch
        - mountPath: /etc/ovn/
          name: etc-openvswitch
        - mountPath: /var/lib/openvswitch
          name: var-lib-openvswitch
        - mountPath: /env
          name: env-overrides
        - mountPath: /ovn-cert
          name: ovn-cert
        - mountPath: /ovn-ca
          name: ovn-ca
        - mountPath: /var/log/ovn
          name: node-log
        - mountPath: /dev/log
          name: log-socket
        terminationMessagePolicy: FallbackToLogsOnError
        resources:
          requests:
            cpu: 10m
            memory: 300Mi
      # ovnkube-node: does node-level bookkeeping and configuration
      - name: ovnkube-node
        image: "quay.io/zshi/ovn-daemonset:microshift"
        command:
        - /bin/bash
        - -c
        - |
          set -xe
          if [[ -f "/env/${K8S_NODE}" ]]; then
            set -o allexport
            source "/env/${K8S_NODE}"
            set +o allexport
          fi
          cp -f /usr/libexec/cni/ovn-k8s-cni-overlay /cni-bin-dir/
          ovn_config_namespace=openshift-ovn-kubernetes
          echo "I$(date "+%m%d %H:%M:%S.%N") - disable conntrack on geneve port"
          iptables -t raw -A PREROUTING -p udp --dport 6081 -j NOTRACK
          iptables -t raw -A OUTPUT -p udp --dport 6081 -j NOTRACK
          ip6tables -t raw -A PREROUTING -p udp --dport 6081 -j NOTRACK
          ip6tables -t raw -A OUTPUT -p udp --dport 6081 -j NOTRACK
          echo "I$(date "+%m%d %H:%M:%S.%N") - starting ovnkube-node"

          gateway_mode_flags="--gateway-mode shared --gateway-interface br-ex"

          export_network_flows_flags=
          if [[ -n "${NETFLOW_COLLECTORS}" ]] ; then
            export_network_flows_flags="--netflow-targets ${NETFLOW_COLLECTORS}"
          fi
          if [[ -n "${SFLOW_COLLECTORS}" ]] ; then
            export_network_flows_flags="$export_network_flows_flags --sflow-targets ${SFLOW_COLLECTORS}"
          fi
          if [[ -n "${IPFIX_COLLECTORS}" ]] ; then
            export_network_flows_flags="$export_network_flows_flags --ipfix-targets ${IPFIX_COLLECTORS}"
          fi
          if [[ -n "${IPFIX_CACHE_MAX_FLOWS}" ]] ; then
            export_network_flows_flags="$export_network_flows_flags --ipfix-cache-max-flows ${IPFIX_CACHE_MAX_FLOWS}"
          fi
          if [[ -n "${IPFIX_CACHE_ACTIVE_TIMEOUT}" ]] ; then
            export_network_flows_flags="$export_network_flows_flags --ipfix-cache-active-timeout ${IPFIX_CACHE_ACTIVE_TIMEOUT}"
          fi
          if [[ -n "${IPFIX_SAMPLING}" ]] ; then
            export_network_flows_flags="$export_network_flows_flags --ipfix-sampling ${IPFIX_SAMPLING}"
          fi
          gw_interface_flag=
          # if br-ex1 is configured on the node, we want to use it for external gateway traffic
          if [ -d /sys/class/net/br-ex1 ]; then
            gw_interface_flag="--exgw-interface=br-ex1"
          fi

          node_mgmt_port_netdev_flags=
          if [[ -n "${OVNKUBE_NODE_MGMT_PORT_NETDEV}" ]] ; then
            node_mgmt_port_netdev_flags="--ovnkube-node-mgmt-port-netdev ${OVNKUBE_NODE_MGMT_PORT_NETDEV}"
          fi

          exec /usr/bin/ovnkube --init-node "${K8S_NODE}" \
            --nb-address "ssl:10.73.116.66:9641" \
            --sb-address "ssl:10.73.116.66:9642" \
            --nb-client-privkey /ovn-cert/tls.key \
            --nb-client-cert /ovn-cert/tls.crt \
            --nb-client-cacert /ovn-ca/ca-bundle.crt \
            --nb-cert-common-name "ovn" \
            --sb-client-privkey /ovn-cert/tls.key \
            --sb-client-cert /ovn-cert/tls.crt \
            --sb-client-cacert /ovn-ca/ca-bundle.crt \
            --sb-cert-common-name "ovn" \
            --config-file=/run/ovnkube-config/ovnkube.conf \
            --loglevel "${OVN_KUBE_LOG_LEVEL}" \
            --inactivity-probe="${OVN_CONTROLLER_INACTIVITY_PROBE}" \
            ${gateway_mode_flags} \
            --metrics-bind-address "127.0.0.1:29103" \
            --ovn-metrics-bind-address "127.0.0.1:29105" \
            --metrics-enable-pprof \
            --disable-snat-multiple-gws \
            ${export_network_flows_flags} \
            ${gw_interface_flag}
        env:
        # for kubectl
        - name: KUBERNETES_SERVICE_PORT
          value: "6443"
        - name: KUBERNETES_SERVICE_HOST
          value: "10.73.116.66"
        - name: OVN_CONTROLLER_INACTIVITY_PROBE
          value: "180000"
        - name: OVN_KUBE_LOG_LEVEL
          value: "4"
        - name: K8S_NODE
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        ports:
        - name: metrics-port
          containerPort: 29103
        securityContext:
          privileged: true
        terminationMessagePolicy: FallbackToLogsOnError
        volumeMounts:
        # for checking ovs-configuration service
        - mountPath: /etc/systemd/system
          name: systemd-units
          readOnly: true
        # for the iptables wrapper
        - mountPath: /host
          name: host-slash
          readOnly: true
          mountPropagation: HostToContainer
        # for the CNI server socket
        - mountPath: /run/ovn-kubernetes/
          name: host-run-ovn-kubernetes
        # accessing bind-mounted net namespaces
        - mountPath: /run/netns
          name: host-run-netns
          readOnly: true
          mountPropagation: HostToContainer
        # for installing the CNI plugin binary
        - mountPath: /cni-bin-dir
          name: host-cni-bin
        # for installing the CNI configuration file
        - mountPath: /etc/cni/net.d
          name: host-cni-netd
        # Where we store IP allocations
        - mountPath: /var/lib/cni/networks/ovn-k8s-cni-overlay
          name: host-var-lib-cni-networks-ovn-kubernetes
        - mountPath: /run/openvswitch
          name: run-openvswitch
        - mountPath: /run/ovn/
          name: run-ovn
        - mountPath: /etc/openvswitch
          name: etc-openvswitch
        - mountPath: /etc/ovn/
          name: etc-openvswitch
        - mountPath: /var/lib/openvswitch
          name: var-lib-openvswitch
        - mountPath: /run/ovnkube-config/
          name: ovnkube-config
        - mountPath: /var/lib/microshift/resources/kubeadmin/
          name: kubeconfig
        - mountPath: /env
          name: env-overrides
        - mountPath: /ovn-cert
          name: ovn-cert
        - mountPath: /ovn-ca
          name: ovn-ca
        resources:
          requests:
            cpu: 10m
            memory: 300Mi
        lifecycle:
          preStop:
            exec:
              command: ["rm","-f","/etc/cni/net.d/10-ovn-kubernetes.conf"]
        readinessProbe:
          exec:
            command: ["test", "-f", "/etc/cni/net.d/10-ovn-kubernetes.conf"]
          initialDelaySeconds: 5
          periodSeconds: 5
      nodeSelector:
        beta.kubernetes.io/os: "linux"
      volumes:
      # for checking ovs-configuration service
      - name: systemd-units
        hostPath:
          path: /etc/systemd/system
      # used for iptables wrapper scripts
      - name: host-slash
        hostPath:
          path: /
      - name: host-run-netns
        hostPath:
          path: /run/netns
      - name: var-lib-openvswitch
        hostPath:
          path: /var/lib/openvswitch/data
      - name: etc-openvswitch
        hostPath:
          path: /etc/openvswitch
      - name: run-openvswitch
        hostPath:
          path: /var/run/openvswitch
      - name: run-ovn
        hostPath:
          path: /var/run/ovn
      # Used for placement of ACL audit logs 
      - name: node-log
        hostPath: 
          path: /var/log/ovn
      - name: log-socket
        hostPath: 
          path: /dev/log
      # For CNI server
      - name: host-run-ovn-kubernetes
        hostPath:
          path: /run/ovn-kubernetes
      - name: host-cni-bin
        hostPath:
          path: "/var/lib/cni/bin"
      - name: host-cni-netd
        hostPath:
          path: "/var/run/multus/cni/net.d"
      - name: host-var-lib-cni-networks-ovn-kubernetes
        hostPath:
          path: /var/lib/cni/networks/ovn-k8s-cni-overlay
      - name: kubeconfig
        hostPath:
          path: /var/lib/microshift/resources/kubeadmin
      - name: ovnkube-config
        configMap:
          name: ovnkube-config
      - name: env-overrides
        configMap:
          name: env-overrides
          optional: true
      - name: ovn-ca
        configMap:
          name: ovn-ca
      - name: ovn-cert
        secret:
          secretName: ovn-cert
      - name: ovn-node-metrics-cert
        secret:
          secretName: ovn-node-metrics-cert
          optional: true
      tolerations:
      - operator: "Exists"
`)

func assetsComponentsOvnNodeDaemonsetYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnNodeDaemonsetYaml, nil
}

func assetsComponentsOvnNodeDaemonsetYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnNodeDaemonsetYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/node/daemonset.yaml", size: 11400, mode: os.FileMode(436), modTime: time.Unix(1653814439, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnNodeServiceaccountYaml = []byte(`---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ovn-kubernetes-node
  namespace: openshift-ovn-kubernetes
`)

func assetsComponentsOvnNodeServiceaccountYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnNodeServiceaccountYaml, nil
}

func assetsComponentsOvnNodeServiceaccountYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnNodeServiceaccountYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/node/serviceaccount.yaml", size: 116, mode: os.FileMode(436), modTime: time.Unix(1653813695, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnRoleYaml = []byte(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: openshift-ovn-kubernetes-node
  namespace: openshift-ovn-kubernetes
rules:
- apiGroups: [""]
  resources:
  - configmaps
  verbs:
  - get
  - list
  - watch
- apiGroups: [certificates.k8s.io]
  resources: ['certificatesigningrequests']
  verbs:
    - create
    - get
    - delete
    - update
    - list

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: openshift-ovn-kubernetes-sbdb
  namespace: openshift-ovn-kubernetes
rules:
- apiGroups: [""]
  resources:
  - endpoints
  verbs:
  - create
  - update
  - patch
`)

func assetsComponentsOvnRoleYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnRoleYaml, nil
}

func assetsComponentsOvnRoleYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/role.yaml", size: 615, mode: os.FileMode(436), modTime: time.Unix(1653813593, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnRolebindingYaml = []byte(`---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: openshift-ovn-kubernetes-node
  namespace: openshift-ovn-kubernetes
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: openshift-ovn-kubernetes-node
subjects:
- kind: ServiceAccount
  name: ovn-kubernetes-node
  namespace: openshift-ovn-kubernetes

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: openshift-ovn-kubernetes-sbdb
  namespace: openshift-ovn-kubernetes
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: openshift-ovn-kubernetes-sbdb
subjects:
- kind: ServiceAccount
  name: ovn-kubernetes-controller
  namespace: openshift-ovn-kubernetes
`)

func assetsComponentsOvnRolebindingYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnRolebindingYaml, nil
}

func assetsComponentsOvnRolebindingYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnRolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/rolebinding.yaml", size: 699, mode: os.FileMode(436), modTime: time.Unix(1653813608, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsOvnServiceYaml = []byte(`---
# service to expose the ovn-master pod
# at present ovn-master is limited to a single instance so
# when the cluster has multiple masters we can get to the
# ovn-master via this service.
apiVersion: v1
kind: Service
metadata:
  name: ovnkube-db
  namespace: openshift-ovn-kubernetes
spec:
  selector:
    app: ovnkube-master
  ports:
  - name: north
    port: 9641
    protocol: TCP
    targetPort: 9641
  - name: south
    port: 9642
    protocol: TCP
    targetPort: 9642
  sessionAffinity: None
  clusterIP: None
  type: ClusterIP
`)

func assetsComponentsOvnServiceYamlBytes() ([]byte, error) {
	return _assetsComponentsOvnServiceYaml, nil
}

func assetsComponentsOvnServiceYaml() (*asset, error) {
	bytes, err := assetsComponentsOvnServiceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/ovn/service.yaml", size: 538, mode: os.FileMode(436), modTime: time.Unix(1653813645, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaClusterroleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:openshift:controller:service-ca
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
- apiGroups:
  - ""
  resources:
  - services
  verbs:
  - get
  - list
  - watch
  - update
  - patch
- apiGroups:
  - admissionregistration.k8s.io
  resources:
  - mutatingwebhookconfigurations
  - validatingwebhookconfigurations
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - customresourcedefinitions
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - apiregistration.k8s.io
  resources:
  - apiservices
  verbs:
  - get
  - list
  - watch
  - update
  - patch
- apiGroups:
  - ""
  resources:
  - configmaps
  verbs:
  - get
  - list
  - watch
  - update
`)

func assetsComponentsServiceCaClusterroleYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaClusterroleYaml, nil
}

func assetsComponentsServiceCaClusterroleYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaClusterroleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/clusterrole.yaml", size: 864, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaClusterrolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:openshift:controller:service-ca
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  namespace: openshift-service-ca
  name: service-ca
`)

func assetsComponentsServiceCaClusterrolebindingYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaClusterrolebindingYaml, nil
}

func assetsComponentsServiceCaClusterrolebindingYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaClusterrolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/clusterrolebinding.yaml", size: 298, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: openshift-service-ca
  name: service-ca
  labels:
    app: service-ca
    service-ca: "true"
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: service-ca
      service-ca: "true"
  template:
    metadata:
      name: service-ca
      annotations:
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
      labels:
        app: service-ca
        service-ca: "true"
    spec:
      securityContext: {}
      serviceAccount: service-ca
      serviceAccountName: service-ca
      containers:
      - name: service-ca-controller
        image: {{ .ReleaseImage.service_ca_operator }}
        imagePullPolicy: IfNotPresent
        command: ["service-ca-operator", "controller"]
        ports:
        - containerPort: 8443
        # securityContext:
        #   runAsNonRoot: true
        resources:
          requests:
            memory: 120Mi
            cpu: 10m
        volumeMounts:
        - mountPath: /var/run/secrets/signing-key
          name: signing-key
        - mountPath: /var/run/configmaps/signing-cabundle
          name: signing-cabundle
      volumes:
      - name: signing-key
        secret:
          secretName: {{.TLSSecret}}
      - name: signing-cabundle
        configMap:
          name: {{.CAConfigMap}}
      # nodeSelector:
      #   node-role.kubernetes.io/master: ""
      priorityClassName: "system-cluster-critical"
      tolerations:
      - key: node-role.kubernetes.io/master
        operator: Exists
        effect: "NoSchedule"
      - key: "node.kubernetes.io/unreachable"
        operator: "Exists"
        effect: "NoExecute"
        tolerationSeconds: 120
      - key: "node.kubernetes.io/not-ready"
        operator: "Exists"
        effect: "NoExecute"
        tolerationSeconds: 120
`)

func assetsComponentsServiceCaDeploymentYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaDeploymentYaml, nil
}

func assetsComponentsServiceCaDeploymentYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/deployment.yaml", size: 1866, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaNsYaml = []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: openshift-service-ca
  annotations:
    openshift.io/node-selector: ""
    workload.openshift.io/allowed: "management"
`)

func assetsComponentsServiceCaNsYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaNsYaml, nil
}

func assetsComponentsServiceCaNsYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaNsYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/ns.yaml", size: 168, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaRoleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: system:openshift:controller:service-ca
  namespace: openshift-service-ca
rules:
- apiGroups:
  - security.openshift.io
  resources:
  - securitycontextconstraints
  resourceNames:
  - restricted
  verbs:
  - use
- apiGroups:
  - ""
  resources:
  - events
  verbs:
  - create
- apiGroups:
  - ""
  resources:
  - configmaps
  verbs:
  - get
  - list
  - watch
  - update
  - create
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - "apps"
  resources:
  - replicasets
  - deployments
  verbs:
  - get
  - list
  - watch`)

func assetsComponentsServiceCaRoleYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaRoleYaml, nil
}

func assetsComponentsServiceCaRoleYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/role.yaml", size: 634, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaRolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: system:openshift:controller:service-ca
  namespace: openshift-service-ca
roleRef:
  kind: Role
  name: system:openshift:controller:service-ca
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  namespace: openshift-service-ca
  name: service-ca
`)

func assetsComponentsServiceCaRolebindingYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaRolebindingYaml, nil
}

func assetsComponentsServiceCaRolebindingYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaRolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/rolebinding.yaml", size: 343, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaSaYaml = []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: openshift-service-ca
  name: service-ca
`)

func assetsComponentsServiceCaSaYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaSaYaml, nil
}

func assetsComponentsServiceCaSaYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaSaYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/sa.yaml", size: 99, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaSigningCabundleYaml = []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  namespace: openshift-service-ca
  name: signing-cabundle
data:
  ca-bundle.crt:
`)

func assetsComponentsServiceCaSigningCabundleYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaSigningCabundleYaml, nil
}

func assetsComponentsServiceCaSigningCabundleYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaSigningCabundleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/signing-cabundle.yaml", size: 123, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsComponentsServiceCaSigningSecretYaml = []byte(`apiVersion: v1
kind: Secret
metadata:
  namespace: openshift-service-ca
  name: signing-key
type: kubernetes.io/tls
data:
  tls.crt:
  tls.key:
`)

func assetsComponentsServiceCaSigningSecretYamlBytes() ([]byte, error) {
	return _assetsComponentsServiceCaSigningSecretYaml, nil
}

func assetsComponentsServiceCaSigningSecretYaml() (*asset, error) {
	bytes, err := assetsComponentsServiceCaSigningSecretYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/components/service-ca/signing-secret.yaml", size: 144, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCore0000_50_clusterOpenshiftControllerManager_00_namespaceYaml = []byte(`apiVersion: v1
kind: Namespace
metadata:
  annotations:
    include.release.openshift.io/self-managed-high-availability: "true"
    openshift.io/node-selector: ""
  labels:
    openshift.io/cluster-monitoring: "true"
  name: openshift-controller-manager
`)

func assetsCore0000_50_clusterOpenshiftControllerManager_00_namespaceYamlBytes() ([]byte, error) {
	return _assetsCore0000_50_clusterOpenshiftControllerManager_00_namespaceYaml, nil
}

func assetsCore0000_50_clusterOpenshiftControllerManager_00_namespaceYaml() (*asset, error) {
	bytes, err := assetsCore0000_50_clusterOpenshiftControllerManager_00_namespaceYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/core/0000_50_cluster-openshift-controller-manager_00_namespace.yaml", size: 254, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_03_authorizationOpenshift_01_rolebindingrestrictionCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/470
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: rolebindingrestrictions.authorization.openshift.io
spec:
  group: authorization.openshift.io
  names:
    kind: RoleBindingRestriction
    listKind: RoleBindingRestrictionList
    plural: rolebindingrestrictions
    singular: rolebindingrestriction
  scope: Namespaced
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          description: "RoleBindingRestriction is an object that can be matched against a subject (user, group, or service account) to determine whether rolebindings on that subject are allowed in the namespace to which the RoleBindingRestriction belongs.  If any one of those RoleBindingRestriction objects matches a subject, rolebindings on that subject in the namespace are allowed. \n Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer)."
          type: object
          properties:
            apiVersion:
              description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
              type: string
            kind:
              description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
              type: string
            metadata:
              type: object
            spec:
              description: Spec defines the matcher.
              type: object
              properties:
                grouprestriction:
                  description: GroupRestriction matches against group subjects.
                  type: object
                  properties:
                    groups:
                      description: Groups is a list of groups used to match against an individual user's groups. If the user is a member of one of the whitelisted groups, the user is allowed to be bound to a role.
                      type: array
                      items:
                        type: string
                      nullable: true
                    labels:
                      description: Selectors specifies a list of label selectors over group labels.
                      type: array
                      items:
                        description: A label selector is a label query over a set of resources. The result of matchLabels and matchExpressions are ANDed. An empty label selector matches all objects. A null label selector matches no objects.
                        type: object
                        properties:
                          matchExpressions:
                            description: matchExpressions is a list of label selector requirements. The requirements are ANDed.
                            type: array
                            items:
                              description: A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
                              type: object
                              required:
                                - key
                                - operator
                              properties:
                                key:
                                  description: key is the label key that the selector applies to.
                                  type: string
                                operator:
                                  description: operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
                                  type: string
                                values:
                                  description: values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
                                  type: array
                                  items:
                                    type: string
                          matchLabels:
                            description: matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
                            type: object
                            additionalProperties:
                              type: string
                      nullable: true
                  nullable: true
                serviceaccountrestriction:
                  description: ServiceAccountRestriction matches against service-account subjects.
                  type: object
                  properties:
                    namespaces:
                      description: Namespaces specifies a list of literal namespace names.
                      type: array
                      items:
                        type: string
                    serviceaccounts:
                      description: ServiceAccounts specifies a list of literal service-account names.
                      type: array
                      items:
                        description: ServiceAccountReference specifies a service account and namespace by their names.
                        type: object
                        properties:
                          name:
                            description: Name is the name of the service account.
                            type: string
                          namespace:
                            description: Namespace is the namespace of the service account.  Service accounts from inside the whitelisted namespaces are allowed to be bound to roles.  If Namespace is empty, then the namespace of the RoleBindingRestriction in which the ServiceAccountReference is embedded is used.
                            type: string
                  nullable: true
                userrestriction:
                  description: UserRestriction matches against user subjects.
                  type: object
                  properties:
                    groups:
                      description: Groups specifies a list of literal group names.
                      type: array
                      items:
                        type: string
                      nullable: true
                    labels:
                      description: Selectors specifies a list of label selectors over user labels.
                      type: array
                      items:
                        description: A label selector is a label query over a set of resources. The result of matchLabels and matchExpressions are ANDed. An empty label selector matches all objects. A null label selector matches no objects.
                        type: object
                        properties:
                          matchExpressions:
                            description: matchExpressions is a list of label selector requirements. The requirements are ANDed.
                            type: array
                            items:
                              description: A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
                              type: object
                              required:
                                - key
                                - operator
                              properties:
                                key:
                                  description: key is the label key that the selector applies to.
                                  type: string
                                operator:
                                  description: operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
                                  type: string
                                values:
                                  description: values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
                                  type: array
                                  items:
                                    type: string
                          matchLabels:
                            description: matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
                            type: object
                            additionalProperties:
                              type: string
                      nullable: true
                    users:
                      description: Users specifies a list of literal user names.
                      type: array
                      items:
                        type: string
                  nullable: true
      served: true
      storage: true
`)

func assetsCrd0000_03_authorizationOpenshift_01_rolebindingrestrictionCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_03_authorizationOpenshift_01_rolebindingrestrictionCrdYaml, nil
}

func assetsCrd0000_03_authorizationOpenshift_01_rolebindingrestrictionCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_03_authorizationOpenshift_01_rolebindingrestrictionCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_03_authorization-openshift_01_rolebindingrestriction.crd.yaml", size: 9898, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_03_configOperator_01_proxyCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/470
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: proxies.config.openshift.io
spec:
  group: config.openshift.io
  names:
    kind: Proxy
    listKind: ProxyList
    plural: proxies
    singular: proxy
  scope: Cluster
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          description: "Proxy holds cluster-wide information on how to configure default proxies for the cluster. The canonical name is ` + "`" + `cluster` + "`" + ` \n Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer)."
          type: object
          required:
            - spec
          properties:
            apiVersion:
              description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
              type: string
            kind:
              description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
              type: string
            metadata:
              type: object
            spec:
              description: Spec holds user-settable values for the proxy configuration
              type: object
              properties:
                httpProxy:
                  description: httpProxy is the URL of the proxy for HTTP requests.  Empty means unset and will not result in an env var.
                  type: string
                httpsProxy:
                  description: httpsProxy is the URL of the proxy for HTTPS requests.  Empty means unset and will not result in an env var.
                  type: string
                noProxy:
                  description: noProxy is a comma-separated list of hostnames and/or CIDRs and/or IPs for which the proxy should not be used. Empty means unset and will not result in an env var.
                  type: string
                readinessEndpoints:
                  description: readinessEndpoints is a list of endpoints used to verify readiness of the proxy.
                  type: array
                  items:
                    type: string
                trustedCA:
                  description: "trustedCA is a reference to a ConfigMap containing a CA certificate bundle. The trustedCA field should only be consumed by a proxy validator. The validator is responsible for reading the certificate bundle from the required key \"ca-bundle.crt\", merging it with the system default trust bundle, and writing the merged trust bundle to a ConfigMap named \"trusted-ca-bundle\" in the \"openshift-config-managed\" namespace. Clients that expect to make proxy connections must use the trusted-ca-bundle for all HTTPS requests to the proxy, and may use the trusted-ca-bundle for non-proxy HTTPS requests as well. \n The namespace for the ConfigMap referenced by trustedCA is \"openshift-config\". Here is an example ConfigMap (in yaml): \n apiVersion: v1 kind: ConfigMap metadata:  name: user-ca-bundle  namespace: openshift-config  data:    ca-bundle.crt: |      -----BEGIN CERTIFICATE-----      Custom CA certificate bundle.      -----END CERTIFICATE-----"
                  type: object
                  required:
                    - name
                  properties:
                    name:
                      description: name is the metadata.name of the referenced config map
                      type: string
            status:
              description: status holds observed values from the cluster. They may not be overridden.
              type: object
              properties:
                httpProxy:
                  description: httpProxy is the URL of the proxy for HTTP requests.
                  type: string
                httpsProxy:
                  description: httpsProxy is the URL of the proxy for HTTPS requests.
                  type: string
                noProxy:
                  description: noProxy is a comma-separated list of hostnames and/or CIDRs for which the proxy should not be used.
                  type: string
      served: true
      storage: true
      subresources:
        status: {}
`)

func assetsCrd0000_03_configOperator_01_proxyCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_03_configOperator_01_proxyCrdYaml, nil
}

func assetsCrd0000_03_configOperator_01_proxyCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_03_configOperator_01_proxyCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_03_config-operator_01_proxy.crd.yaml", size: 4790, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_03_quotaOpenshift_01_clusterresourcequotaCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/470
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: clusterresourcequotas.quota.openshift.io
spec:
  group: quota.openshift.io
  names:
    kind: ClusterResourceQuota
    listKind: ClusterResourceQuotaList
    plural: clusterresourcequotas
    singular: clusterresourcequota
  scope: Cluster
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          description: "ClusterResourceQuota mirrors ResourceQuota at a cluster scope.  This object is easily convertible to synthetic ResourceQuota object to allow quota evaluation re-use. \n Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer)."
          type: object
          required:
            - metadata
            - spec
          properties:
            apiVersion:
              description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
              type: string
            kind:
              description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
              type: string
            metadata:
              type: object
            spec:
              description: Spec defines the desired quota
              type: object
              required:
                - quota
                - selector
              properties:
                quota:
                  description: Quota defines the desired quota
                  type: object
                  properties:
                    hard:
                      description: 'hard is the set of desired hard limits for each named resource. More info: https://kubernetes.io/docs/concepts/policy/resource-quotas/'
                      type: object
                      additionalProperties:
                        pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                        anyOf:
                          - type: integer
                          - type: string
                        x-kubernetes-int-or-string: true
                    scopeSelector:
                      description: scopeSelector is also a collection of filters like scopes that must match each object tracked by a quota but expressed using ScopeSelectorOperator in combination with possible values. For a resource to match, both scopes AND scopeSelector (if specified in spec), must be matched.
                      type: object
                      properties:
                        matchExpressions:
                          description: A list of scope selector requirements by scope of the resources.
                          type: array
                          items:
                            description: A scoped-resource selector requirement is a selector that contains values, a scope name, and an operator that relates the scope name and values.
                            type: object
                            required:
                              - operator
                              - scopeName
                            properties:
                              operator:
                                description: Represents a scope's relationship to a set of values. Valid operators are In, NotIn, Exists, DoesNotExist.
                                type: string
                              scopeName:
                                description: The name of the scope that the selector applies to.
                                type: string
                              values:
                                description: An array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
                                type: array
                                items:
                                  type: string
                    scopes:
                      description: A collection of filters that must match each object tracked by a quota. If not specified, the quota matches all objects.
                      type: array
                      items:
                        description: A ResourceQuotaScope defines a filter that must match each object tracked by a quota
                        type: string
                selector:
                  description: Selector is the selector used to match projects. It should only select active projects on the scale of dozens (though it can select many more less active projects).  These projects will contend on object creation through this resource.
                  type: object
                  properties:
                    annotations:
                      description: AnnotationSelector is used to select projects by annotation.
                      type: object
                      additionalProperties:
                        type: string
                      nullable: true
                    labels:
                      description: LabelSelector is used to select projects by label.
                      type: object
                      properties:
                        matchExpressions:
                          description: matchExpressions is a list of label selector requirements. The requirements are ANDed.
                          type: array
                          items:
                            description: A label selector requirement is a selector that contains values, a key, and an operator that relates the key and values.
                            type: object
                            required:
                              - key
                              - operator
                            properties:
                              key:
                                description: key is the label key that the selector applies to.
                                type: string
                              operator:
                                description: operator represents a key's relationship to a set of values. Valid operators are In, NotIn, Exists and DoesNotExist.
                                type: string
                              values:
                                description: values is an array of string values. If the operator is In or NotIn, the values array must be non-empty. If the operator is Exists or DoesNotExist, the values array must be empty. This array is replaced during a strategic merge patch.
                                type: array
                                items:
                                  type: string
                        matchLabels:
                          description: matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
                          type: object
                          additionalProperties:
                            type: string
                      nullable: true
            status:
              description: Status defines the actual enforced quota and its current usage
              type: object
              required:
                - total
              properties:
                namespaces:
                  description: Namespaces slices the usage by project.  This division allows for quick resolution of deletion reconciliation inside of a single project without requiring a recalculation across all projects.  This can be used to pull the deltas for a given project.
                  type: array
                  items:
                    description: ResourceQuotaStatusByNamespace gives status for a particular project
                    type: object
                    required:
                      - namespace
                      - status
                    properties:
                      namespace:
                        description: Namespace the project this status applies to
                        type: string
                      status:
                        description: Status indicates how many resources have been consumed by this project
                        type: object
                        properties:
                          hard:
                            description: 'Hard is the set of enforced hard limits for each named resource. More info: https://kubernetes.io/docs/concepts/policy/resource-quotas/'
                            type: object
                            additionalProperties:
                              pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                              anyOf:
                                - type: integer
                                - type: string
                              x-kubernetes-int-or-string: true
                          used:
                            description: Used is the current observed total usage of the resource in the namespace.
                            type: object
                            additionalProperties:
                              pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                              anyOf:
                                - type: integer
                                - type: string
                              x-kubernetes-int-or-string: true
                  nullable: true
                total:
                  description: Total defines the actual enforced quota and its current usage across all projects
                  type: object
                  properties:
                    hard:
                      description: 'Hard is the set of enforced hard limits for each named resource. More info: https://kubernetes.io/docs/concepts/policy/resource-quotas/'
                      type: object
                      additionalProperties:
                        pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                        anyOf:
                          - type: integer
                          - type: string
                        x-kubernetes-int-or-string: true
                    used:
                      description: Used is the current observed total usage of the resource in the namespace.
                      type: object
                      additionalProperties:
                        pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                        anyOf:
                          - type: integer
                          - type: string
                        x-kubernetes-int-or-string: true
      served: true
      storage: true
      subresources:
        status: {}
`)

func assetsCrd0000_03_quotaOpenshift_01_clusterresourcequotaCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_03_quotaOpenshift_01_clusterresourcequotaCrdYaml, nil
}

func assetsCrd0000_03_quotaOpenshift_01_clusterresourcequotaCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_03_quotaOpenshift_01_clusterresourcequotaCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_03_quota-openshift_01_clusterresourcequota.crd.yaml", size: 11773, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_03_securityOpenshift_01_sccCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/470
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: securitycontextconstraints.security.openshift.io
spec:
  group: security.openshift.io
  names:
    kind: SecurityContextConstraints
    listKind: SecurityContextConstraintsList
    plural: securitycontextconstraints
    singular: securitycontextconstraints
  scope: Cluster
  versions:
    - additionalPrinterColumns:
        - description: Determines if a container can request to be run as privileged
          jsonPath: .allowPrivilegedContainer
          name: Priv
          type: string
        - description: A list of capabilities that can be requested to add to the container
          jsonPath: .allowedCapabilities
          name: Caps
          type: string
        - description: Strategy that will dictate what labels will be set in the SecurityContext
          jsonPath: .seLinuxContext.type
          name: SELinux
          type: string
        - description: Strategy that will dictate what RunAsUser is used in the SecurityContext
          jsonPath: .runAsUser.type
          name: RunAsUser
          type: string
        - description: Strategy that will dictate what fs group is used by the SecurityContext
          jsonPath: .fsGroup.type
          name: FSGroup
          type: string
        - description: Strategy that will dictate what supplemental groups are used by the SecurityContext
          jsonPath: .supplementalGroups.type
          name: SupGroup
          type: string
        - description: Sort order of SCCs
          jsonPath: .priority
          name: Priority
          type: string
        - description: Force containers to run with a read only root file system
          jsonPath: .readOnlyRootFilesystem
          name: ReadOnlyRootFS
          type: string
        - description: White list of allowed volume plugins
          jsonPath: .volumes
          name: Volumes
          type: string
      name: v1
      schema:
        openAPIV3Schema:
          description: "SecurityContextConstraints governs the ability to make requests that affect the SecurityContext that will be applied to a container. For historical reasons SCC was exposed under the core Kubernetes API group. That exposure is deprecated and will be removed in a future release - users should instead use the security.openshift.io group to manage SecurityContextConstraints. \n Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer)."
          type: object
          required:
            - allowHostDirVolumePlugin
            - allowHostIPC
            - allowHostNetwork
            - allowHostPID
            - allowHostPorts
            - allowPrivilegedContainer
            - allowedCapabilities
            - defaultAddCapabilities
            - priority
            - readOnlyRootFilesystem
            - requiredDropCapabilities
            - volumes
          properties:
            allowHostDirVolumePlugin:
              description: AllowHostDirVolumePlugin determines if the policy allow containers to use the HostDir volume plugin
              type: boolean
            allowHostIPC:
              description: AllowHostIPC determines if the policy allows host ipc in the containers.
              type: boolean
            allowHostNetwork:
              description: AllowHostNetwork determines if the policy allows the use of HostNetwork in the pod spec.
              type: boolean
            allowHostPID:
              description: AllowHostPID determines if the policy allows host pid in the containers.
              type: boolean
            allowHostPorts:
              description: AllowHostPorts determines if the policy allows host ports in the containers.
              type: boolean
            allowPrivilegeEscalation:
              description: AllowPrivilegeEscalation determines if a pod can request to allow privilege escalation. If unspecified, defaults to true.
              type: boolean
              nullable: true
            allowPrivilegedContainer:
              description: AllowPrivilegedContainer determines if a container can request to be run as privileged.
              type: boolean
            allowedCapabilities:
              description: AllowedCapabilities is a list of capabilities that can be requested to add to the container. Capabilities in this field maybe added at the pod author's discretion. You must not list a capability in both AllowedCapabilities and RequiredDropCapabilities. To allow all capabilities you may use '*'.
              type: array
              items:
                description: Capability represent POSIX capabilities type
                type: string
              nullable: true
            allowedFlexVolumes:
              description: AllowedFlexVolumes is a whitelist of allowed Flexvolumes.  Empty or nil indicates that all Flexvolumes may be used.  This parameter is effective only when the usage of the Flexvolumes is allowed in the "Volumes" field.
              type: array
              items:
                description: AllowedFlexVolume represents a single Flexvolume that is allowed to be used.
                type: object
                required:
                  - driver
                properties:
                  driver:
                    description: Driver is the name of the Flexvolume driver.
                    type: string
              nullable: true
            allowedUnsafeSysctls:
              description: "AllowedUnsafeSysctls is a list of explicitly allowed unsafe sysctls, defaults to none. Each entry is either a plain sysctl name or ends in \"*\" in which case it is considered as a prefix of allowed sysctls. Single * means all unsafe sysctls are allowed. Kubelet has to whitelist all allowed unsafe sysctls explicitly to avoid rejection. \n Examples: e.g. \"foo/*\" allows \"foo/bar\", \"foo/baz\", etc. e.g. \"foo.*\" allows \"foo.bar\", \"foo.baz\", etc."
              type: array
              items:
                type: string
              nullable: true
            apiVersion:
              description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
              type: string
            defaultAddCapabilities:
              description: DefaultAddCapabilities is the default set of capabilities that will be added to the container unless the pod spec specifically drops the capability.  You may not list a capabiility in both DefaultAddCapabilities and RequiredDropCapabilities.
              type: array
              items:
                description: Capability represent POSIX capabilities type
                type: string
              nullable: true
            defaultAllowPrivilegeEscalation:
              description: DefaultAllowPrivilegeEscalation controls the default setting for whether a process can gain more privileges than its parent process.
              type: boolean
              nullable: true
            forbiddenSysctls:
              description: "ForbiddenSysctls is a list of explicitly forbidden sysctls, defaults to none. Each entry is either a plain sysctl name or ends in \"*\" in which case it is considered as a prefix of forbidden sysctls. Single * means all sysctls are forbidden. \n Examples: e.g. \"foo/*\" forbids \"foo/bar\", \"foo/baz\", etc. e.g. \"foo.*\" forbids \"foo.bar\", \"foo.baz\", etc."
              type: array
              items:
                type: string
              nullable: true
            fsGroup:
              description: FSGroup is the strategy that will dictate what fs group is used by the SecurityContext.
              type: object
              properties:
                ranges:
                  description: Ranges are the allowed ranges of fs groups.  If you would like to force a single fs group then supply a single range with the same start and end.
                  type: array
                  items:
                    description: 'IDRange provides a min/max of an allowed range of IDs. TODO: this could be reused for UIDs.'
                    type: object
                    properties:
                      max:
                        description: Max is the end of the range, inclusive.
                        type: integer
                        format: int64
                      min:
                        description: Min is the start of the range, inclusive.
                        type: integer
                        format: int64
                type:
                  description: Type is the strategy that will dictate what FSGroup is used in the SecurityContext.
                  type: string
              nullable: true
            groups:
              description: The groups that have permission to use this security context constraints
              type: array
              items:
                type: string
              nullable: true
            kind:
              description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
              type: string
            metadata:
              type: object
            priority:
              description: Priority influences the sort order of SCCs when evaluating which SCCs to try first for a given pod request based on access in the Users and Groups fields.  The higher the int, the higher priority. An unset value is considered a 0 priority. If scores for multiple SCCs are equal they will be sorted from most restrictive to least restrictive. If both priorities and restrictions are equal the SCCs will be sorted by name.
              type: integer
              format: int32
              nullable: true
            readOnlyRootFilesystem:
              description: ReadOnlyRootFilesystem when set to true will force containers to run with a read only root file system.  If the container specifically requests to run with a non-read only root file system the SCC should deny the pod. If set to false the container may run with a read only root file system if it wishes but it will not be forced to.
              type: boolean
            requiredDropCapabilities:
              description: RequiredDropCapabilities are the capabilities that will be dropped from the container.  These are required to be dropped and cannot be added.
              type: array
              items:
                description: Capability represent POSIX capabilities type
                type: string
              nullable: true
            runAsUser:
              description: RunAsUser is the strategy that will dictate what RunAsUser is used in the SecurityContext.
              type: object
              properties:
                type:
                  description: Type is the strategy that will dictate what RunAsUser is used in the SecurityContext.
                  type: string
                uid:
                  description: UID is the user id that containers must run as.  Required for the MustRunAs strategy if not using namespace/service account allocated uids.
                  type: integer
                  format: int64
                uidRangeMax:
                  description: UIDRangeMax defines the max value for a strategy that allocates by range.
                  type: integer
                  format: int64
                uidRangeMin:
                  description: UIDRangeMin defines the min value for a strategy that allocates by range.
                  type: integer
                  format: int64
              nullable: true
            seLinuxContext:
              description: SELinuxContext is the strategy that will dictate what labels will be set in the SecurityContext.
              type: object
              properties:
                seLinuxOptions:
                  description: seLinuxOptions required to run as; required for MustRunAs
                  type: object
                  properties:
                    level:
                      description: Level is SELinux level label that applies to the container.
                      type: string
                    role:
                      description: Role is a SELinux role label that applies to the container.
                      type: string
                    type:
                      description: Type is a SELinux type label that applies to the container.
                      type: string
                    user:
                      description: User is a SELinux user label that applies to the container.
                      type: string
                type:
                  description: Type is the strategy that will dictate what SELinux context is used in the SecurityContext.
                  type: string
              nullable: true
            seccompProfiles:
              description: "SeccompProfiles lists the allowed profiles that may be set for the pod or container's seccomp annotations.  An unset (nil) or empty value means that no profiles may be specifid by the pod or container.\tThe wildcard '*' may be used to allow all profiles.  When used to generate a value for a pod the first non-wildcard profile will be used as the default."
              type: array
              items:
                type: string
              nullable: true
            supplementalGroups:
              description: SupplementalGroups is the strategy that will dictate what supplemental groups are used by the SecurityContext.
              type: object
              properties:
                ranges:
                  description: Ranges are the allowed ranges of supplemental groups.  If you would like to force a single supplemental group then supply a single range with the same start and end.
                  type: array
                  items:
                    description: 'IDRange provides a min/max of an allowed range of IDs. TODO: this could be reused for UIDs.'
                    type: object
                    properties:
                      max:
                        description: Max is the end of the range, inclusive.
                        type: integer
                        format: int64
                      min:
                        description: Min is the start of the range, inclusive.
                        type: integer
                        format: int64
                type:
                  description: Type is the strategy that will dictate what supplemental groups is used in the SecurityContext.
                  type: string
              nullable: true
            users:
              description: The users who have permissions to use this security context constraints
              type: array
              items:
                type: string
              nullable: true
            volumes:
              description: Volumes is a white list of allowed volume plugins.  FSType corresponds directly with the field names of a VolumeSource (azureFile, configMap, emptyDir).  To allow all volumes you may use "*". To allow no volumes, set to ["none"].
              type: array
              items:
                description: FS Type gives strong typing to different file systems that are used by volumes.
                type: string
              nullable: true
      served: true
      storage: true
`)

func assetsCrd0000_03_securityOpenshift_01_sccCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_03_securityOpenshift_01_sccCrdYaml, nil
}

func assetsCrd0000_03_securityOpenshift_01_sccCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_03_securityOpenshift_01_sccCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_03_security-openshift_01_scc.crd.yaml", size: 16010, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_10_configOperator_01_buildCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/470
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: builds.config.openshift.io
spec:
  group: config.openshift.io
  names:
    kind: Build
    listKind: BuildList
    plural: builds
    singular: build
  preserveUnknownFields: false
  scope: Cluster
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          description: "Build configures the behavior of OpenShift builds for the entire cluster. This includes default settings that can be overridden in BuildConfig objects, and overrides which are applied to all builds. \n The canonical name is \"cluster\" \n Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer)."
          type: object
          required:
            - spec
          properties:
            apiVersion:
              description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
              type: string
            kind:
              description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
              type: string
            metadata:
              type: object
            spec:
              description: Spec holds user-settable values for the build controller configuration
              type: object
              properties:
                additionalTrustedCA:
                  description: "AdditionalTrustedCA is a reference to a ConfigMap containing additional CAs that should be trusted for image pushes and pulls during builds. The namespace for this config map is openshift-config. \n DEPRECATED: Additional CAs for image pull and push should be set on image.config.openshift.io/cluster instead."
                  type: object
                  required:
                    - name
                  properties:
                    name:
                      description: name is the metadata.name of the referenced config map
                      type: string
                buildDefaults:
                  description: BuildDefaults controls the default information for Builds
                  type: object
                  properties:
                    defaultProxy:
                      description: "DefaultProxy contains the default proxy settings for all build operations, including image pull/push and source download. \n Values can be overrode by setting the ` + "`" + `HTTP_PROXY` + "`" + `, ` + "`" + `HTTPS_PROXY` + "`" + `, and ` + "`" + `NO_PROXY` + "`" + ` environment variables in the build config's strategy."
                      type: object
                      properties:
                        httpProxy:
                          description: httpProxy is the URL of the proxy for HTTP requests.  Empty means unset and will not result in an env var.
                          type: string
                        httpsProxy:
                          description: httpsProxy is the URL of the proxy for HTTPS requests.  Empty means unset and will not result in an env var.
                          type: string
                        noProxy:
                          description: noProxy is a comma-separated list of hostnames and/or CIDRs and/or IPs for which the proxy should not be used. Empty means unset and will not result in an env var.
                          type: string
                        readinessEndpoints:
                          description: readinessEndpoints is a list of endpoints used to verify readiness of the proxy.
                          type: array
                          items:
                            type: string
                        trustedCA:
                          description: "trustedCA is a reference to a ConfigMap containing a CA certificate bundle. The trustedCA field should only be consumed by a proxy validator. The validator is responsible for reading the certificate bundle from the required key \"ca-bundle.crt\", merging it with the system default trust bundle, and writing the merged trust bundle to a ConfigMap named \"trusted-ca-bundle\" in the \"openshift-config-managed\" namespace. Clients that expect to make proxy connections must use the trusted-ca-bundle for all HTTPS requests to the proxy, and may use the trusted-ca-bundle for non-proxy HTTPS requests as well. \n The namespace for the ConfigMap referenced by trustedCA is \"openshift-config\". Here is an example ConfigMap (in yaml): \n apiVersion: v1 kind: ConfigMap metadata:  name: user-ca-bundle  namespace: openshift-config  data:    ca-bundle.crt: |      -----BEGIN CERTIFICATE-----      Custom CA certificate bundle.      -----END CERTIFICATE-----"
                          type: object
                          required:
                            - name
                          properties:
                            name:
                              description: name is the metadata.name of the referenced config map
                              type: string
                    env:
                      description: Env is a set of default environment variables that will be applied to the build if the specified variables do not exist on the build
                      type: array
                      items:
                        description: EnvVar represents an environment variable present in a Container.
                        type: object
                        required:
                          - name
                        properties:
                          name:
                            description: Name of the environment variable. Must be a C_IDENTIFIER.
                            type: string
                          value:
                            description: 'Variable references $(VAR_NAME) are expanded using the previously defined environment variables in the container and any service environment variables. If a variable cannot be resolved, the reference in the input string will be unchanged. Double $$ are reduced to a single $, which allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will produce the string literal "$(VAR_NAME)". Escaped references will never be expanded, regardless of whether the variable exists or not. Defaults to "".'
                            type: string
                          valueFrom:
                            description: Source for the environment variable's value. Cannot be used if value is not empty.
                            type: object
                            properties:
                              configMapKeyRef:
                                description: Selects a key of a ConfigMap.
                                type: object
                                required:
                                  - key
                                properties:
                                  key:
                                    description: The key to select.
                                    type: string
                                  name:
                                    description: 'Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?'
                                    type: string
                                  optional:
                                    description: Specify whether the ConfigMap or its key must be defined
                                    type: boolean
                              fieldRef:
                                description: 'Selects a field of the pod: supports metadata.name, metadata.namespace, ` + "`" + `metadata.labels[''<KEY>'']` + "`" + `, ` + "`" + `metadata.annotations[''<KEY>'']` + "`" + `, spec.nodeName, spec.serviceAccountName, status.hostIP, status.podIP, status.podIPs.'
                                type: object
                                required:
                                  - fieldPath
                                properties:
                                  apiVersion:
                                    description: Version of the schema the FieldPath is written in terms of, defaults to "v1".
                                    type: string
                                  fieldPath:
                                    description: Path of the field to select in the specified API version.
                                    type: string
                              resourceFieldRef:
                                description: 'Selects a resource of the container: only resources limits and requests (limits.cpu, limits.memory, limits.ephemeral-storage, requests.cpu, requests.memory and requests.ephemeral-storage) are currently supported.'
                                type: object
                                required:
                                  - resource
                                properties:
                                  containerName:
                                    description: 'Container name: required for volumes, optional for env vars'
                                    type: string
                                  divisor:
                                    description: Specifies the output format of the exposed resources, defaults to "1"
                                    pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                                    anyOf:
                                      - type: integer
                                      - type: string
                                    x-kubernetes-int-or-string: true
                                  resource:
                                    description: 'Required: resource to select'
                                    type: string
                              secretKeyRef:
                                description: Selects a key of a secret in the pod's namespace
                                type: object
                                required:
                                  - key
                                properties:
                                  key:
                                    description: The key of the secret to select from.  Must be a valid secret key.
                                    type: string
                                  name:
                                    description: 'Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names TODO: Add other useful fields. apiVersion, kind, uid?'
                                    type: string
                                  optional:
                                    description: Specify whether the Secret or its key must be defined
                                    type: boolean
                    gitProxy:
                      description: "GitProxy contains the proxy settings for git operations only. If set, this will override any Proxy settings for all git commands, such as git clone. \n Values that are not set here will be inherited from DefaultProxy."
                      type: object
                      properties:
                        httpProxy:
                          description: httpProxy is the URL of the proxy for HTTP requests.  Empty means unset and will not result in an env var.
                          type: string
                        httpsProxy:
                          description: httpsProxy is the URL of the proxy for HTTPS requests.  Empty means unset and will not result in an env var.
                          type: string
                        noProxy:
                          description: noProxy is a comma-separated list of hostnames and/or CIDRs and/or IPs for which the proxy should not be used. Empty means unset and will not result in an env var.
                          type: string
                        readinessEndpoints:
                          description: readinessEndpoints is a list of endpoints used to verify readiness of the proxy.
                          type: array
                          items:
                            type: string
                        trustedCA:
                          description: "trustedCA is a reference to a ConfigMap containing a CA certificate bundle. The trustedCA field should only be consumed by a proxy validator. The validator is responsible for reading the certificate bundle from the required key \"ca-bundle.crt\", merging it with the system default trust bundle, and writing the merged trust bundle to a ConfigMap named \"trusted-ca-bundle\" in the \"openshift-config-managed\" namespace. Clients that expect to make proxy connections must use the trusted-ca-bundle for all HTTPS requests to the proxy, and may use the trusted-ca-bundle for non-proxy HTTPS requests as well. \n The namespace for the ConfigMap referenced by trustedCA is \"openshift-config\". Here is an example ConfigMap (in yaml): \n apiVersion: v1 kind: ConfigMap metadata:  name: user-ca-bundle  namespace: openshift-config  data:    ca-bundle.crt: |      -----BEGIN CERTIFICATE-----      Custom CA certificate bundle.      -----END CERTIFICATE-----"
                          type: object
                          required:
                            - name
                          properties:
                            name:
                              description: name is the metadata.name of the referenced config map
                              type: string
                    imageLabels:
                      description: ImageLabels is a list of docker labels that are applied to the resulting image. User can override a default label by providing a label with the same name in their Build/BuildConfig.
                      type: array
                      items:
                        type: object
                        properties:
                          name:
                            description: Name defines the name of the label. It must have non-zero length.
                            type: string
                          value:
                            description: Value defines the literal value of the label.
                            type: string
                    resources:
                      description: Resources defines resource requirements to execute the build.
                      type: object
                      properties:
                        limits:
                          description: 'Limits describes the maximum amount of compute resources allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/'
                          type: object
                          additionalProperties:
                            pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                            anyOf:
                              - type: integer
                              - type: string
                            x-kubernetes-int-or-string: true
                        requests:
                          description: 'Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/'
                          type: object
                          additionalProperties:
                            pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                            anyOf:
                              - type: integer
                              - type: string
                            x-kubernetes-int-or-string: true
                buildOverrides:
                  description: BuildOverrides controls override settings for builds
                  type: object
                  properties:
                    forcePull:
                      description: ForcePull overrides, if set, the equivalent value in the builds, i.e. false disables force pull for all builds, true enables force pull for all builds, independently of what each build specifies itself
                      type: boolean
                    imageLabels:
                      description: ImageLabels is a list of docker labels that are applied to the resulting image. If user provided a label in their Build/BuildConfig with the same name as one in this list, the user's label will be overwritten.
                      type: array
                      items:
                        type: object
                        properties:
                          name:
                            description: Name defines the name of the label. It must have non-zero length.
                            type: string
                          value:
                            description: Value defines the literal value of the label.
                            type: string
                    nodeSelector:
                      description: NodeSelector is a selector which must be true for the build pod to fit on a node
                      type: object
                      additionalProperties:
                        type: string
                    tolerations:
                      description: Tolerations is a list of Tolerations that will override any existing tolerations set on a build pod.
                      type: array
                      items:
                        description: The pod this Toleration is attached to tolerates any taint that matches the triple <key,value,effect> using the matching operator <operator>.
                        type: object
                        properties:
                          effect:
                            description: Effect indicates the taint effect to match. Empty means match all taint effects. When specified, allowed values are NoSchedule, PreferNoSchedule and NoExecute.
                            type: string
                          key:
                            description: Key is the taint key that the toleration applies to. Empty means match all taint keys. If the key is empty, operator must be Exists; this combination means to match all values and all keys.
                            type: string
                          operator:
                            description: Operator represents a key's relationship to the value. Valid operators are Exists and Equal. Defaults to Equal. Exists is equivalent to wildcard for value, so that a pod can tolerate all taints of a particular category.
                            type: string
                          tolerationSeconds:
                            description: TolerationSeconds represents the period of time the toleration (which must be of effect NoExecute, otherwise this field is ignored) tolerates the taint. By default, it is not set, which means tolerate the taint forever (do not evict). Zero and negative values will be treated as 0 (evict immediately) by the system.
                            type: integer
                            format: int64
                          value:
                            description: Value is the taint value the toleration matches to. If the operator is Exists, the value should be empty, otherwise just a regular string.
                            type: string
      served: true
      storage: true
      subresources:
        status: {}
`)

func assetsCrd0000_10_configOperator_01_buildCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_10_configOperator_01_buildCrdYaml, nil
}

func assetsCrd0000_10_configOperator_01_buildCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_10_configOperator_01_buildCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_10_config-operator_01_build.crd.yaml", size: 20246, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_10_configOperator_01_featuregateCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/470
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: featuregates.config.openshift.io
spec:
  group: config.openshift.io
  names:
    kind: FeatureGate
    listKind: FeatureGateList
    plural: featuregates
    singular: featuregate
  scope: Cluster
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          description: "Feature holds cluster-wide information about feature gates.  The canonical name is ` + "`" + `cluster` + "`" + ` \n Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer)."
          type: object
          required:
            - spec
          properties:
            apiVersion:
              description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
              type: string
            kind:
              description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
              type: string
            metadata:
              type: object
            spec:
              description: spec holds user settable values for configuration
              type: object
              properties:
                customNoUpgrade:
                  description: customNoUpgrade allows the enabling or disabling of any feature. Turning this feature set on IS NOT SUPPORTED, CANNOT BE UNDONE, and PREVENTS UPGRADES. Because of its nature, this setting cannot be validated.  If you have any typos or accidentally apply invalid combinations your cluster may fail in an unrecoverable way.  featureSet must equal "CustomNoUpgrade" must be set to use this field.
                  type: object
                  properties:
                    disabled:
                      description: disabled is a list of all feature gates that you want to force off
                      type: array
                      items:
                        type: string
                    enabled:
                      description: enabled is a list of all feature gates that you want to force on
                      type: array
                      items:
                        type: string
                  nullable: true
                featureSet:
                  description: featureSet changes the list of features in the cluster.  The default is empty.  Be very careful adjusting this setting. Turning on or off features may cause irreversible changes in your cluster which cannot be undone.
                  type: string
            status:
              description: status holds observed values from the cluster. They may not be overridden.
              type: object
      served: true
      storage: true
      subresources:
        status: {}
`)

func assetsCrd0000_10_configOperator_01_featuregateCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_10_configOperator_01_featuregateCrdYaml, nil
}

func assetsCrd0000_10_configOperator_01_featuregateCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_10_configOperator_01_featuregateCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_10_config-operator_01_featuregate.crd.yaml", size: 3438, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_10_configOperator_01_imageCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/470
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: images.config.openshift.io
spec:
  group: config.openshift.io
  names:
    kind: Image
    listKind: ImageList
    plural: images
    singular: image
  scope: Cluster
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          description: "Image governs policies related to imagestream imports and runtime configuration for external registries. It allows cluster admins to configure which registries OpenShift is allowed to import images from, extra CA trust bundles for external registries, and policies to block or allow registry hostnames. When exposing OpenShift's image registry to the public, this also lets cluster admins specify the external hostname. \n Compatibility level 1: Stable within a major release for a minimum of 12 months or 3 minor releases (whichever is longer)."
          type: object
          required:
            - spec
          properties:
            apiVersion:
              description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
              type: string
            kind:
              description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
              type: string
            metadata:
              type: object
            spec:
              description: spec holds user settable values for configuration
              type: object
              properties:
                additionalTrustedCA:
                  description: additionalTrustedCA is a reference to a ConfigMap containing additional CAs that should be trusted during imagestream import, pod image pull, build image pull, and imageregistry pullthrough. The namespace for this config map is openshift-config.
                  type: object
                  required:
                    - name
                  properties:
                    name:
                      description: name is the metadata.name of the referenced config map
                      type: string
                allowedRegistriesForImport:
                  description: allowedRegistriesForImport limits the container image registries that normal users may import images from. Set this list to the registries that you trust to contain valid Docker images and that you want applications to be able to import from. Users with permission to create Images or ImageStreamMappings via the API are not affected by this policy - typically only administrators or system integrations will have those permissions.
                  type: array
                  items:
                    description: RegistryLocation contains a location of the registry specified by the registry domain name. The domain name might include wildcards, like '*' or '??'.
                    type: object
                    properties:
                      domainName:
                        description: domainName specifies a domain name for the registry In case the registry use non-standard (80 or 443) port, the port should be included in the domain name as well.
                        type: string
                      insecure:
                        description: insecure indicates whether the registry is secure (https) or insecure (http) By default (if not specified) the registry is assumed as secure.
                        type: boolean
                externalRegistryHostnames:
                  description: externalRegistryHostnames provides the hostnames for the default external image registry. The external hostname should be set only when the image registry is exposed externally. The first value is used in 'publicDockerImageRepository' field in ImageStreams. The value must be in "hostname[:port]" format.
                  type: array
                  items:
                    type: string
                registrySources:
                  description: registrySources contains configuration that determines how the container runtime should treat individual registries when accessing images for builds+pods. (e.g. whether or not to allow insecure access).  It does not contain configuration for the internal cluster registry.
                  type: object
                  properties:
                    allowedRegistries:
                      description: "allowedRegistries are the only registries permitted for image pull and push actions. All other registries are denied. \n Only one of BlockedRegistries or AllowedRegistries may be set."
                      type: array
                      items:
                        type: string
                    blockedRegistries:
                      description: "blockedRegistries cannot be used for image pull and push actions. All other registries are permitted. \n Only one of BlockedRegistries or AllowedRegistries may be set."
                      type: array
                      items:
                        type: string
                    containerRuntimeSearchRegistries:
                      description: 'containerRuntimeSearchRegistries are registries that will be searched when pulling images that do not have fully qualified domains in their pull specs. Registries will be searched in the order provided in the list. Note: this search list only works with the container runtime, i.e CRI-O. Will NOT work with builds or imagestream imports.'
                      type: array
                      format: hostname
                      minItems: 1
                      items:
                        type: string
                      x-kubernetes-list-type: set
                    insecureRegistries:
                      description: insecureRegistries are registries which do not have a valid TLS certificates or only support HTTP connections.
                      type: array
                      items:
                        type: string
            status:
              description: status holds observed values from the cluster. They may not be overridden.
              type: object
              properties:
                externalRegistryHostnames:
                  description: externalRegistryHostnames provides the hostnames for the default external image registry. The external hostname should be set only when the image registry is exposed externally. The first value is used in 'publicDockerImageRepository' field in ImageStreams. The value must be in "hostname[:port]" format.
                  type: array
                  items:
                    type: string
                internalRegistryHostname:
                  description: internalRegistryHostname sets the hostname for the default internal image registry. The value must be in "hostname[:port]" format. This value is set by the image registry operator which controls the internal registry hostname. For backward compatibility, users can still use OPENSHIFT_DEFAULT_REGISTRY environment variable but this setting overrides the environment variable.
                  type: string
      served: true
      storage: true
      subresources:
        status: {}
`)

func assetsCrd0000_10_configOperator_01_imageCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_10_configOperator_01_imageCrdYaml, nil
}

func assetsCrd0000_10_configOperator_01_imageCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_10_configOperator_01_imageCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_10_config-operator_01_image.crd.yaml", size: 7808, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_10_configOperator_01_imagecontentsourcepolicyCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/470
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: imagecontentsourcepolicies.operator.openshift.io
spec:
  group: operator.openshift.io
  names:
    kind: ImageContentSourcePolicy
    listKind: ImageContentSourcePolicyList
    plural: imagecontentsourcepolicies
    singular: imagecontentsourcepolicy
  scope: Cluster
  versions:
    - name: v1alpha1
      schema:
        openAPIV3Schema:
          description: "ImageContentSourcePolicy holds cluster-wide information about how to handle registry mirror rules. When multiple policies are defined, the outcome of the behavior is defined on each field. \n Compatibility level 4: No compatibility is provided, the API can change at any point for any reason. These capabilities should not be used by applications needing long term support."
          type: object
          required:
            - spec
          properties:
            apiVersion:
              description: 'APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
              type: string
            kind:
              description: 'Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
              type: string
            metadata:
              type: object
            spec:
              description: spec holds user settable values for configuration
              type: object
              properties:
                repositoryDigestMirrors:
                  description: "repositoryDigestMirrors allows images referenced by image digests in pods to be pulled from alternative mirrored repository locations. The image pull specification provided to the pod will be compared to the source locations described in RepositoryDigestMirrors and the image may be pulled down from any of the mirrors in the list instead of the specified repository allowing administrators to choose a potentially faster mirror. Only image pull specifications that have an image digest will have this behavior applied to them - tags will continue to be pulled from the specified repository in the pull spec. \n Each “source” repository is treated independently; configurations for different “source” repositories don’t interact. \n When multiple policies are defined for the same “source” repository, the sets of defined mirrors will be merged together, preserving the relative order of the mirrors, if possible. For example, if policy A has mirrors ` + "`" + `a, b, c` + "`" + ` and policy B has mirrors ` + "`" + `c, d, e` + "`" + `, the mirrors will be used in the order ` + "`" + `a, b, c, d, e` + "`" + `.  If the orders of mirror entries conflict (e.g. ` + "`" + `a, b` + "`" + ` vs. ` + "`" + `b, a` + "`" + `) the configuration is not rejected but the resulting order is unspecified."
                  type: array
                  items:
                    description: 'RepositoryDigestMirrors holds cluster-wide information about how to handle mirros in the registries config. Note: the mirrors only work when pulling the images that are referenced by their digests.'
                    type: object
                    required:
                      - source
                    properties:
                      mirrors:
                        description: mirrors is one or more repositories that may also contain the same images. The order of mirrors in this list is treated as the user's desired priority, while source is by default considered lower priority than all mirrors. Other cluster configuration, including (but not limited to) other repositoryDigestMirrors objects, may impact the exact order mirrors are contacted in, or some mirrors may be contacted in parallel, so this should be considered a preference rather than a guarantee of ordering.
                        type: array
                        items:
                          type: string
                      source:
                        description: source is the repository that users refer to, e.g. in image pull specifications.
                        type: string
      served: true
      storage: true
      subresources:
        status: {}
`)

func assetsCrd0000_10_configOperator_01_imagecontentsourcepolicyCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_10_configOperator_01_imagecontentsourcepolicyCrdYaml, nil
}

func assetsCrd0000_10_configOperator_01_imagecontentsourcepolicyCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_10_configOperator_01_imagecontentsourcepolicyCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_10_config-operator_01_imagecontentsourcepolicy.crd.yaml", size: 4754, mode: os.FileMode(436), modTime: time.Unix(1653646266, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsCrd0000_11_imageregistryConfigsCrdYaml = []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    api-approved.openshift.io: https://github.com/openshift/api/pull/519
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
  name: configs.imageregistry.operator.openshift.io
spec:
  group: imageregistry.operator.openshift.io
  names:
    kind: Config
    listKind: ConfigList
    plural: configs
    singular: config
  scope: Cluster
  versions:
  - name: v1
    schema:
      openAPIV3Schema:
        description: Config is the configuration object for a registry instance managed
          by the registry operator
        type: object
        required:
        - metadata
        - spec
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            description: ImageRegistrySpec defines the specs for the running registry.
            type: object
            required:
            - managementState
            - replicas
            properties:
              affinity:
                description: affinity is a group of node affinity scheduling rules
                  for the image registry pod(s).
                type: object
                properties:
                  nodeAffinity:
                    description: Describes node affinity scheduling rules for the
                      pod.
                    type: object
                    properties:
                      preferredDuringSchedulingIgnoredDuringExecution:
                        description: The scheduler will prefer to schedule pods to
                          nodes that satisfy the affinity expressions specified by
                          this field, but it may choose a node that violates one or
                          more of the expressions. The node that is most preferred
                          is the one with the greatest sum of weights, i.e. for each
                          node that meets all of the scheduling requirements (resource
                          request, requiredDuringScheduling affinity expressions,
                          etc.), compute a sum by iterating through the elements of
                          this field and adding "weight" to the sum if the node matches
                          the corresponding matchExpressions; the node(s) with the
                          highest sum are the most preferred.
                        type: array
                        items:
                          description: An empty preferred scheduling term matches
                            all objects with implicit weight 0 (i.e. it's a no-op).
                            A null preferred scheduling term matches no objects (i.e.
                            is also a no-op).
                          type: object
                          required:
                          - preference
                          - weight
                          properties:
                            preference:
                              description: A node selector term, associated with the
                                corresponding weight.
                              type: object
                              properties:
                                matchExpressions:
                                  description: A list of node selector requirements
                                    by node's labels.
                                  type: array
                                  items:
                                    description: A node selector requirement is a
                                      selector that contains values, a key, and an
                                      operator that relates the key and values.
                                    type: object
                                    required:
                                    - key
                                    - operator
                                    properties:
                                      key:
                                        description: The label key that the selector
                                          applies to.
                                        type: string
                                      operator:
                                        description: Represents a key's relationship
                                          to a set of values. Valid operators are
                                          In, NotIn, Exists, DoesNotExist. Gt, and
                                          Lt.
                                        type: string
                                      values:
                                        description: An array of string values. If
                                          the operator is In or NotIn, the values
                                          array must be non-empty. If the operator
                                          is Exists or DoesNotExist, the values array
                                          must be empty. If the operator is Gt or
                                          Lt, the values array must have a single
                                          element, which will be interpreted as an
                                          integer. This array is replaced during a
                                          strategic merge patch.
                                        type: array
                                        items:
                                          type: string
                                matchFields:
                                  description: A list of node selector requirements
                                    by node's fields.
                                  type: array
                                  items:
                                    description: A node selector requirement is a
                                      selector that contains values, a key, and an
                                      operator that relates the key and values.
                                    type: object
                                    required:
                                    - key
                                    - operator
                                    properties:
                                      key:
                                        description: The label key that the selector
                                          applies to.
                                        type: string
                                      operator:
                                        description: Represents a key's relationship
                                          to a set of values. Valid operators are
                                          In, NotIn, Exists, DoesNotExist. Gt, and
                                          Lt.
                                        type: string
                                      values:
                                        description: An array of string values. If
                                          the operator is In or NotIn, the values
                                          array must be non-empty. If the operator
                                          is Exists or DoesNotExist, the values array
                                          must be empty. If the operator is Gt or
                                          Lt, the values array must have a single
                                          element, which will be interpreted as an
                                          integer. This array is replaced during a
                                          strategic merge patch.
                                        type: array
                                        items:
                                          type: string
                            weight:
                              description: Weight associated with matching the corresponding
                                nodeSelectorTerm, in the range 1-100.
                              type: integer
                              format: int32
                      requiredDuringSchedulingIgnoredDuringExecution:
                        description: If the affinity requirements specified by this
                          field are not met at scheduling time, the pod will not be
                          scheduled onto the node. If the affinity requirements specified
                          by this field cease to be met at some point during pod execution
                          (e.g. due to an update), the system may or may not try to
                          eventually evict the pod from its node.
                        type: object
                        required:
                        - nodeSelectorTerms
                        properties:
                          nodeSelectorTerms:
                            description: Required. A list of node selector terms.
                              The terms are ORed.
                            type: array
                            items:
                              description: A null or empty node selector term matches
                                no objects. The requirements of them are ANDed. The
                                TopologySelectorTerm type implements a subset of the
                                NodeSelectorTerm.
                              type: object
                              properties:
                                matchExpressions:
                                  description: A list of node selector requirements
                                    by node's labels.
                                  type: array
                                  items:
                                    description: A node selector requirement is a
                                      selector that contains values, a key, and an
                                      operator that relates the key and values.
                                    type: object
                                    required:
                                    - key
                                    - operator
                                    properties:
                                      key:
                                        description: The label key that the selector
                                          applies to.
                                        type: string
                                      operator:
                                        description: Represents a key's relationship
                                          to a set of values. Valid operators are
                                          In, NotIn, Exists, DoesNotExist. Gt, and
                                          Lt.
                                        type: string
                                      values:
                                        description: An array of string values. If
                                          the operator is In or NotIn, the values
                                          array must be non-empty. If the operator
                                          is Exists or DoesNotExist, the values array
                                          must be empty. If the operator is Gt or
                                          Lt, the values array must have a single
                                          element, which will be interpreted as an
                                          integer. This array is replaced during a
                                          strategic merge patch.
                                        type: array
                                        items:
                                          type: string
                                matchFields:
                                  description: A list of node selector requirements
                                    by node's fields.
                                  type: array
                                  items:
                                    description: A node selector requirement is a
                                      selector that contains values, a key, and an
                                      operator that relates the key and values.
                                    type: object
                                    required:
                                    - key
                                    - operator
                                    properties:
                                      key:
                                        description: The label key that the selector
                                          applies to.
                                        type: string
                                      operator:
                                        description: Represents a key's relationship
                                          to a set of values. Valid operators are
                                          In, NotIn, Exists, DoesNotExist. Gt, and
                                          Lt.
                                        type: string
                                      values:
                                        description: An array of string values. If
                                          the operator is In or NotIn, the values
                                          array must be non-empty. If the operator
                                          is Exists or DoesNotExist, the values array
                                          must be empty. If the operator is Gt or
                                          Lt, the values array must have a single
                                          element, which will be interpreted as an
                                          integer. This array is replaced during a
                                          strategic merge patch.
                                        type: array
                                        items:
                                          type: string
                  podAffinity:
                    description: Describes pod affinity scheduling rules (e.g. co-locate
                      this pod in the same node, zone, etc. as some other pod(s)).
                    type: object
                    properties:
                      preferredDuringSchedulingIgnoredDuringExecution:
                        description: The scheduler will prefer to schedule pods to
                          nodes that satisfy the affinity expressions specified by
                          this field, but it may choose a node that violates one or
                          more of the expressions. The node that is most preferred
                          is the one with the greatest sum of weights, i.e. for each
                          node that meets all of the scheduling requirements (resource
                          request, requiredDuringScheduling affinity expressions,
                          etc.), compute a sum by iterating through the elements of
                          this field and adding "weight" to the sum if the node has
                          pods which matches the corresponding podAffinityTerm; the
                          node(s) with the highest sum are the most preferred.
                        type: array
                        items:
                          description: The weights of all of the matched WeightedPodAffinityTerm
                            fields are added per-node to find the most preferred node(s)
                          type: object
                          required:
                          - podAffinityTerm
                          - weight
                          properties:
                            podAffinityTerm:
                              description: Required. A pod affinity term, associated
                                with the corresponding weight.
                              type: object
                              required:
                              - topologyKey
                              properties:
                                labelSelector:
                                  description: A label query over a set of resources,
                                    in this case pods.
                                  type: object
                                  properties:
                                    matchExpressions:
                                      description: matchExpressions is a list of label
                                        selector requirements. The requirements are
                                        ANDed.
                                      type: array
                                      items:
                                        description: A label selector requirement
                                          is a selector that contains values, a key,
                                          and an operator that relates the key and
                                          values.
                                        type: object
                                        required:
                                        - key
                                        - operator
                                        properties:
                                          key:
                                            description: key is the label key that
                                              the selector applies to.
                                            type: string
                                          operator:
                                            description: operator represents a key's
                                              relationship to a set of values. Valid
                                              operators are In, NotIn, Exists and
                                              DoesNotExist.
                                            type: string
                                          values:
                                            description: values is an array of string
                                              values. If the operator is In or NotIn,
                                              the values array must be non-empty.
                                              If the operator is Exists or DoesNotExist,
                                              the values array must be empty. This
                                              array is replaced during a strategic
                                              merge patch.
                                            type: array
                                            items:
                                              type: string
                                    matchLabels:
                                      description: matchLabels is a map of {key,value}
                                        pairs. A single {key,value} in the matchLabels
                                        map is equivalent to an element of matchExpressions,
                                        whose key field is "key", the operator is
                                        "In", and the values array contains only "value".
                                        The requirements are ANDed.
                                      type: object
                                      additionalProperties:
                                        type: string
                                namespaceSelector:
                                  description: A label query over the set of namespaces
                                    that the term applies to. The term is applied
                                    to the union of the namespaces selected by this
                                    field and the ones listed in the namespaces field.
                                    null selector and null or empty namespaces list
                                    means "this pod's namespace". An empty selector
                                    ({}) matches all namespaces. This field is alpha-level
                                    and is only honored when PodAffinityNamespaceSelector
                                    feature is enabled.
                                  type: object
                                  properties:
                                    matchExpressions:
                                      description: matchExpressions is a list of label
                                        selector requirements. The requirements are
                                        ANDed.
                                      type: array
                                      items:
                                        description: A label selector requirement
                                          is a selector that contains values, a key,
                                          and an operator that relates the key and
                                          values.
                                        type: object
                                        required:
                                        - key
                                        - operator
                                        properties:
                                          key:
                                            description: key is the label key that
                                              the selector applies to.
                                            type: string
                                          operator:
                                            description: operator represents a key's
                                              relationship to a set of values. Valid
                                              operators are In, NotIn, Exists and
                                              DoesNotExist.
                                            type: string
                                          values:
                                            description: values is an array of string
                                              values. If the operator is In or NotIn,
                                              the values array must be non-empty.
                                              If the operator is Exists or DoesNotExist,
                                              the values array must be empty. This
                                              array is replaced during a strategic
                                              merge patch.
                                            type: array
                                            items:
                                              type: string
                                    matchLabels:
                                      description: matchLabels is a map of {key,value}
                                        pairs. A single {key,value} in the matchLabels
                                        map is equivalent to an element of matchExpressions,
                                        whose key field is "key", the operator is
                                        "In", and the values array contains only "value".
                                        The requirements are ANDed.
                                      type: object
                                      additionalProperties:
                                        type: string
                                namespaces:
                                  description: namespaces specifies a static list
                                    of namespace names that the term applies to. The
                                    term is applied to the union of the namespaces
                                    listed in this field and the ones selected by
                                    namespaceSelector. null or empty namespaces list
                                    and null namespaceSelector means "this pod's namespace"
                                  type: array
                                  items:
                                    type: string
                                topologyKey:
                                  description: This pod should be co-located (affinity)
                                    or not co-located (anti-affinity) with the pods
                                    matching the labelSelector in the specified namespaces,
                                    where co-located is defined as running on a node
                                    whose value of the label with key topologyKey
                                    matches that of any node on which any of the selected
                                    pods is running. Empty topologyKey is not allowed.
                                  type: string
                            weight:
                              description: weight associated with matching the corresponding
                                podAffinityTerm, in the range 1-100.
                              type: integer
                              format: int32
                      requiredDuringSchedulingIgnoredDuringExecution:
                        description: If the affinity requirements specified by this
                          field are not met at scheduling time, the pod will not be
                          scheduled onto the node. If the affinity requirements specified
                          by this field cease to be met at some point during pod execution
                          (e.g. due to a pod label update), the system may or may
                          not try to eventually evict the pod from its node. When
                          there are multiple elements, the lists of nodes corresponding
                          to each podAffinityTerm are intersected, i.e. all terms
                          must be satisfied.
                        type: array
                        items:
                          description: Defines a set of pods (namely those matching
                            the labelSelector relative to the given namespace(s))
                            that this pod should be co-located (affinity) or not co-located
                            (anti-affinity) with, where co-located is defined as running
                            on a node whose value of the label with key <topologyKey>
                            matches that of any node on which a pod of the set of
                            pods is running
                          type: object
                          required:
                          - topologyKey
                          properties:
                            labelSelector:
                              description: A label query over a set of resources,
                                in this case pods.
                              type: object
                              properties:
                                matchExpressions:
                                  description: matchExpressions is a list of label
                                    selector requirements. The requirements are ANDed.
                                  type: array
                                  items:
                                    description: A label selector requirement is a
                                      selector that contains values, a key, and an
                                      operator that relates the key and values.
                                    type: object
                                    required:
                                    - key
                                    - operator
                                    properties:
                                      key:
                                        description: key is the label key that the
                                          selector applies to.
                                        type: string
                                      operator:
                                        description: operator represents a key's relationship
                                          to a set of values. Valid operators are
                                          In, NotIn, Exists and DoesNotExist.
                                        type: string
                                      values:
                                        description: values is an array of string
                                          values. If the operator is In or NotIn,
                                          the values array must be non-empty. If the
                                          operator is Exists or DoesNotExist, the
                                          values array must be empty. This array is
                                          replaced during a strategic merge patch.
                                        type: array
                                        items:
                                          type: string
                                matchLabels:
                                  description: matchLabels is a map of {key,value}
                                    pairs. A single {key,value} in the matchLabels
                                    map is equivalent to an element of matchExpressions,
                                    whose key field is "key", the operator is "In",
                                    and the values array contains only "value". The
                                    requirements are ANDed.
                                  type: object
                                  additionalProperties:
                                    type: string
                            namespaceSelector:
                              description: A label query over the set of namespaces
                                that the term applies to. The term is applied to the
                                union of the namespaces selected by this field and
                                the ones listed in the namespaces field. null selector
                                and null or empty namespaces list means "this pod's
                                namespace". An empty selector ({}) matches all namespaces.
                                This field is alpha-level and is only honored when
                                PodAffinityNamespaceSelector feature is enabled.
                              type: object
                              properties:
                                matchExpressions:
                                  description: matchExpressions is a list of label
                                    selector requirements. The requirements are ANDed.
                                  type: array
                                  items:
                                    description: A label selector requirement is a
                                      selector that contains values, a key, and an
                                      operator that relates the key and values.
                                    type: object
                                    required:
                                    - key
                                    - operator
                                    properties:
                                      key:
                                        description: key is the label key that the
                                          selector applies to.
                                        type: string
                                      operator:
                                        description: operator represents a key's relationship
                                          to a set of values. Valid operators are
                                          In, NotIn, Exists and DoesNotExist.
                                        type: string
                                      values:
                                        description: values is an array of string
                                          values. If the operator is In or NotIn,
                                          the values array must be non-empty. If the
                                          operator is Exists or DoesNotExist, the
                                          values array must be empty. This array is
                                          replaced during a strategic merge patch.
                                        type: array
                                        items:
                                          type: string
                                matchLabels:
                                  description: matchLabels is a map of {key,value}
                                    pairs. A single {key,value} in the matchLabels
                                    map is equivalent to an element of matchExpressions,
                                    whose key field is "key", the operator is "In",
                                    and the values array contains only "value". The
                                    requirements are ANDed.
                                  type: object
                                  additionalProperties:
                                    type: string
                            namespaces:
                              description: namespaces specifies a static list of namespace
                                names that the term applies to. The term is applied
                                to the union of the namespaces listed in this field
                                and the ones selected by namespaceSelector. null or
                                empty namespaces list and null namespaceSelector means
                                "this pod's namespace"
                              type: array
                              items:
                                type: string
                            topologyKey:
                              description: This pod should be co-located (affinity)
                                or not co-located (anti-affinity) with the pods matching
                                the labelSelector in the specified namespaces, where
                                co-located is defined as running on a node whose value
                                of the label with key topologyKey matches that of
                                any node on which any of the selected pods is running.
                                Empty topologyKey is not allowed.
                              type: string
                  podAntiAffinity:
                    description: Describes pod anti-affinity scheduling rules (e.g.
                      avoid putting this pod in the same node, zone, etc. as some
                      other pod(s)).
                    type: object
                    properties:
                      preferredDuringSchedulingIgnoredDuringExecution:
                        description: The scheduler will prefer to schedule pods to
                          nodes that satisfy the anti-affinity expressions specified
                          by this field, but it may choose a node that violates one
                          or more of the expressions. The node that is most preferred
                          is the one with the greatest sum of weights, i.e. for each
                          node that meets all of the scheduling requirements (resource
                          request, requiredDuringScheduling anti-affinity expressions,
                          etc.), compute a sum by iterating through the elements of
                          this field and adding "weight" to the sum if the node has
                          pods which matches the corresponding podAffinityTerm; the
                          node(s) with the highest sum are the most preferred.
                        type: array
                        items:
                          description: The weights of all of the matched WeightedPodAffinityTerm
                            fields are added per-node to find the most preferred node(s)
                          type: object
                          required:
                          - podAffinityTerm
                          - weight
                          properties:
                            podAffinityTerm:
                              description: Required. A pod affinity term, associated
                                with the corresponding weight.
                              type: object
                              required:
                              - topologyKey
                              properties:
                                labelSelector:
                                  description: A label query over a set of resources,
                                    in this case pods.
                                  type: object
                                  properties:
                                    matchExpressions:
                                      description: matchExpressions is a list of label
                                        selector requirements. The requirements are
                                        ANDed.
                                      type: array
                                      items:
                                        description: A label selector requirement
                                          is a selector that contains values, a key,
                                          and an operator that relates the key and
                                          values.
                                        type: object
                                        required:
                                        - key
                                        - operator
                                        properties:
                                          key:
                                            description: key is the label key that
                                              the selector applies to.
                                            type: string
                                          operator:
                                            description: operator represents a key's
                                              relationship to a set of values. Valid
                                              operators are In, NotIn, Exists and
                                              DoesNotExist.
                                            type: string
                                          values:
                                            description: values is an array of string
                                              values. If the operator is In or NotIn,
                                              the values array must be non-empty.
                                              If the operator is Exists or DoesNotExist,
                                              the values array must be empty. This
                                              array is replaced during a strategic
                                              merge patch.
                                            type: array
                                            items:
                                              type: string
                                    matchLabels:
                                      description: matchLabels is a map of {key,value}
                                        pairs. A single {key,value} in the matchLabels
                                        map is equivalent to an element of matchExpressions,
                                        whose key field is "key", the operator is
                                        "In", and the values array contains only "value".
                                        The requirements are ANDed.
                                      type: object
                                      additionalProperties:
                                        type: string
                                namespaceSelector:
                                  description: A label query over the set of namespaces
                                    that the term applies to. The term is applied
                                    to the union of the namespaces selected by this
                                    field and the ones listed in the namespaces field.
                                    null selector and null or empty namespaces list
                                    means "this pod's namespace". An empty selector
                                    ({}) matches all namespaces. This field is alpha-level
                                    and is only honored when PodAffinityNamespaceSelector
                                    feature is enabled.
                                  type: object
                                  properties:
                                    matchExpressions:
                                      description: matchExpressions is a list of label
                                        selector requirements. The requirements are
                                        ANDed.
                                      type: array
                                      items:
                                        description: A label selector requirement
                                          is a selector that contains values, a key,
                                          and an operator that relates the key and
                                          values.
                                        type: object
                                        required:
                                        - key
                                        - operator
                                        properties:
                                          key:
                                            description: key is the label key that
                                              the selector applies to.
                                            type: string
                                          operator:
                                            description: operator represents a key's
                                              relationship to a set of values. Valid
                                              operators are In, NotIn, Exists and
                                              DoesNotExist.
                                            type: string
                                          values:
                                            description: values is an array of string
                                              values. If the operator is In or NotIn,
                                              the values array must be non-empty.
                                              If the operator is Exists or DoesNotExist,
                                              the values array must be empty. This
                                              array is replaced during a strategic
                                              merge patch.
                                            type: array
                                            items:
                                              type: string
                                    matchLabels:
                                      description: matchLabels is a map of {key,value}
                                        pairs. A single {key,value} in the matchLabels
                                        map is equivalent to an element of matchExpressions,
                                        whose key field is "key", the operator is
                                        "In", and the values array contains only "value".
                                        The requirements are ANDed.
                                      type: object
                                      additionalProperties:
                                        type: string
                                namespaces:
                                  description: namespaces specifies a static list
                                    of namespace names that the term applies to. The
                                    term is applied to the union of the namespaces
                                    listed in this field and the ones selected by
                                    namespaceSelector. null or empty namespaces list
                                    and null namespaceSelector means "this pod's namespace"
                                  type: array
                                  items:
                                    type: string
                                topologyKey:
                                  description: This pod should be co-located (affinity)
                                    or not co-located (anti-affinity) with the pods
                                    matching the labelSelector in the specified namespaces,
                                    where co-located is defined as running on a node
                                    whose value of the label with key topologyKey
                                    matches that of any node on which any of the selected
                                    pods is running. Empty topologyKey is not allowed.
                                  type: string
                            weight:
                              description: weight associated with matching the corresponding
                                podAffinityTerm, in the range 1-100.
                              type: integer
                              format: int32
                      requiredDuringSchedulingIgnoredDuringExecution:
                        description: If the anti-affinity requirements specified by
                          this field are not met at scheduling time, the pod will
                          not be scheduled onto the node. If the anti-affinity requirements
                          specified by this field cease to be met at some point during
                          pod execution (e.g. due to a pod label update), the system
                          may or may not try to eventually evict the pod from its
                          node. When there are multiple elements, the lists of nodes
                          corresponding to each podAffinityTerm are intersected, i.e.
                          all terms must be satisfied.
                        type: array
                        items:
                          description: Defines a set of pods (namely those matching
                            the labelSelector relative to the given namespace(s))
                            that this pod should be co-located (affinity) or not co-located
                            (anti-affinity) with, where co-located is defined as running
                            on a node whose value of the label with key <topologyKey>
                            matches that of any node on which a pod of the set of
                            pods is running
                          type: object
                          required:
                          - topologyKey
                          properties:
                            labelSelector:
                              description: A label query over a set of resources,
                                in this case pods.
                              type: object
                              properties:
                                matchExpressions:
                                  description: matchExpressions is a list of label
                                    selector requirements. The requirements are ANDed.
                                  type: array
                                  items:
                                    description: A label selector requirement is a
                                      selector that contains values, a key, and an
                                      operator that relates the key and values.
                                    type: object
                                    required:
                                    - key
                                    - operator
                                    properties:
                                      key:
                                        description: key is the label key that the
                                          selector applies to.
                                        type: string
                                      operator:
                                        description: operator represents a key's relationship
                                          to a set of values. Valid operators are
                                          In, NotIn, Exists and DoesNotExist.
                                        type: string
                                      values:
                                        description: values is an array of string
                                          values. If the operator is In or NotIn,
                                          the values array must be non-empty. If the
                                          operator is Exists or DoesNotExist, the
                                          values array must be empty. This array is
                                          replaced during a strategic merge patch.
                                        type: array
                                        items:
                                          type: string
                                matchLabels:
                                  description: matchLabels is a map of {key,value}
                                    pairs. A single {key,value} in the matchLabels
                                    map is equivalent to an element of matchExpressions,
                                    whose key field is "key", the operator is "In",
                                    and the values array contains only "value". The
                                    requirements are ANDed.
                                  type: object
                                  additionalProperties:
                                    type: string
                            namespaceSelector:
                              description: A label query over the set of namespaces
                                that the term applies to. The term is applied to the
                                union of the namespaces selected by this field and
                                the ones listed in the namespaces field. null selector
                                and null or empty namespaces list means "this pod's
                                namespace". An empty selector ({}) matches all namespaces.
                                This field is alpha-level and is only honored when
                                PodAffinityNamespaceSelector feature is enabled.
                              type: object
                              properties:
                                matchExpressions:
                                  description: matchExpressions is a list of label
                                    selector requirements. The requirements are ANDed.
                                  type: array
                                  items:
                                    description: A label selector requirement is a
                                      selector that contains values, a key, and an
                                      operator that relates the key and values.
                                    type: object
                                    required:
                                    - key
                                    - operator
                                    properties:
                                      key:
                                        description: key is the label key that the
                                          selector applies to.
                                        type: string
                                      operator:
                                        description: operator represents a key's relationship
                                          to a set of values. Valid operators are
                                          In, NotIn, Exists and DoesNotExist.
                                        type: string
                                      values:
                                        description: values is an array of string
                                          values. If the operator is In or NotIn,
                                          the values array must be non-empty. If the
                                          operator is Exists or DoesNotExist, the
                                          values array must be empty. This array is
                                          replaced during a strategic merge patch.
                                        type: array
                                        items:
                                          type: string
                                matchLabels:
                                  description: matchLabels is a map of {key,value}
                                    pairs. A single {key,value} in the matchLabels
                                    map is equivalent to an element of matchExpressions,
                                    whose key field is "key", the operator is "In",
                                    and the values array contains only "value". The
                                    requirements are ANDed.
                                  type: object
                                  additionalProperties:
                                    type: string
                            namespaces:
                              description: namespaces specifies a static list of namespace
                                names that the term applies to. The term is applied
                                to the union of the namespaces listed in this field
                                and the ones selected by namespaceSelector. null or
                                empty namespaces list and null namespaceSelector means
                                "this pod's namespace"
                              type: array
                              items:
                                type: string
                            topologyKey:
                              description: This pod should be co-located (affinity)
                                or not co-located (anti-affinity) with the pods matching
                                the labelSelector in the specified namespaces, where
                                co-located is defined as running on a node whose value
                                of the label with key topologyKey matches that of
                                any node on which any of the selected pods is running.
                                Empty topologyKey is not allowed.
                              type: string
              defaultRoute:
                description: defaultRoute indicates whether an external facing route
                  for the registry should be created using the default generated hostname.
                type: boolean
              disableRedirect:
                description: disableRedirect controls whether to route all data through
                  the Registry, rather than redirecting to the backend.
                type: boolean
              httpSecret:
                description: httpSecret is the value needed by the registry to secure
                  uploads, generated by default.
                type: string
              logLevel:
                description: "logLevel is an intent based logging for an overall component.
                  \ It does not give fine grained control, but it is a simple way
                  to manage coarse grained logging choices that operators have to
                  interpret for their operands. \n Valid values are: \"Normal\", \"Debug\",
                  \"Trace\", \"TraceAll\". Defaults to \"Normal\"."
                type: string
                default: Normal
                enum:
                - ""
                - Normal
                - Debug
                - Trace
                - TraceAll
              logging:
                description: logging is deprecated, use logLevel instead.
                type: integer
                format: int64
              managementState:
                description: managementState indicates whether and how the operator
                  should manage the component
                type: string
                pattern: ^(Managed|Unmanaged|Force|Removed)$
              nodeSelector:
                description: nodeSelector defines the node selection constraints for
                  the registry pod.
                type: object
                additionalProperties:
                  type: string
              observedConfig:
                description: observedConfig holds a sparse config that controller
                  has observed from the cluster state.  It exists in spec because
                  it is an input to the level for the operator
                type: object
                nullable: true
                x-kubernetes-preserve-unknown-fields: true
              operatorLogLevel:
                description: "operatorLogLevel is an intent based logging for the
                  operator itself.  It does not give fine grained control, but it
                  is a simple way to manage coarse grained logging choices that operators
                  have to interpret for themselves. \n Valid values are: \"Normal\",
                  \"Debug\", \"Trace\", \"TraceAll\". Defaults to \"Normal\"."
                type: string
                default: Normal
                enum:
                - ""
                - Normal
                - Debug
                - Trace
                - TraceAll
              proxy:
                description: proxy defines the proxy to be used when calling master
                  api, upstream registries, etc.
                type: object
                properties:
                  http:
                    description: http defines the proxy to be used by the image registry
                      when accessing HTTP endpoints.
                    type: string
                  https:
                    description: https defines the proxy to be used by the image registry
                      when accessing HTTPS endpoints.
                    type: string
                  noProxy:
                    description: noProxy defines a comma-separated list of host names
                      that shouldn't go through any proxy.
                    type: string
              readOnly:
                description: readOnly indicates whether the registry instance should
                  reject attempts to push new images or delete existing ones.
                type: boolean
              replicas:
                description: replicas determines the number of registry instances
                  to run.
                type: integer
                format: int32
              requests:
                description: requests controls how many parallel requests a given
                  registry instance will handle before queuing additional requests.
                type: object
                properties:
                  read:
                    description: read defines limits for image registry's reads.
                    type: object
                    properties:
                      maxInQueue:
                        description: maxInQueue sets the maximum queued api requests
                          to the registry.
                        type: integer
                      maxRunning:
                        description: maxRunning sets the maximum in flight api requests
                          to the registry.
                        type: integer
                      maxWaitInQueue:
                        description: maxWaitInQueue sets the maximum time a request
                          can wait in the queue before being rejected.
                        type: string
                        format: duration
                  write:
                    description: write defines limits for image registry's writes.
                    type: object
                    properties:
                      maxInQueue:
                        description: maxInQueue sets the maximum queued api requests
                          to the registry.
                        type: integer
                      maxRunning:
                        description: maxRunning sets the maximum in flight api requests
                          to the registry.
                        type: integer
                      maxWaitInQueue:
                        description: maxWaitInQueue sets the maximum time a request
                          can wait in the queue before being rejected.
                        type: string
                        format: duration
              resources:
                description: resources defines the resource requests+limits for the
                  registry pod.
                type: object
                properties:
                  limits:
                    description: 'Limits describes the maximum amount of compute resources
                      allowed. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/'
                    type: object
                    additionalProperties:
                      pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                      anyOf:
                      - type: integer
                      - type: string
                      x-kubernetes-int-or-string: true
                  requests:
                    description: 'Requests describes the minimum amount of compute
                      resources required. If Requests is omitted for a container,
                      it defaults to Limits if that is explicitly specified, otherwise
                      to an implementation-defined value. More info: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/'
                    type: object
                    additionalProperties:
                      pattern: ^(\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))(([KMGTPE]i)|[numkMGTPE]|([eE](\+|-)?(([0-9]+(\.[0-9]*)?)|(\.[0-9]+))))?$
                      anyOf:
                      - type: integer
                      - type: string
                      x-kubernetes-int-or-string: true
              rolloutStrategy:
                description: rolloutStrategy defines rollout strategy for the image
                  registry deployment.
                type: string
                pattern: ^(RollingUpdate|Recreate)$
              routes:
                description: routes defines additional external facing routes which
                  should be created for the registry.
                type: array
                items:
                  description: ImageRegistryConfigRoute holds information on external
                    route access to image registry.
                  type: object
                  required:
                  - name
                  properties:
                    hostname:
                      description: hostname for the route.
                      type: string
                    name:
                      description: name of the route to be created.
                      type: string
                    secretName:
                      description: secretName points to secret containing the certificates
                        to be used by the route.
                      type: string
              storage:
                description: storage details for configuring registry storage, e.g.
                  S3 bucket coordinates.
                type: object
                properties:
                  azure:
                    description: azure represents configuration that uses Azure Blob
                      Storage.
                    type: object
                    properties:
                      accountName:
                        description: accountName defines the account to be used by
                          the registry.
                        type: string
                      cloudName:
                        description: cloudName is the name of the Azure cloud environment
                          to be used by the registry. If empty, the operator will
                          set it based on the infrastructure object.
                        type: string
                      container:
                        description: container defines Azure's container to be used
                          by registry.
                        type: string
                        maxLength: 63
                        minLength: 3
                        pattern: ^[0-9a-z]+(-[0-9a-z]+)*$
                  emptyDir:
                    description: 'emptyDir represents ephemeral storage on the pod''s
                      host node. WARNING: this storage cannot be used with more than
                      1 replica and is not suitable for production use. When the pod
                      is removed from a node for any reason, the data in the emptyDir
                      is deleted forever.'
                    type: object
                  gcs:
                    description: gcs represents configuration that uses Google Cloud
                      Storage.
                    type: object
                    properties:
                      bucket:
                        description: bucket is the bucket name in which you want to
                          store the registry's data. Optional, will be generated if
                          not provided.
                        type: string
                      keyID:
                        description: keyID is the KMS key ID to use for encryption.
                          Optional, buckets are encrypted by default on GCP. This
                          allows for the use of a custom encryption key.
                        type: string
                      projectID:
                        description: projectID is the Project ID of the GCP project
                          that this bucket should be associated with.
                        type: string
                      region:
                        description: region is the GCS location in which your bucket
                          exists. Optional, will be set based on the installed GCS
                          Region.
                        type: string
                  managementState:
                    description: managementState indicates if the operator manages
                      the underlying storage unit. If Managed the operator will remove
                      the storage when this operator gets Removed.
                    type: string
                    pattern: ^(Managed|Unmanaged)$
                  pvc:
                    description: pvc represents configuration that uses a PersistentVolumeClaim.
                    type: object
                    properties:
                      claim:
                        description: claim defines the Persisent Volume Claim's name
                          to be used.
                        type: string
                  s3:
                    description: s3 represents configuration that uses Amazon Simple
                      Storage Service.
                    type: object
                    properties:
                      bucket:
                        description: bucket is the bucket name in which you want to
                          store the registry's data. Optional, will be generated if
                          not provided.
                        type: string
                      cloudFront:
                        description: cloudFront configures Amazon Cloudfront as the
                          storage middleware in a registry.
                        type: object
                        required:
                        - baseURL
                        - keypairID
                        - privateKey
                        properties:
                          baseURL:
                            description: baseURL contains the SCHEME://HOST[/PATH]
                              at which Cloudfront is served.
                            type: string
                          duration:
                            description: duration is the duration of the Cloudfront
                              session.
                            type: string
                            format: duration
                          keypairID:
                            description: keypairID is key pair ID provided by AWS.
                            type: string
                          privateKey:
                            description: privateKey points to secret containing the
                              private key, provided by AWS.
                            type: object
                            required:
                            - key
                            properties:
                              key:
                                description: The key of the secret to select from.  Must
                                  be a valid secret key.
                                type: string
                              name:
                                description: 'Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
                                  TODO: Add other useful fields. apiVersion, kind,
                                  uid?'
                                type: string
                              optional:
                                description: Specify whether the Secret or its key
                                  must be defined
                                type: boolean
                      encrypt:
                        description: encrypt specifies whether the registry stores
                          the image in encrypted format or not. Optional, defaults
                          to false.
                        type: boolean
                      keyID:
                        description: keyID is the KMS key ID to use for encryption.
                          Optional, Encrypt must be true, or this parameter is ignored.
                        type: string
                      region:
                        description: region is the AWS region in which your bucket
                          exists. Optional, will be set based on the installed AWS
                          Region.
                        type: string
                      regionEndpoint:
                        description: regionEndpoint is the endpoint for S3 compatible
                          storage services. Optional, defaults based on the Region
                          that is provided.
                        type: string
                      virtualHostedStyle:
                        description: virtualHostedStyle enables using S3 virtual hosted
                          style bucket paths with a custom RegionEndpoint Optional,
                          defaults to false.
                        type: boolean
                  swift:
                    description: swift represents configuration that uses OpenStack
                      Object Storage.
                    type: object
                    properties:
                      authURL:
                        description: authURL defines the URL for obtaining an authentication
                          token.
                        type: string
                      authVersion:
                        description: authVersion specifies the OpenStack Auth's version.
                        type: string
                      container:
                        description: container defines the name of Swift container
                          where to store the registry's data.
                        type: string
                      domain:
                        description: domain specifies Openstack's domain name for
                          Identity v3 API.
                        type: string
                      domainID:
                        description: domainID specifies Openstack's domain id for
                          Identity v3 API.
                        type: string
                      regionName:
                        description: regionName defines Openstack's region in which
                          container exists.
                        type: string
                      tenant:
                        description: tenant defines Openstack tenant name to be used
                          by registry.
                        type: string
                      tenantID:
                        description: tenant defines Openstack tenant id to be used
                          by registry.
                        type: string
              tolerations:
                description: tolerations defines the tolerations for the registry
                  pod.
                type: array
                items:
                  description: The pod this Toleration is attached to tolerates any
                    taint that matches the triple <key,value,effect> using the matching
                    operator <operator>.
                  type: object
                  properties:
                    effect:
                      description: Effect indicates the taint effect to match. Empty
                        means match all taint effects. When specified, allowed values
                        are NoSchedule, PreferNoSchedule and NoExecute.
                      type: string
                    key:
                      description: Key is the taint key that the toleration applies
                        to. Empty means match all taint keys. If the key is empty,
                        operator must be Exists; this combination means to match all
                        values and all keys.
                      type: string
                    operator:
                      description: Operator represents a key's relationship to the
                        value. Valid operators are Exists and Equal. Defaults to Equal.
                        Exists is equivalent to wildcard for value, so that a pod
                        can tolerate all taints of a particular category.
                      type: string
                    tolerationSeconds:
                      description: TolerationSeconds represents the period of time
                        the toleration (which must be of effect NoExecute, otherwise
                        this field is ignored) tolerates the taint. By default, it
                        is not set, which means tolerate the taint forever (do not
                        evict). Zero and negative values will be treated as 0 (evict
                        immediately) by the system.
                      type: integer
                      format: int64
                    value:
                      description: Value is the taint value the toleration matches
                        to. If the operator is Exists, the value should be empty,
                        otherwise just a regular string.
                      type: string
              unsupportedConfigOverrides:
                description: 'unsupportedConfigOverrides holds a sparse config that
                  will override any previously set options.  It only needs to be the
                  fields to override it will end up overlaying in the following order:
                  1. hardcoded defaults 2. observedConfig 3. unsupportedConfigOverrides'
                type: object
                nullable: true
                x-kubernetes-preserve-unknown-fields: true
          status:
            description: ImageRegistryStatus reports image registry operational status.
            type: object
            required:
            - storage
            - storageManaged
            properties:
              conditions:
                description: conditions is a list of conditions and their status
                type: array
                items:
                  description: OperatorCondition is just the standard condition fields.
                  type: object
                  properties:
                    lastTransitionTime:
                      type: string
                      format: date-time
                    message:
                      type: string
                    reason:
                      type: string
                    status:
                      type: string
                    type:
                      type: string
              generations:
                description: generations are used to determine when an item needs
                  to be reconciled or has changed in a way that needs a reaction.
                type: array
                items:
                  description: GenerationStatus keeps track of the generation for
                    a given resource so that decisions about forced updates can be
                    made.
                  type: object
                  properties:
                    group:
                      description: group is the group of the thing you're tracking
                      type: string
                    hash:
                      description: hash is an optional field set for resources without
                        generation that are content sensitive like secrets and configmaps
                      type: string
                    lastGeneration:
                      description: lastGeneration is the last generation of the workload
                        controller involved
                      type: integer
                      format: int64
                    name:
                      description: name is the name of the thing you're tracking
                      type: string
                    namespace:
                      description: namespace is where the thing you're tracking is
                      type: string
                    resource:
                      description: resource is the resource type of the thing you're
                        tracking
                      type: string
              observedGeneration:
                description: observedGeneration is the last generation change you've
                  dealt with
                type: integer
                format: int64
              readyReplicas:
                description: readyReplicas indicates how many replicas are ready and
                  at the desired state
                type: integer
                format: int32
              storage:
                description: storage indicates the current applied storage configuration
                  of the registry.
                type: object
                properties:
                  azure:
                    description: azure represents configuration that uses Azure Blob
                      Storage.
                    type: object
                    properties:
                      accountName:
                        description: accountName defines the account to be used by
                          the registry.
                        type: string
                      cloudName:
                        description: cloudName is the name of the Azure cloud environment
                          to be used by the registry. If empty, the operator will
                          set it based on the infrastructure object.
                        type: string
                      container:
                        description: container defines Azure's container to be used
                          by registry.
                        type: string
                        maxLength: 63
                        minLength: 3
                        pattern: ^[0-9a-z]+(-[0-9a-z]+)*$
                  emptyDir:
                    description: 'emptyDir represents ephemeral storage on the pod''s
                      host node. WARNING: this storage cannot be used with more than
                      1 replica and is not suitable for production use. When the pod
                      is removed from a node for any reason, the data in the emptyDir
                      is deleted forever.'
                    type: object
                  gcs:
                    description: gcs represents configuration that uses Google Cloud
                      Storage.
                    type: object
                    properties:
                      bucket:
                        description: bucket is the bucket name in which you want to
                          store the registry's data. Optional, will be generated if
                          not provided.
                        type: string
                      keyID:
                        description: keyID is the KMS key ID to use for encryption.
                          Optional, buckets are encrypted by default on GCP. This
                          allows for the use of a custom encryption key.
                        type: string
                      projectID:
                        description: projectID is the Project ID of the GCP project
                          that this bucket should be associated with.
                        type: string
                      region:
                        description: region is the GCS location in which your bucket
                          exists. Optional, will be set based on the installed GCS
                          Region.
                        type: string
                  managementState:
                    description: managementState indicates if the operator manages
                      the underlying storage unit. If Managed the operator will remove
                      the storage when this operator gets Removed.
                    type: string
                    pattern: ^(Managed|Unmanaged)$
                  pvc:
                    description: pvc represents configuration that uses a PersistentVolumeClaim.
                    type: object
                    properties:
                      claim:
                        description: claim defines the Persisent Volume Claim's name
                          to be used.
                        type: string
                  s3:
                    description: s3 represents configuration that uses Amazon Simple
                      Storage Service.
                    type: object
                    properties:
                      bucket:
                        description: bucket is the bucket name in which you want to
                          store the registry's data. Optional, will be generated if
                          not provided.
                        type: string
                      cloudFront:
                        description: cloudFront configures Amazon Cloudfront as the
                          storage middleware in a registry.
                        type: object
                        required:
                        - baseURL
                        - keypairID
                        - privateKey
                        properties:
                          baseURL:
                            description: baseURL contains the SCHEME://HOST[/PATH]
                              at which Cloudfront is served.
                            type: string
                          duration:
                            description: duration is the duration of the Cloudfront
                              session.
                            type: string
                            format: duration
                          keypairID:
                            description: keypairID is key pair ID provided by AWS.
                            type: string
                          privateKey:
                            description: privateKey points to secret containing the
                              private key, provided by AWS.
                            type: object
                            required:
                            - key
                            properties:
                              key:
                                description: The key of the secret to select from.  Must
                                  be a valid secret key.
                                type: string
                              name:
                                description: 'Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
                                  TODO: Add other useful fields. apiVersion, kind,
                                  uid?'
                                type: string
                              optional:
                                description: Specify whether the Secret or its key
                                  must be defined
                                type: boolean
                      encrypt:
                        description: encrypt specifies whether the registry stores
                          the image in encrypted format or not. Optional, defaults
                          to false.
                        type: boolean
                      keyID:
                        description: keyID is the KMS key ID to use for encryption.
                          Optional, Encrypt must be true, or this parameter is ignored.
                        type: string
                      region:
                        description: region is the AWS region in which your bucket
                          exists. Optional, will be set based on the installed AWS
                          Region.
                        type: string
                      regionEndpoint:
                        description: regionEndpoint is the endpoint for S3 compatible
                          storage services. Optional, defaults based on the Region
                          that is provided.
                        type: string
                      virtualHostedStyle:
                        description: virtualHostedStyle enables using S3 virtual hosted
                          style bucket paths with a custom RegionEndpoint Optional,
                          defaults to false.
                        type: boolean
                  swift:
                    description: swift represents configuration that uses OpenStack
                      Object Storage.
                    type: object
                    properties:
                      authURL:
                        description: authURL defines the URL for obtaining an authentication
                          token.
                        type: string
                      authVersion:
                        description: authVersion specifies the OpenStack Auth's version.
                        type: string
                      container:
                        description: container defines the name of Swift container
                          where to store the registry's data.
                        type: string
                      domain:
                        description: domain specifies Openstack's domain name for
                          Identity v3 API.
                        type: string
                      domainID:
                        description: domainID specifies Openstack's domain id for
                          Identity v3 API.
                        type: string
                      regionName:
                        description: regionName defines Openstack's region in which
                          container exists.
                        type: string
                      tenant:
                        description: tenant defines Openstack tenant name to be used
                          by registry.
                        type: string
                      tenantID:
                        description: tenant defines Openstack tenant id to be used
                          by registry.
                        type: string
              storageManaged:
                description: storageManaged is deprecated, please refer to Storage.managementState
                type: boolean
              version:
                description: version is the level this availability applies to
                type: string
    served: true
    storage: true
    subresources:
      status: {}
`)

func assetsCrd0000_11_imageregistryConfigsCrdYamlBytes() ([]byte, error) {
	return _assetsCrd0000_11_imageregistryConfigsCrdYaml, nil
}

func assetsCrd0000_11_imageregistryConfigsCrdYaml() (*asset, error) {
	bytes, err := assetsCrd0000_11_imageregistryConfigsCrdYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/crd/0000_11_imageregistry-configs.crd.yaml", size: 90225, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsScc0000_20_kubeApiserverOperator_00_sccAnyuidYaml = []byte(`allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities:
apiVersion: security.openshift.io/v1
defaultAddCapabilities:
fsGroup:
  type: RunAsAny
groups:
- system:cluster-admins
kind: SecurityContextConstraints
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
    release.openshift.io/create-only: "true"
    kubernetes.io/description: anyuid provides all features of the restricted SCC
      but allows users to run with any UID and any GID.
  name: anyuid
priority: 10
readOnlyRootFilesystem: false
requiredDropCapabilities:
- MKNOD
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: RunAsAny
users: []
volumes:
- configMap
- downwardAPI
- emptyDir
- persistentVolumeClaim
- projected
- secret
`)

func assetsScc0000_20_kubeApiserverOperator_00_sccAnyuidYamlBytes() ([]byte, error) {
	return _assetsScc0000_20_kubeApiserverOperator_00_sccAnyuidYaml, nil
}

func assetsScc0000_20_kubeApiserverOperator_00_sccAnyuidYaml() (*asset, error) {
	bytes, err := assetsScc0000_20_kubeApiserverOperator_00_sccAnyuidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/scc/0000_20_kube-apiserver-operator_00_scc-anyuid.yaml", size: 1048, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsScc0000_20_kubeApiserverOperator_00_sccHostaccessYaml = []byte(`allowHostDirVolumePlugin: true
allowHostIPC: true
allowHostNetwork: true
allowHostPID: true
allowHostPorts: true
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities:
apiVersion: security.openshift.io/v1
defaultAddCapabilities:
fsGroup:
  type: MustRunAs
groups: []
kind: SecurityContextConstraints
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
    release.openshift.io/create-only: "true"
    kubernetes.io/description: 'hostaccess allows access to all host namespaces but
      still requires pods to be run with a UID and SELinux context that are allocated
      to the namespace. WARNING: this SCC allows host access to namespaces, file systems,
      and PIDS.  It should only be used by trusted pods.  Grant with caution.'
  name: hostaccess
priority:
readOnlyRootFilesystem: false
requiredDropCapabilities:
- KILL
- MKNOD
- SETUID
- SETGID
runAsUser:
  type: MustRunAsRange
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: RunAsAny
users: []
volumes:
- configMap
- downwardAPI
- emptyDir
- hostPath
- persistentVolumeClaim
- projected
- secret
`)

func assetsScc0000_20_kubeApiserverOperator_00_sccHostaccessYamlBytes() ([]byte, error) {
	return _assetsScc0000_20_kubeApiserverOperator_00_sccHostaccessYaml, nil
}

func assetsScc0000_20_kubeApiserverOperator_00_sccHostaccessYaml() (*asset, error) {
	bytes, err := assetsScc0000_20_kubeApiserverOperator_00_sccHostaccessYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/scc/0000_20_kube-apiserver-operator_00_scc-hostaccess.yaml", size: 1267, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsScc0000_20_kubeApiserverOperator_00_sccHostmountAnyuidYaml = []byte(`allowHostDirVolumePlugin: true
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities:
apiVersion: security.openshift.io/v1
defaultAddCapabilities:
fsGroup:
  type: RunAsAny
groups: []
kind: SecurityContextConstraints
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
    release.openshift.io/create-only: "true"
    kubernetes.io/description: |-
      hostmount-anyuid provides all the features of the
      restricted SCC but allows host mounts and any UID by a pod.  This is primarily
      used by the persistent volume recycler. WARNING: this SCC allows host file
      system access as any UID, including UID 0.  Grant with caution.
  name: hostmount-anyuid
priority:
readOnlyRootFilesystem: false
requiredDropCapabilities:
- MKNOD
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: RunAsAny
users:
- system:serviceaccount:openshift-infra:pv-recycler-controller
volumes:
- configMap
- downwardAPI
- emptyDir
- hostPath
- nfs
- persistentVolumeClaim
- projected
- secret
`)

func assetsScc0000_20_kubeApiserverOperator_00_sccHostmountAnyuidYamlBytes() ([]byte, error) {
	return _assetsScc0000_20_kubeApiserverOperator_00_sccHostmountAnyuidYaml, nil
}

func assetsScc0000_20_kubeApiserverOperator_00_sccHostmountAnyuidYaml() (*asset, error) {
	bytes, err := assetsScc0000_20_kubeApiserverOperator_00_sccHostmountAnyuidYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/scc/0000_20_kube-apiserver-operator_00_scc-hostmount-anyuid.yaml", size: 1298, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsScc0000_20_kubeApiserverOperator_00_sccHostnetworkYaml = []byte(`allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: true
allowHostPID: false
allowHostPorts: true
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities:
apiVersion: security.openshift.io/v1
defaultAddCapabilities:
fsGroup:
  type: MustRunAs
groups: []
kind: SecurityContextConstraints
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
    release.openshift.io/create-only: "true"
    kubernetes.io/description: hostnetwork allows using host networking and host ports
      but still requires pods to be run with a UID and SELinux context that are allocated
      to the namespace.
  name: hostnetwork
priority:
readOnlyRootFilesystem: false
requiredDropCapabilities:
- KILL
- MKNOD
- SETUID
- SETGID
runAsUser:
  type: MustRunAsRange
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: MustRunAs
users: []
volumes:
- configMap
- downwardAPI
- emptyDir
- persistentVolumeClaim
- projected
- secret
`)

func assetsScc0000_20_kubeApiserverOperator_00_sccHostnetworkYamlBytes() ([]byte, error) {
	return _assetsScc0000_20_kubeApiserverOperator_00_sccHostnetworkYaml, nil
}

func assetsScc0000_20_kubeApiserverOperator_00_sccHostnetworkYaml() (*asset, error) {
	bytes, err := assetsScc0000_20_kubeApiserverOperator_00_sccHostnetworkYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/scc/0000_20_kube-apiserver-operator_00_scc-hostnetwork.yaml", size: 1123, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsScc0000_20_kubeApiserverOperator_00_sccNonrootYaml = []byte(`allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities:
apiVersion: security.openshift.io/v1
defaultAddCapabilities:
fsGroup:
  type: RunAsAny
groups: []
kind: SecurityContextConstraints
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
    release.openshift.io/create-only: "true"
    kubernetes.io/description: nonroot provides all features of the restricted SCC
      but allows users to run with any non-root UID.  The user must specify the UID
      or it must be specified on the by the manifest of the container runtime.
  name: nonroot
priority:
readOnlyRootFilesystem: false
requiredDropCapabilities:
- KILL
- MKNOD
- SETUID
- SETGID
runAsUser:
  type: MustRunAsNonRoot
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: RunAsAny
users: []
volumes:
- configMap
- downwardAPI
- emptyDir
- persistentVolumeClaim
- projected
- secret
`)

func assetsScc0000_20_kubeApiserverOperator_00_sccNonrootYamlBytes() ([]byte, error) {
	return _assetsScc0000_20_kubeApiserverOperator_00_sccNonrootYaml, nil
}

func assetsScc0000_20_kubeApiserverOperator_00_sccNonrootYaml() (*asset, error) {
	bytes, err := assetsScc0000_20_kubeApiserverOperator_00_sccNonrootYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/scc/0000_20_kube-apiserver-operator_00_scc-nonroot.yaml", size: 1166, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsScc0000_20_kubeApiserverOperator_00_sccPrivilegedYaml = []byte(`allowHostDirVolumePlugin: true
allowHostIPC: true
allowHostNetwork: true
allowHostPID: true
allowHostPorts: true
allowPrivilegeEscalation: true
allowPrivilegedContainer: true
allowedCapabilities:
- "*"
allowedUnsafeSysctls:
- "*"
apiVersion: security.openshift.io/v1
defaultAddCapabilities:
fsGroup:
  type: RunAsAny
groups:
- system:cluster-admins
- system:nodes
- system:masters
kind: SecurityContextConstraints
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
    release.openshift.io/create-only: "true"
    kubernetes.io/description: 'privileged allows access to all privileged and host
      features and the ability to run as any user, any group, any fsGroup, and with
      any SELinux context.  WARNING: this is the most relaxed SCC and should be used
      only for cluster administration. Grant with caution.'
  name: privileged
priority:
readOnlyRootFilesystem: false
requiredDropCapabilities:
runAsUser:
  type: RunAsAny
seLinuxContext:
  type: RunAsAny
seccompProfiles:
- "*"
supplementalGroups:
  type: RunAsAny
users:
- system:admin
- system:serviceaccount:openshift-infra:build-controller
volumes:
- "*"
`)

func assetsScc0000_20_kubeApiserverOperator_00_sccPrivilegedYamlBytes() ([]byte, error) {
	return _assetsScc0000_20_kubeApiserverOperator_00_sccPrivilegedYaml, nil
}

func assetsScc0000_20_kubeApiserverOperator_00_sccPrivilegedYaml() (*asset, error) {
	bytes, err := assetsScc0000_20_kubeApiserverOperator_00_sccPrivilegedYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/scc/0000_20_kube-apiserver-operator_00_scc-privileged.yaml", size: 1291, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsScc0000_20_kubeApiserverOperator_00_sccRestrictedYaml = []byte(`allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities:
apiVersion: security.openshift.io/v1
defaultAddCapabilities:
fsGroup:
  type: MustRunAs
groups:
- system:authenticated
kind: SecurityContextConstraints
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
    release.openshift.io/create-only: "true"
    kubernetes.io/description: restricted denies access to all host features and requires
      pods to be run with a UID, and SELinux context that are allocated to the namespace.  This
      is the most restrictive SCC and it is used by default for authenticated users.
  name: restricted
priority:
readOnlyRootFilesystem: false
requiredDropCapabilities:
- KILL
- MKNOD
- SETUID
- SETGID
runAsUser:
  type: MustRunAsRange
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: RunAsAny
users: []
volumes:
- configMap
- downwardAPI
- emptyDir
- persistentVolumeClaim
- projected
- secret
`)

func assetsScc0000_20_kubeApiserverOperator_00_sccRestrictedYamlBytes() ([]byte, error) {
	return _assetsScc0000_20_kubeApiserverOperator_00_sccRestrictedYaml, nil
}

func assetsScc0000_20_kubeApiserverOperator_00_sccRestrictedYaml() (*asset, error) {
	bytes, err := assetsScc0000_20_kubeApiserverOperator_00_sccRestrictedYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/scc/0000_20_kube-apiserver-operator_00_scc-restricted.yaml", size: 1213, mode: os.FileMode(436), modTime: time.Unix(1653632080, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"assets/components/flannel/clusterrole.yaml":                                    assetsComponentsFlannelClusterroleYaml,
	"assets/components/flannel/clusterrolebinding.yaml":                             assetsComponentsFlannelClusterrolebindingYaml,
	"assets/components/flannel/configmap.yaml":                                      assetsComponentsFlannelConfigmapYaml,
	"assets/components/flannel/daemonset.yaml":                                      assetsComponentsFlannelDaemonsetYaml,
	"assets/components/flannel/podsecuritypolicy.yaml":                              assetsComponentsFlannelPodsecuritypolicyYaml,
	"assets/components/flannel/service-account.yaml":                                assetsComponentsFlannelServiceAccountYaml,
	"assets/components/hostpath-provisioner/clusterrole.yaml":                       assetsComponentsHostpathProvisionerClusterroleYaml,
	"assets/components/hostpath-provisioner/clusterrolebinding.yaml":                assetsComponentsHostpathProvisionerClusterrolebindingYaml,
	"assets/components/hostpath-provisioner/daemonset.yaml":                         assetsComponentsHostpathProvisionerDaemonsetYaml,
	"assets/components/hostpath-provisioner/namespace.yaml":                         assetsComponentsHostpathProvisionerNamespaceYaml,
	"assets/components/hostpath-provisioner/scc.yaml":                               assetsComponentsHostpathProvisionerSccYaml,
	"assets/components/hostpath-provisioner/service-account.yaml":                   assetsComponentsHostpathProvisionerServiceAccountYaml,
	"assets/components/hostpath-provisioner/storageclass.yaml":                      assetsComponentsHostpathProvisionerStorageclassYaml,
	"assets/components/openshift-dns/dns/cluster-role-binding.yaml":                 assetsComponentsOpenshiftDnsDnsClusterRoleBindingYaml,
	"assets/components/openshift-dns/dns/cluster-role.yaml":                         assetsComponentsOpenshiftDnsDnsClusterRoleYaml,
	"assets/components/openshift-dns/dns/configmap.yaml":                            assetsComponentsOpenshiftDnsDnsConfigmapYaml,
	"assets/components/openshift-dns/dns/daemonset.yaml":                            assetsComponentsOpenshiftDnsDnsDaemonsetYaml,
	"assets/components/openshift-dns/dns/namespace.yaml":                            assetsComponentsOpenshiftDnsDnsNamespaceYaml,
	"assets/components/openshift-dns/dns/service-account.yaml":                      assetsComponentsOpenshiftDnsDnsServiceAccountYaml,
	"assets/components/openshift-dns/dns/service.yaml":                              assetsComponentsOpenshiftDnsDnsServiceYaml,
	"assets/components/openshift-dns/node-resolver/daemonset.yaml":                  assetsComponentsOpenshiftDnsNodeResolverDaemonsetYaml,
	"assets/components/openshift-dns/node-resolver/service-account.yaml":            assetsComponentsOpenshiftDnsNodeResolverServiceAccountYaml,
	"assets/components/openshift-router/cluster-role-binding.yaml":                  assetsComponentsOpenshiftRouterClusterRoleBindingYaml,
	"assets/components/openshift-router/cluster-role.yaml":                          assetsComponentsOpenshiftRouterClusterRoleYaml,
	"assets/components/openshift-router/configmap.yaml":                             assetsComponentsOpenshiftRouterConfigmapYaml,
	"assets/components/openshift-router/deployment.yaml":                            assetsComponentsOpenshiftRouterDeploymentYaml,
	"assets/components/openshift-router/namespace.yaml":                             assetsComponentsOpenshiftRouterNamespaceYaml,
	"assets/components/openshift-router/service-account.yaml":                       assetsComponentsOpenshiftRouterServiceAccountYaml,
	"assets/components/openshift-router/service-cloud.yaml":                         assetsComponentsOpenshiftRouterServiceCloudYaml,
	"assets/components/openshift-router/service-internal.yaml":                      assetsComponentsOpenshiftRouterServiceInternalYaml,
	"assets/components/ovn/clusterrole.yaml":                                        assetsComponentsOvnClusterroleYaml,
	"assets/components/ovn/clusterrolebinding.yaml":                                 assetsComponentsOvnClusterrolebindingYaml,
	"assets/components/ovn/configmap-ovn-ca.yaml":                                   assetsComponentsOvnConfigmapOvnCaYaml,
	"assets/components/ovn/configmap.yaml":                                          assetsComponentsOvnConfigmapYaml,
	"assets/components/ovn/master/.daemonset.yaml.swp":                              assetsComponentsOvnMasterDaemonsetYamlSwp,
	"assets/components/ovn/master/daemonset.yaml":                                   assetsComponentsOvnMasterDaemonsetYaml,
	"assets/components/ovn/master/serviceaccount.yaml":                              assetsComponentsOvnMasterServiceaccountYaml,
	"assets/components/ovn/namespace.yaml":                                          assetsComponentsOvnNamespaceYaml,
	"assets/components/ovn/node/daemonset.yaml":                                     assetsComponentsOvnNodeDaemonsetYaml,
	"assets/components/ovn/node/serviceaccount.yaml":                                assetsComponentsOvnNodeServiceaccountYaml,
	"assets/components/ovn/role.yaml":                                               assetsComponentsOvnRoleYaml,
	"assets/components/ovn/rolebinding.yaml":                                        assetsComponentsOvnRolebindingYaml,
	"assets/components/ovn/service.yaml":                                            assetsComponentsOvnServiceYaml,
	"assets/components/service-ca/clusterrole.yaml":                                 assetsComponentsServiceCaClusterroleYaml,
	"assets/components/service-ca/clusterrolebinding.yaml":                          assetsComponentsServiceCaClusterrolebindingYaml,
	"assets/components/service-ca/deployment.yaml":                                  assetsComponentsServiceCaDeploymentYaml,
	"assets/components/service-ca/ns.yaml":                                          assetsComponentsServiceCaNsYaml,
	"assets/components/service-ca/role.yaml":                                        assetsComponentsServiceCaRoleYaml,
	"assets/components/service-ca/rolebinding.yaml":                                 assetsComponentsServiceCaRolebindingYaml,
	"assets/components/service-ca/sa.yaml":                                          assetsComponentsServiceCaSaYaml,
	"assets/components/service-ca/signing-cabundle.yaml":                            assetsComponentsServiceCaSigningCabundleYaml,
	"assets/components/service-ca/signing-secret.yaml":                              assetsComponentsServiceCaSigningSecretYaml,
	"assets/core/0000_50_cluster-openshift-controller-manager_00_namespace.yaml":    assetsCore0000_50_clusterOpenshiftControllerManager_00_namespaceYaml,
	"assets/crd/0000_03_authorization-openshift_01_rolebindingrestriction.crd.yaml": assetsCrd0000_03_authorizationOpenshift_01_rolebindingrestrictionCrdYaml,
	"assets/crd/0000_03_config-operator_01_proxy.crd.yaml":                          assetsCrd0000_03_configOperator_01_proxyCrdYaml,
	"assets/crd/0000_03_quota-openshift_01_clusterresourcequota.crd.yaml":           assetsCrd0000_03_quotaOpenshift_01_clusterresourcequotaCrdYaml,
	"assets/crd/0000_03_security-openshift_01_scc.crd.yaml":                         assetsCrd0000_03_securityOpenshift_01_sccCrdYaml,
	"assets/crd/0000_10_config-operator_01_build.crd.yaml":                          assetsCrd0000_10_configOperator_01_buildCrdYaml,
	"assets/crd/0000_10_config-operator_01_featuregate.crd.yaml":                    assetsCrd0000_10_configOperator_01_featuregateCrdYaml,
	"assets/crd/0000_10_config-operator_01_image.crd.yaml":                          assetsCrd0000_10_configOperator_01_imageCrdYaml,
	"assets/crd/0000_10_config-operator_01_imagecontentsourcepolicy.crd.yaml":       assetsCrd0000_10_configOperator_01_imagecontentsourcepolicyCrdYaml,
	"assets/crd/0000_11_imageregistry-configs.crd.yaml":                             assetsCrd0000_11_imageregistryConfigsCrdYaml,
	"assets/scc/0000_20_kube-apiserver-operator_00_scc-anyuid.yaml":                 assetsScc0000_20_kubeApiserverOperator_00_sccAnyuidYaml,
	"assets/scc/0000_20_kube-apiserver-operator_00_scc-hostaccess.yaml":             assetsScc0000_20_kubeApiserverOperator_00_sccHostaccessYaml,
	"assets/scc/0000_20_kube-apiserver-operator_00_scc-hostmount-anyuid.yaml":       assetsScc0000_20_kubeApiserverOperator_00_sccHostmountAnyuidYaml,
	"assets/scc/0000_20_kube-apiserver-operator_00_scc-hostnetwork.yaml":            assetsScc0000_20_kubeApiserverOperator_00_sccHostnetworkYaml,
	"assets/scc/0000_20_kube-apiserver-operator_00_scc-nonroot.yaml":                assetsScc0000_20_kubeApiserverOperator_00_sccNonrootYaml,
	"assets/scc/0000_20_kube-apiserver-operator_00_scc-privileged.yaml":             assetsScc0000_20_kubeApiserverOperator_00_sccPrivilegedYaml,
	"assets/scc/0000_20_kube-apiserver-operator_00_scc-restricted.yaml":             assetsScc0000_20_kubeApiserverOperator_00_sccRestrictedYaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"assets": {nil, map[string]*bintree{
		"components": {nil, map[string]*bintree{
			"flannel": {nil, map[string]*bintree{
				"clusterrole.yaml":        {assetsComponentsFlannelClusterroleYaml, map[string]*bintree{}},
				"clusterrolebinding.yaml": {assetsComponentsFlannelClusterrolebindingYaml, map[string]*bintree{}},
				"configmap.yaml":          {assetsComponentsFlannelConfigmapYaml, map[string]*bintree{}},
				"daemonset.yaml":          {assetsComponentsFlannelDaemonsetYaml, map[string]*bintree{}},
				"podsecuritypolicy.yaml":  {assetsComponentsFlannelPodsecuritypolicyYaml, map[string]*bintree{}},
				"service-account.yaml":    {assetsComponentsFlannelServiceAccountYaml, map[string]*bintree{}},
			}},
			"hostpath-provisioner": {nil, map[string]*bintree{
				"clusterrole.yaml":        {assetsComponentsHostpathProvisionerClusterroleYaml, map[string]*bintree{}},
				"clusterrolebinding.yaml": {assetsComponentsHostpathProvisionerClusterrolebindingYaml, map[string]*bintree{}},
				"daemonset.yaml":          {assetsComponentsHostpathProvisionerDaemonsetYaml, map[string]*bintree{}},
				"namespace.yaml":          {assetsComponentsHostpathProvisionerNamespaceYaml, map[string]*bintree{}},
				"scc.yaml":                {assetsComponentsHostpathProvisionerSccYaml, map[string]*bintree{}},
				"service-account.yaml":    {assetsComponentsHostpathProvisionerServiceAccountYaml, map[string]*bintree{}},
				"storageclass.yaml":       {assetsComponentsHostpathProvisionerStorageclassYaml, map[string]*bintree{}},
			}},
			"openshift-dns": {nil, map[string]*bintree{
				"dns": {nil, map[string]*bintree{
					"cluster-role-binding.yaml": {assetsComponentsOpenshiftDnsDnsClusterRoleBindingYaml, map[string]*bintree{}},
					"cluster-role.yaml":         {assetsComponentsOpenshiftDnsDnsClusterRoleYaml, map[string]*bintree{}},
					"configmap.yaml":            {assetsComponentsOpenshiftDnsDnsConfigmapYaml, map[string]*bintree{}},
					"daemonset.yaml":            {assetsComponentsOpenshiftDnsDnsDaemonsetYaml, map[string]*bintree{}},
					"namespace.yaml":            {assetsComponentsOpenshiftDnsDnsNamespaceYaml, map[string]*bintree{}},
					"service-account.yaml":      {assetsComponentsOpenshiftDnsDnsServiceAccountYaml, map[string]*bintree{}},
					"service.yaml":              {assetsComponentsOpenshiftDnsDnsServiceYaml, map[string]*bintree{}},
				}},
				"node-resolver": {nil, map[string]*bintree{
					"daemonset.yaml":       {assetsComponentsOpenshiftDnsNodeResolverDaemonsetYaml, map[string]*bintree{}},
					"service-account.yaml": {assetsComponentsOpenshiftDnsNodeResolverServiceAccountYaml, map[string]*bintree{}},
				}},
			}},
			"openshift-router": {nil, map[string]*bintree{
				"cluster-role-binding.yaml": {assetsComponentsOpenshiftRouterClusterRoleBindingYaml, map[string]*bintree{}},
				"cluster-role.yaml":         {assetsComponentsOpenshiftRouterClusterRoleYaml, map[string]*bintree{}},
				"configmap.yaml":            {assetsComponentsOpenshiftRouterConfigmapYaml, map[string]*bintree{}},
				"deployment.yaml":           {assetsComponentsOpenshiftRouterDeploymentYaml, map[string]*bintree{}},
				"namespace.yaml":            {assetsComponentsOpenshiftRouterNamespaceYaml, map[string]*bintree{}},
				"service-account.yaml":      {assetsComponentsOpenshiftRouterServiceAccountYaml, map[string]*bintree{}},
				"service-cloud.yaml":        {assetsComponentsOpenshiftRouterServiceCloudYaml, map[string]*bintree{}},
				"service-internal.yaml":     {assetsComponentsOpenshiftRouterServiceInternalYaml, map[string]*bintree{}},
			}},
			"ovn": {nil, map[string]*bintree{
				"clusterrole.yaml":        {assetsComponentsOvnClusterroleYaml, map[string]*bintree{}},
				"clusterrolebinding.yaml": {assetsComponentsOvnClusterrolebindingYaml, map[string]*bintree{}},
				"configmap-ovn-ca.yaml":   {assetsComponentsOvnConfigmapOvnCaYaml, map[string]*bintree{}},
				"configmap.yaml":          {assetsComponentsOvnConfigmapYaml, map[string]*bintree{}},
				"master": {nil, map[string]*bintree{
					".daemonset.yaml.swp": {assetsComponentsOvnMasterDaemonsetYamlSwp, map[string]*bintree{}},
					"daemonset.yaml":      {assetsComponentsOvnMasterDaemonsetYaml, map[string]*bintree{}},
					"serviceaccount.yaml": {assetsComponentsOvnMasterServiceaccountYaml, map[string]*bintree{}},
				}},
				"namespace.yaml": {assetsComponentsOvnNamespaceYaml, map[string]*bintree{}},
				"node": {nil, map[string]*bintree{
					"daemonset.yaml":      {assetsComponentsOvnNodeDaemonsetYaml, map[string]*bintree{}},
					"serviceaccount.yaml": {assetsComponentsOvnNodeServiceaccountYaml, map[string]*bintree{}},
				}},
				"role.yaml":        {assetsComponentsOvnRoleYaml, map[string]*bintree{}},
				"rolebinding.yaml": {assetsComponentsOvnRolebindingYaml, map[string]*bintree{}},
				"service.yaml":     {assetsComponentsOvnServiceYaml, map[string]*bintree{}},
			}},
			"service-ca": {nil, map[string]*bintree{
				"clusterrole.yaml":        {assetsComponentsServiceCaClusterroleYaml, map[string]*bintree{}},
				"clusterrolebinding.yaml": {assetsComponentsServiceCaClusterrolebindingYaml, map[string]*bintree{}},
				"deployment.yaml":         {assetsComponentsServiceCaDeploymentYaml, map[string]*bintree{}},
				"ns.yaml":                 {assetsComponentsServiceCaNsYaml, map[string]*bintree{}},
				"role.yaml":               {assetsComponentsServiceCaRoleYaml, map[string]*bintree{}},
				"rolebinding.yaml":        {assetsComponentsServiceCaRolebindingYaml, map[string]*bintree{}},
				"sa.yaml":                 {assetsComponentsServiceCaSaYaml, map[string]*bintree{}},
				"signing-cabundle.yaml":   {assetsComponentsServiceCaSigningCabundleYaml, map[string]*bintree{}},
				"signing-secret.yaml":     {assetsComponentsServiceCaSigningSecretYaml, map[string]*bintree{}},
			}},
		}},
		"core": {nil, map[string]*bintree{
			"0000_50_cluster-openshift-controller-manager_00_namespace.yaml": {assetsCore0000_50_clusterOpenshiftControllerManager_00_namespaceYaml, map[string]*bintree{}},
		}},
		"crd": {nil, map[string]*bintree{
			"0000_03_authorization-openshift_01_rolebindingrestriction.crd.yaml": {assetsCrd0000_03_authorizationOpenshift_01_rolebindingrestrictionCrdYaml, map[string]*bintree{}},
			"0000_03_config-operator_01_proxy.crd.yaml":                          {assetsCrd0000_03_configOperator_01_proxyCrdYaml, map[string]*bintree{}},
			"0000_03_quota-openshift_01_clusterresourcequota.crd.yaml":           {assetsCrd0000_03_quotaOpenshift_01_clusterresourcequotaCrdYaml, map[string]*bintree{}},
			"0000_03_security-openshift_01_scc.crd.yaml":                         {assetsCrd0000_03_securityOpenshift_01_sccCrdYaml, map[string]*bintree{}},
			"0000_10_config-operator_01_build.crd.yaml":                          {assetsCrd0000_10_configOperator_01_buildCrdYaml, map[string]*bintree{}},
			"0000_10_config-operator_01_featuregate.crd.yaml":                    {assetsCrd0000_10_configOperator_01_featuregateCrdYaml, map[string]*bintree{}},
			"0000_10_config-operator_01_image.crd.yaml":                          {assetsCrd0000_10_configOperator_01_imageCrdYaml, map[string]*bintree{}},
			"0000_10_config-operator_01_imagecontentsourcepolicy.crd.yaml":       {assetsCrd0000_10_configOperator_01_imagecontentsourcepolicyCrdYaml, map[string]*bintree{}},
			"0000_11_imageregistry-configs.crd.yaml":                             {assetsCrd0000_11_imageregistryConfigsCrdYaml, map[string]*bintree{}},
		}},
		"scc": {nil, map[string]*bintree{
			"0000_20_kube-apiserver-operator_00_scc-anyuid.yaml":           {assetsScc0000_20_kubeApiserverOperator_00_sccAnyuidYaml, map[string]*bintree{}},
			"0000_20_kube-apiserver-operator_00_scc-hostaccess.yaml":       {assetsScc0000_20_kubeApiserverOperator_00_sccHostaccessYaml, map[string]*bintree{}},
			"0000_20_kube-apiserver-operator_00_scc-hostmount-anyuid.yaml": {assetsScc0000_20_kubeApiserverOperator_00_sccHostmountAnyuidYaml, map[string]*bintree{}},
			"0000_20_kube-apiserver-operator_00_scc-hostnetwork.yaml":      {assetsScc0000_20_kubeApiserverOperator_00_sccHostnetworkYaml, map[string]*bintree{}},
			"0000_20_kube-apiserver-operator_00_scc-nonroot.yaml":          {assetsScc0000_20_kubeApiserverOperator_00_sccNonrootYaml, map[string]*bintree{}},
			"0000_20_kube-apiserver-operator_00_scc-privileged.yaml":       {assetsScc0000_20_kubeApiserverOperator_00_sccPrivilegedYaml, map[string]*bintree{}},
			"0000_20_kube-apiserver-operator_00_scc-restricted.yaml":       {assetsScc0000_20_kubeApiserverOperator_00_sccRestrictedYaml, map[string]*bintree{}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
