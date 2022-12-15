package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/openshift/microshift/pkg/util"
	"gopkg.in/yaml.v2"
	"k8s.io/klog/v2"
)

type OVNKubernetesPlugin struct {
	Name    string
	Version string
}

const (
	pluginVersion  = "0.1"
	pluginName     = "ovn-kubernetes"
	ConfigFileName = "ovn.yaml"
)

var Plugin OVNKubernetesPlugin

func init() {
	Plugin = OVNKubernetesPlugin{
		Name:    pluginName,
		Version: pluginVersion,
	}
}

func (p *OVNKubernetesPlugin) GetName() string {
	return p.Name
}

func (p *OVNKubernetesPlugin) GetVersion() string {
	return p.Version
}

func (p *OVNKubernetesPlugin) GetManifests() []map[string][]string {
	manifests := make([]map[string][]string, 0)

	manifests = append(manifests, map[string][]string{
		"namespace": []string{
			"/etc/microshift/ovn/namespace.yaml",
		},
	})
	manifests = append(manifests, map[string][]string{
		"serviceaccount": []string{
			"/etc/microshift/ovn/node/serviceaccount.yaml",
			"/etc/microshift/ovn/master/serviceaccount.yaml",
		},
	})
	manifests = append(manifests, map[string][]string{
		"role": []string{
			"/etc/microshift/ovn/role.yaml",
		},
	})
	manifests = append(manifests, map[string][]string{
		"rolebinding": []string{
			"/etc/microshift/ovn/rolebinding.yaml",
		},
	})
	manifests = append(manifests, map[string][]string{
		"clusterrole": []string{
			"/etc/microshift/ovn/clusterrole.yaml",
		},
	})
	manifests = append(manifests, map[string][]string{
		"clusterrolebinding": []string{
			"/etc/microshift/ovn/clusterrolebinding.yaml",
		},
	})
	manifests = append(manifests, map[string][]string{
		"configmap": []string{
			"/etc/microshift/ovn/configmap.yaml",
		},
	})
	manifests = append(manifests, map[string][]string{
		"daemonset": []string{
			"/etc/microshift/ovn/master/daemonset.yaml",
			"/etc/microshift/ovn/node/daemonset.yaml",
		},
	})

	return manifests
}

func (p *OVNKubernetesPlugin) GetRenderParams() map[string]string {
	params := make(map[string]string, 0)
	c, err := NewOVNKubernetesConfigFromFileOrDefault("/etc/microshift/ovn.yaml")
	if err != nil {
		return params
	}
	params["MTU"] = fmt.Sprint(c.MTU)
	return params
}

func (p *OVNKubernetesPlugin) ValidateConfig() bool {
	return true
}

func (p *OVNKubernetesPlugin) GetInitScript() []string {
	cmdStr := make([]string, 0)
	cmdStr = append(cmdStr, "configure-ovs.sh")
	cmdStr = append(cmdStr, "OVNKubernetes")
	return cmdStr
}

func (p *OVNKubernetesPlugin) PreStartHook() error {
	return util.RunCommand("configure-ovs.sh", "OVNKubernetes")
}

type OVNKubernetesConfig struct {
	// Configuration for microshift-ovs-init.service
	OVSInit OVSInit `json:"ovsInit,omitempty"`
	// MTU to use for the geneve tunnel interface.
	// This must be 100 bytes smaller than the uplink mtu.
	// Default is 1400.
	MTU uint32 `json:"mtu,omitempty"`
}

type OVSInit struct {
	// disable microshift-ovs-init.service.
	// OVS bridge "br-ex" needs to be configured manually when disableOVSInit is true.
	DisableOVSInit bool `json:"disableOVSInit,omitempty"`
	// Uplink interface for OVS bridge "br-ex"
	GatewayInterface string `json:"gatewayInterface,omitempty"`
	// Uplink interface for OVS bridge "br-ex1"
	ExternalGatewayInterface string `json:"externalGatewayInterface,omitempty"`
}

func (o *OVNKubernetesConfig) ValidateOVSBridge(bridge string) error {
	_, err := net.InterfaceByName(bridge)
	if err != nil {
		return err
	}
	return nil
}

func (o *OVNKubernetesConfig) withDefaults() *OVNKubernetesConfig {
	o.OVSInit.DisableOVSInit = false
	o.MTU = 1400
	return o
}

func newOVNKubernetesConfigFromFile(path string) (*OVNKubernetesConfig, error) {
	o := new(OVNKubernetesConfig)
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(buf, &o)
	if err != nil {
		return nil, fmt.Errorf("parsing OVNKubernetes config: %v", err)
	}
	return o, nil
}

func NewOVNKubernetesConfigFromFileOrDefault(path string) (*OVNKubernetesConfig, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			klog.Info("OVNKubernetes config file not found, assuming default values")
			return new(OVNKubernetesConfig).withDefaults(), nil
		}
		return nil, fmt.Errorf("failed to get OVNKubernetes config file: %v", err)
	}

	o, err := newOVNKubernetesConfigFromFile(path)
	if err == nil {
		klog.Info("got OVNKubernetes config from file %q", path)
		return o, nil
	}
	return nil, fmt.Errorf("getting OVNKubernetes config: %v", err)
}
