package components

import (
	"fmt"
	"path/filepath"
	"plugin"

	"github.com/openshift/microshift/pkg/config"
	"k8s.io/klog/v2"
)

var (
	microshiftDataDir = config.GetDataDir()
	cniPluginDir      = "/etc/microshift/plugins"
)

func loadCNIPlugin(path string) (CNIPlugin, error) {
	klog.Infof("loadCNIPlugin(): load CNI plugin from %s", path)
	p, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}

	symbol, err := p.Lookup("Plugin")
	if err != nil {
		return nil, err
	}

	cni, ok := symbol.(CNIPlugin)
	if !ok {
		return nil, fmt.Errorf("unable to load CNI plugin")
	}

	return cni, nil
}

func StartComponents(cfg *config.MicroshiftConfig) error {
	var cni CNIPlugin
	var err error
	kubeAdminConfig := cfg.KubeConfigPath(config.KubeAdmin)

	if err = startServiceCAController(cfg, kubeAdminConfig); err != nil {
		klog.Warningf("Failed to start service-ca controller: %v", err)
		return err
	}

	if err = startCSIPlugin(cfg, cfg.KubeConfigPath(config.KubeAdmin)); err != nil {
		klog.Warningf("Failed to start csi plugin: %v", err)
		return err
	}

	if err = startIngressController(cfg, kubeAdminConfig); err != nil {
		klog.Warningf("Failed to start ingress router controller: %v", err)
		return err
	}
	if err = startDNSController(cfg, kubeAdminConfig); err != nil {
		klog.Warningf("Failed to start DNS controller: %v", err)
		return err
	}

	if cni, err = loadCNIPlugin(filepath.Join(cniPluginDir, "ovn_kubernetes_plugin.so")); err != nil {
		klog.Warningf("Failed to load CNI plugin: %v", err)
		return err
	}

	if err = startCNIPlugin(cfg, kubeAdminConfig, cni); err != nil {
		klog.Warningf("Failed to start CNI plugin: %v", err)
		return err
	}
	return nil
}
