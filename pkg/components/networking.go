package components

import (
	"fmt"
	"path/filepath"

	"github.com/openshift/microshift/pkg/assets"
	"github.com/openshift/microshift/pkg/config"
	"k8s.io/klog/v2"
)

type CNIPlugin interface {
	GetName() string
	GetVersion() string
	GetManifests() []map[string][]string
	GetRenderParams() string
	ValidateConfig() bool
}

func startCNIPlugin(cfg *config.MicroshiftConfig, kubeconfigPath string, plugin CNIPlugin) error {
	if !plugin.ValidateConfig() {
		return fmt.Errorf("failed to validate %s CNI config", plugin.GetName())
	}

	mtu := plugin.GetRenderParams()
	extraParams := assets.RenderParams{
		"MTU":            mtu,
		"KubeconfigPath": kubeconfigPath,
		"KubeconfigDir":  filepath.Join(microshiftDataDir, "/resources/kubeadmin"),
	}

	manifests := plugin.GetManifests()
	for _, v := range manifests {
		for kind, manifest := range v {
			switch kind {
			case "namespace":
				if err := assets.ApplyNamespaces(manifest, kubeconfigPath); err != nil {
					klog.Warningf("Failed to apply namespace %v: %v", manifest, err)
					return err
				}
			case "serviceaccount":
				if err := assets.ApplyServiceAccounts(manifest, kubeconfigPath); err != nil {
					klog.Warningf("Failed to apply serviceAccount %v %v", manifest, err)
					return err
				}
			case "role":
				if err := assets.ApplyRoles(manifest, kubeconfigPath); err != nil {
					klog.Warningf("Failed to apply role %v: %v", manifest, err)
					return err
				}
			case "rolebinding":
				if err := assets.ApplyRoleBindings(manifest, kubeconfigPath); err != nil {
					klog.Warningf("Failed to apply rolebinding %v: %v", manifest, err)
					return err
				}
			case "clusterrole":
				if err := assets.ApplyClusterRoles(manifest, kubeconfigPath); err != nil {
					klog.Warningf("Failed to apply clusterRole %v %v", manifest, err)
					return err
				}
			case "clusterrolebinding":
				if err := assets.ApplyClusterRoleBindings(manifest, kubeconfigPath); err != nil {
					klog.Warningf("Failed to apply clusterRoleBinding %v %v", manifest, err)
					return err
				}
			case "configmap":
				if err := assets.ApplyConfigMaps(manifest, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
					klog.Warningf("Failed to apply configMap %v %v", manifest, err)
					return err
				}
			case "daemonset":
				if err := assets.ApplyDaemonSets(manifest, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
					klog.Warningf("Failed to apply apps %v %v", manifest, err)
					return err
				}
			}
		}
	}
	return nil
}
