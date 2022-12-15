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
	GetRenderParams() map[string]string
	ValidateConfig() bool
	GetInitScript() []string
	PreStartHook() error
}

func startCNIPlugin(cfg *config.MicroshiftConfig, kubeconfigPath string, plugin CNIPlugin) error {
	if !plugin.ValidateConfig() {
		return fmt.Errorf("failed to validate %s CNI config", plugin.GetName())
	}

	// cniScript := plugin.GetInitScript()

	// if err := util.RunCommand(cniScript[0], cniScript[1:]...); err != nil {
	// 	return err
	// }

	err := plugin.PreStartHook()
	if err != nil {
		return err
	}

	extraParams := assets.RenderParams{
		"KubeconfigPath": kubeconfigPath,
		"KubeconfigDir":  filepath.Join(microshiftDataDir, "/resources/kubeadmin"),
	}

	cniParams := plugin.GetRenderParams()
	for k, v := range cniParams {
		extraParams[k] = v
	}

	manifests := plugin.GetManifests()
	for _, v := range manifests {
		for kind, manifest := range v {
			switch kind {
			case "namespace":
				if err := assets.ApplyNamespaces(manifest, kubeconfigPath, false); err != nil {
					klog.Warningf("Failed to apply namespace %v: %v", manifest, err)
					return err
				}
			case "serviceaccount":
				if err := assets.ApplyServiceAccounts(manifest, kubeconfigPath, false); err != nil {
					klog.Warningf("Failed to apply serviceAccount %v %v", manifest, err)
					return err
				}
			case "role":
				if err := assets.ApplyRoles(manifest, kubeconfigPath, false); err != nil {
					klog.Warningf("Failed to apply role %v: %v", manifest, err)
					return err
				}
			case "rolebinding":
				if err := assets.ApplyRoleBindings(manifest, kubeconfigPath, false); err != nil {
					klog.Warningf("Failed to apply rolebinding %v: %v", manifest, err)
					return err
				}
			case "clusterrole":
				if err := assets.ApplyClusterRoles(manifest, kubeconfigPath, false); err != nil {
					klog.Warningf("Failed to apply clusterRole %v %v", manifest, err)
					return err
				}
			case "clusterrolebinding":
				if err := assets.ApplyClusterRoleBindings(manifest, kubeconfigPath, false); err != nil {
					klog.Warningf("Failed to apply clusterRoleBinding %v %v", manifest, err)
					return err
				}
			case "configmap":
				if err := assets.ApplyConfigMaps(manifest, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath, false); err != nil {
					klog.Warningf("Failed to apply configMap %v %v", manifest, err)
					return err
				}
			case "daemonset":
				if err := assets.ApplyDaemonSets(manifest, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath, false); err != nil {
					klog.Warningf("Failed to apply apps %v %v", manifest, err)
					return err
				}
			}
		}
	}
	return nil
}
