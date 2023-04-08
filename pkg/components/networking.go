package components

import (
	"fmt"
	"path/filepath"

	"github.com/openshift/microshift/pkg/assets"
	"github.com/openshift/microshift/pkg/config"
	"github.com/openshift/microshift/pkg/config/ovn"
	"k8s.io/klog/v2"
)

func startCNIPlugin(cfg *config.Config, kubeconfigPath string) error {
	var (
		ns = []string{
			"components/ovn/common/namespace.yaml",
		}
		sa = []string{
			"components/ovn/common/master-serviceaccount.yaml",
			"components/ovn/common/node-serviceaccount.yaml",
		}
		r = []string{
			"components/ovn/common/role.yaml",
		}
		rb = []string{
			"components/ovn/common/rolebinding.yaml",
		}
		cr = []string{
			"components/ovn/common/clusterrole.yaml",
		}
		crb = []string{
			"components/ovn/common/clusterrolebinding.yaml",
		}
		cm = []string{
			"components/ovn/common/configmap.yaml",
		}
		apps = []string{
			"components/ovn/single-node/master/daemonset.yaml",
			"components/ovn/single-node/node/daemonset.yaml",
		}
	)

	if cfg.MultiNode.Enabled {
		apps = []string{
			"components/ovn/multi-node/master/daemonset.yaml",
			"components/ovn/multi-node/node/daemonset.yaml",
		}
	}

	ovnConfig, err := ovn.NewOVNKubernetesConfigFromFileOrDefault(filepath.Dir(config.ConfigFile), cfg.MultiNode.Enabled)
	if err != nil {
		return err
	}

	if err := ovnConfig.Validate(); err != nil {
		return fmt.Errorf("failed to validate ovn-kubernetes configurations %v", err)
	}

	if err := assets.ApplyNamespaces(ns, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply ns %v: %v", ns, err)
		return err
	}
	if err := assets.ApplyServiceAccounts(sa, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply serviceAccount %v %v", sa, err)
		return err
	}
	if err := assets.ApplyRoles(r, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply role %v: %v", r, err)
		return err
	}
	if err := assets.ApplyRoleBindings(rb, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply rolebinding %v: %v", rb, err)
		return err
	}
	if err := assets.ApplyClusterRoles(cr, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply clusterRole %v %v", cr, err)
		return err
	}
	if err := assets.ApplyClusterRoleBindings(crb, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply clusterRoleBinding %v %v", crb, err)
		return err
	}

	// Multinode only params: OVN_NB_DB_LIST, OVN_SB_DB_LIST, OVN_NB_PORT, OVN_SB_PORT, OVN_NB_RAFT_PORT, OVN_SB_RAFT_PORT
	extraParams := assets.RenderParams{
		"OVNConfig":      ovnConfig,
		"KubeconfigPath": kubeconfigPath,
		"KubeconfigDir":  filepath.Join(microshiftDataDir, "/resources/kubeadmin"),
		"OVN_NB_DB_LIST": fmt.Sprintf("tcp:%s:%s", cfg.MultiNode.Master, ovn.OVN_NB_PORT),
		"OVN_SB_DB_LIST": fmt.Sprintf("tcp:%s:%s", cfg.MultiNode.Master, ovn.OVN_SB_PORT),
		"OVN_NB_PORT":    ovn.OVN_NB_PORT,
		"OVN_SB_PORT":    ovn.OVN_SB_PORT,
	}
	if err := assets.ApplyConfigMaps(cm, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply configMap %v %v", cm, err)
		return err
	}
	if err := assets.ApplyDaemonSets(apps, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply apps %v %v", apps, err)
		return err
	}
	return nil
}
