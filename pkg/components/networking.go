package components

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openshift/microshift/pkg/assets"
	"github.com/openshift/microshift/pkg/config"
	"github.com/openshift/microshift/pkg/config/ovn"
	"github.com/openshift/microshift/pkg/util/cryptomaterial"
	"k8s.io/klog/v2"
)

func startCNIPlugin(cfg *config.MicroshiftConfig, kubeconfigPath string) error {
	var (
		ns = []string{
			"components/ovn/namespace.yaml",
		}
		sa = []string{
			"components/ovn/node/serviceaccount.yaml",
			"components/ovn/master/serviceaccount.yaml",
		}
		r = []string{
			"components/ovn/role.yaml",
		}
		rb = []string{
			"components/ovn/rolebinding.yaml",
		}
		cr = []string{
			"components/ovn/clusterrole.yaml",
		}
		crb = []string{
			"components/ovn/clusterrolebinding.yaml",
		}
		cm = []string{
			"components/ovn/configmap.yaml",
		}
		svc = []string{
			"components/ovn/service.yaml",
		}
		apps = []string{
			"components/ovn/master/daemonset.yaml",
			"components/ovn/node/daemonset.yaml",
		}
		// secret = "components/ovn/secret-ovn-cert.yaml"
		// cacm   = "components/ovn/configmap-ovn-ca.yaml"
	)

	serviceCADir := cryptomaterial.ServiceCADir(cryptomaterial.CertsDirectory(microshiftDataDir))
	caCertPath := cryptomaterial.CACertPath(serviceCADir)
	caKeyPath := cryptomaterial.CAKeyPath(serviceCADir)

	cmData := map[string]string{}
	secretData := map[string][]byte{}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return err
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return err
	}
	cmData["ca-bundle.crt"] = string(caCertPEM)
	secretData["tls.crt"] = caCertPEM
	secretData["tls.key"] = caKeyPEM

	ovnConfig, err := ovn.NewOVNKubernetesConfigFromFileOrDefault(filepath.Dir(config.DefaultGlobalConfigFile))
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
	extraParams := assets.RenderParams{
		"OVNConfig":        ovnConfig,
		"KubeconfigPath":   kubeconfigPath,
		"KubeconfigDir":    filepath.Join(microshiftDataDir, "/resources/kubeadmin"),
		"OVN_NB_DB_LIST":   fmt.Sprintf("ssl:%s:%s", cfg.NodeIP, ovn.OVN_NB_PORT),
		"OVN_SB_DB_LIST":   fmt.Sprintf("ssl:%s:%s", cfg.NodeIP, ovn.OVN_SB_PORT),
		"OVN_NB_PORT":      ovn.OVN_NB_PORT,
		"OVN_SB_PORT":      ovn.OVN_SB_PORT,
		"OVN_NB_RAFT_PORT": ovn.OVN_NB_RAFT_PORT,
		"OVN_SB_RAFT_PORT": ovn.OVN_SB_RAFT_PORT,
	}
	if err := assets.ApplyConfigMaps(cm, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply configMap %v %v", cm, err)
		return err
	}
	// if err := assets.ApplyConfigMapWithData(cacm, cmData, kubeconfigPath); err != nil {
	// 	klog.Warningf("Failed to apply configMap %v: %v", cacm, err)
	// 	return err
	// }
	// if err := assets.ApplySecretWithData(secret, secretData, kubeconfigPath); err != nil {
	// 	klog.Warningf("Failed to apply secret %v: %v", secret, err)
	// 	return err
	// }
	if err := assets.ApplyServices(svc, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply service %v %v", svc, err)
		return err
	}
	if err := assets.ApplyDaemonSets(apps, renderTemplate, renderParamsFromConfig(cfg, extraParams), kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply apps %v %v", apps, err)
		return err
	}
	return nil
}
