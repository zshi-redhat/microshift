package components

import (
	"os"

	"github.com/openshift/microshift/pkg/assets"
	"github.com/openshift/microshift/pkg/config"
	"k8s.io/klog/v2"
)

func startOVN(cfg *config.MicroshiftConfig, kubeconfigPath string) error {
	var (
		ns = []string{
			"assets/components/ovn/namespace.yaml",
		}
		sa = []string{
			"assets/components/ovn/node/serviceaccount.yaml",
			"assets/components/ovn/master/serviceaccount.yaml",
		}
		r = []string{
			"assets/components/ovn/role.yaml",
		}
		rb = []string{
			"assets/components/ovn/rolebinding.yaml",
		}
		cr = []string{
			"assets/components/ovn/clusterrole.yaml",
		}
		crb = []string{
			"assets/components/ovn/clusterrolebinding.yaml",
		}
		cm = []string{
			"assets/components/ovn/configmap.yaml",
			"assets/components/ovn/configmap-ovn-ca.yaml",
		}
		svc = []string{
			"assets/components/ovn/service.yaml",
		}
		ds = []string{
			"assets/components/ovn/master/daemonset.yaml",
			"assets/components/ovn/node/daemonset.yaml",
		}
		secret = "assets/components/ovn/secret-ovn-cert.yaml"
		cacm   = "assets/components/ovn/configmap-ovn-ca.yaml"
	)

	cmData := map[string]string{}
	caPath := cfg.DataDir + "/certs/ca-bundle/ca-bundle.crt"
	cabundle, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	cmData["ca-bundle.crt"] = string(cabundle)

	secretData := map[string][]byte{}
	tlsCrtPath := cfg.DataDir + "/resources/openshift-ovn-kubernetes/secrets/tls.crt"
	tlsKeyPath := cfg.DataDir + "/resources/openshift-ovn-kubernetes/secrets/tls.key"
	tlscrt, err := os.ReadFile(tlsCrtPath)
	if err != nil {
		return err
	}
	tlskey, err := os.ReadFile(tlsKeyPath)
	if err != nil {
		return err
	}
	secretData["tls.crt"] = tlscrt
	secretData["tls.key"] = tlskey

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
	if err := assets.ApplyConfigMaps(cm, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply configMap %v %v", cm, err)
		return err
	}
	if err := assets.ApplyConfigMapWithData(cacm, cmData, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply sa %v: %v", cacm, err)
		return err
	}
	if err := assets.ApplySecretWithData(secret, secretData, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply secret %v: %v", secret, err)
		return err
	}
	if err := assets.ApplyServices(svc, nil, nil, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply service %v %v", svc, err)
		return err
	}
	if err := assets.ApplyDaemonSets(ds, renderReleaseImage, nil, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply daemonSet %v %v", ds, err)
		return err
	}
	return nil
}

func startFlannel(kubeconfigPath string) error {
	var (
		// psp = []string{
		// 	"assets/components/flannel/podsecuritypolicy.yaml",
		// }
		cr = []string{
			"assets/components/flannel/clusterrole.yaml",
		}
		crb = []string{
			"assets/components/flannel/clusterrolebinding.yaml",
		}
		sa = []string{
			"assets/components/flannel/service-account.yaml",
		}
		cm = []string{
			"assets/components/flannel/configmap.yaml",
		}
		ds = []string{
			"assets/components/flannel/daemonset.yaml",
		}
	)

	if err := assets.ApplyClusterRoles(cr, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply clusterRole %v %v", cr, err)
		return err
	}
	if err := assets.ApplyClusterRoleBindings(crb, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply clusterRoleBinding %v %v", crb, err)
		return err
	}
	if err := assets.ApplyServiceAccounts(sa, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply serviceAccount %v %v", sa, err)
		return err
	}
	if err := assets.ApplyConfigMaps(cm, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply configMap %v %v", cm, err)
		return err
	}
	if err := assets.ApplyDaemonSets(ds, renderReleaseImage, nil, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply daemonSet %v %v", ds, err)
		return err
	}
	return nil

}
