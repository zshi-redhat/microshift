package components

import (
	"github.com/openshift/microshift/pkg/assets"
	"github.com/openshift/microshift/pkg/config"
	"k8s.io/klog/v2"
)

func startOVNKubernetes(cfg *config.MicroshiftConfig, kubeconfigPath string) error {
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
		}
		ds = []string{
			"assets/components/ovn/master/daemonset.yaml",
			"assets/components/ovn/node/daemonset.yaml",
		}
	)

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
	if err := assets.ApplyDaemonSets(ds, renderReleaseImage, nil, kubeconfigPath); err != nil {
		klog.Warningf("Failed to apply daemonSet %v %v", ds, err)
		return err
	}
	return nil
}
