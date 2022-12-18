package components

import (
	"github.com/openshift/microshift/pkg/config"
	"github.com/openshift/microshift/pkg/util"
	"k8s.io/klog/v2"
)

func startCNIPlugin(cfg *config.MicroshiftConfig, kubeconfigPath string) error {
	var err error
	switch cfg.Network.Type {
	case "OVNKubernetes":
		klog.Infof("Using OVNKubernetes CNI plugin")
		err = util.RunCommand("ovn-kubernetes", "--cluster-cidr", "10.42.0.0/16", "--service-cidr", "10.43.0.0/16")
	default:
		klog.Warningf("No network plugin specified, using default Bridge")
	}
	return err
}
