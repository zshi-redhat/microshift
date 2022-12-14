package assets

import (
	"context"
	"fmt"

	embedded "github.com/openshift/microshift/assets"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
)

var (
	coreScheme = runtime.NewScheme()
	coreCodecs = serializer.NewCodecFactory(coreScheme)
)

func init() {
	if err := corev1.AddToScheme(coreScheme); err != nil {
		panic(err)
	}
}

func coreClient(kubeconfigPath string) *coreclientv1.CoreV1Client {
	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		panic(err)
	}

	return coreclientv1.NewForConfigOrDie(rest.AddUserAgent(restConfig, "core-agent"))
}

type coreApplier struct {
	Client *coreclientv1.CoreV1Client
	object runtime.Object
}

func (ca *coreApplier) Reader(objBytes []byte, render RenderFunc, params RenderParams) {
	var err error
	if render != nil {
		objBytes, err = render(objBytes, params)
		if err != nil {
			panic(err)
		}
	}
	obj, err := runtime.Decode(coreCodecs.UniversalDecoder(corev1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(err)
	}
	ca.object = obj
}

func (ca *coreApplier) Applier() error {
	var err error
	kind := ca.object.GetObjectKind().GroupVersionKind().Kind
	switch kind {
	case "Namespace":
		_, _, err = resourceapply.ApplyNamespace(context.TODO(), ca.Client, assetsEventRecorder, ca.object.(*corev1.Namespace))
	case "Service":
		_, _, err = resourceapply.ApplyService(context.TODO(), ca.Client, assetsEventRecorder, ca.object.(*corev1.Service))
	case "ServiceAccount":
		_, _, err = resourceapply.ApplyServiceAccount(context.TODO(), ca.Client, assetsEventRecorder, ca.object.(*corev1.ServiceAccount))
	case "Secret":
		_, _, err = resourceapply.ApplySecret(context.TODO(), ca.Client, assetsEventRecorder, ca.object.(*corev1.Secret))
	case "ConfigMap":
		_, _, err = resourceapply.ApplyConfigMap(context.TODO(), ca.Client, assetsEventRecorder, ca.object.(*corev1.ConfigMap))
	}
	return err
}

func applyCore(cores []string, applier readerApplier, render RenderFunc, params RenderParams) error {
	lock.Lock()
	defer lock.Unlock()

	for _, core := range cores {
		klog.Infof("Applying corev1 api %s", core)
		objBytes, err := embedded.Asset(core)
		if err != nil {
			return fmt.Errorf("error getting asset %s: %v", core, err)
		}
		applier.Reader(objBytes, render, params)
		if err := applier.Applier(); err != nil {
			klog.Warningf("Failed to apply corev1 api %s: %v", core, err)
			return err
		}
	}

	return nil
}

func ApplyCoreResources(cores []string, render RenderFunc, params RenderParams, kubeconfigPath string) error {
	ca := &coreApplier{}
	ca.Client = coreClient(kubeconfigPath)
	return applyCore(cores, ca, render, params)
}

func ApplyConfigMapWithData(cmPath string, data map[string]string, kubeconfigPath string) error {
	ca := &coreApplier{}
	ca.Client = coreClient(kubeconfigPath)
	cmBytes, err := embedded.Asset(cmPath)
	if err != nil {
		return err
	}
	ca.Reader(cmBytes, nil, nil)
	ca.object.(*corev1.ConfigMap).Data = data
	return ca.Applier()
}

func ApplySecretWithData(secretPath string, data map[string][]byte, kubeconfigPath string) error {
	ca := &coreApplier{}
	ca.Client = coreClient(kubeconfigPath)
	secretBytes, err := embedded.Asset(secretPath)
	if err != nil {
		return err
	}
	ca.Reader(secretBytes, nil, nil)
	ca.object.(*corev1.Secret).Data = data
	return ca.Applier()
}
