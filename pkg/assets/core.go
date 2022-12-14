package assets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"html/template"
	"path/filepath"

	embedded "github.com/openshift/microshift/assets"
	"github.com/openshift/microshift/pkg/config"

	sccv1 "github.com/openshift/api/security/v1"
	sccclientv1 "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	sv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	appsclientv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	scv1 "k8s.io/client-go/kubernetes/typed/scheduling/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
)

var (
	resourceApplier *coreApplier
)

var templateFuncs = map[string]interface{}{
	"Dir":       filepath.Dir,
	"Sha256sum": func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) },
}

func init() {
	resourceApplier = &coreApplier{}
	kubeconfigPath := filepath.Join(config.DataDir, "resources", string(config.KubeAdmin), "kubeconfig")
	resourceApplier.coreClient = coreClient(kubeconfigPath)
	resourceApplier.appsClient = appsClient(kubeconfigPath)
	resourceApplier.rbacClient = k8sClient(kubeconfigPath)
	resourceApplier.pcClient = pcClient(kubeconfigPath)
	resourceApplier.sccClient = sccClient(kubeconfigPath)

}

func renderTemplate(tb []byte, data RenderParams) ([]byte, error) {
	tmpl, err := template.New("").Option("missingkey=error").Funcs(templateFuncs).Parse(string(tb))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func coreClient(kubeconfigPath string) *coreclientv1.CoreV1Client {
	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		panic(err)
	}
	return coreclientv1.NewForConfigOrDie(rest.AddUserAgent(restConfig, "core-agent"))
}

func appsClient(kubeconfigPath string) *appsclientv1.AppsV1Client {
	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		panic(err)
	}
	return appsclientv1.NewForConfigOrDie(rest.AddUserAgent(restConfig, "apps-agent"))
}

func k8sClient(kubeconfigPath string) *kubernetes.Clientset {
	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		panic(err)
	}
	return kubernetes.NewForConfigOrDie(rest.AddUserAgent(restConfig, "rbac-agent"))
}

func pcClient(kubeconfigPath string) *scv1.SchedulingV1Client {
	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		panic(err)
	}
	return scv1.NewForConfigOrDie(rest.AddUserAgent(restConfig, "pc-agent"))
}

func sccClient(kubeconfigPath string) *sccclientv1.SecurityV1Client {
	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		panic(err)
	}
	return sccclientv1.NewForConfigOrDie(rest.AddUserAgent(restConfig, "scc-agent"))
}

type coreApplier struct {
	coreClient *coreclientv1.CoreV1Client
	appsClient *appsclientv1.AppsV1Client
	rbacClient *kubernetes.Clientset
	pcClient   *scv1.SchedulingV1Client
	sccClient  *sccclientv1.SecurityV1Client
	object     runtime.Object
}

func (ca *coreApplier) Reader(objBytes []byte, render RenderFunc, params RenderParams) {
	var err error
	objBytes, err = render(objBytes, params)
	if err != nil {
		panic(err)
	}
	obj, _, _ := scheme.Codecs.UniversalDeserializer().Decode(objBytes, nil, nil)
	ca.object = obj
}

func (ca *coreApplier) Applier() error {
	var err error
	kind := ca.object.GetObjectKind().GroupVersionKind().Kind
	switch kind {
	case "Namespace":
		_, _, err = resourceapply.ApplyNamespace(context.TODO(), ca.coreClient, assetsEventRecorder, ca.object.(*corev1.Namespace))
	case "Service":
		_, _, err = resourceapply.ApplyService(context.TODO(), ca.coreClient, assetsEventRecorder, ca.object.(*corev1.Service))
	case "ServiceAccount":
		_, _, err = resourceapply.ApplyServiceAccount(context.TODO(), ca.coreClient, assetsEventRecorder, ca.object.(*corev1.ServiceAccount))
	case "Secret":
		_, _, err = resourceapply.ApplySecret(context.TODO(), ca.coreClient, assetsEventRecorder, ca.object.(*corev1.Secret))
	case "ConfigMap":
		_, _, err = resourceapply.ApplyConfigMap(context.TODO(), ca.coreClient, assetsEventRecorder, ca.object.(*corev1.ConfigMap))
	case "Deployment":
		_, _, err = resourceapply.ApplyDeployment(context.TODO(), ca.appsClient, assetsEventRecorder, ca.object.(*appsv1.Deployment), 0)
	case "DaemonSet":
		_, _, err = resourceapply.ApplyDaemonSet(context.TODO(), ca.appsClient, assetsEventRecorder, ca.object.(*appsv1.DaemonSet), 0)
	case "ClusterRole":
		_, _, err = resourceapply.ApplyClusterRole(context.TODO(), ca.rbacClient.RbacV1(), assetsEventRecorder, ca.object.(*rbacv1.ClusterRole))
	case "ClusterRoleBinding":
		_, _, err = resourceapply.ApplyClusterRoleBinding(context.TODO(), ca.rbacClient.RbacV1(), assetsEventRecorder, ca.object.(*rbacv1.ClusterRoleBinding))
	case "Role":
		_, _, err = resourceapply.ApplyRole(context.TODO(), ca.rbacClient.RbacV1(), assetsEventRecorder, ca.object.(*rbacv1.Role))
	case "RoleBinding":
		_, _, err = resourceapply.ApplyRoleBinding(context.TODO(), ca.rbacClient.RbacV1(), assetsEventRecorder, ca.object.(*rbacv1.RoleBinding))
	case "PriorityClass":
		// adapted from cvo
		existing, err := ca.pcClient.PriorityClasses().Get(context.TODO(), ca.object.(*sv1.PriorityClass).Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err := ca.pcClient.PriorityClasses().Create(context.TODO(), ca.object.(*sv1.PriorityClass), metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}

		var modified bool
		resourcemerge.EnsureObjectMeta(&modified, &existing.ObjectMeta, ca.object.(*sv1.PriorityClass).ObjectMeta)
		if !modified {
			return nil
		}
		_, err = ca.pcClient.PriorityClasses().Update(context.TODO(), existing, metav1.UpdateOptions{})
	case "SecurityContextConstraints":
		// adapted from cvo
		existing, err := ca.sccClient.SecurityContextConstraints().Get(context.TODO(), ca.object.(*sccv1.SecurityContextConstraints).Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err := ca.sccClient.SecurityContextConstraints().Create(context.TODO(), ca.object.(*sccv1.SecurityContextConstraints), metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}

		var modified bool
		resourcemerge.EnsureObjectMeta(&modified, &existing.ObjectMeta, ca.object.(*sccv1.SecurityContextConstraints).ObjectMeta)
		if !modified {
			return nil
		}

		_, err = ca.sccClient.SecurityContextConstraints().Update(context.TODO(), existing, metav1.UpdateOptions{})
		return err
	}
	return err
}

func applyCore(cores []string, applier readerApplier, params RenderParams) error {
	lock.Lock()
	defer lock.Unlock()

	for _, core := range cores {
		klog.Infof("Applying corev1 api %s", core)
		objBytes, err := embedded.Asset(core)
		if err != nil {
			return fmt.Errorf("error getting asset %s: %v", core, err)
		}
		applier.Reader(objBytes, renderTemplate, params)
		if err := applier.Applier(); err != nil {
			klog.Warningf("Failed to apply corev1 api %s: %v", core, err)
			return err
		}
	}

	return nil
}

func ApplyCoreResources(cores []string, render RenderFunc, params RenderParams, kubeconfigPath string) error {
	ca := &coreApplier{}
	ca.coreClient = coreClient(kubeconfigPath)
	return applyCore(cores, ca, params)
}

func ApplyConfigMapWithData(cmPath string, data map[string]string, kubeconfigPath string) error {
	ca := &coreApplier{}
	ca.coreClient = coreClient(kubeconfigPath)
	cmBytes, err := embedded.Asset(cmPath)
	if err != nil {
		return err
	}
	ca.Reader(cmBytes, renderTemplate, nil)
	ca.object.(*corev1.ConfigMap).Data = data
	return ca.Applier()
}

func ApplySecretWithData(secretPath string, data map[string][]byte, kubeconfigPath string) error {
	ca := &coreApplier{}
	ca.coreClient = coreClient(kubeconfigPath)
	secretBytes, err := embedded.Asset(secretPath)
	if err != nil {
		return err
	}
	ca.Reader(secretBytes, renderTemplate, nil)
	ca.object.(*corev1.Secret).Data = data
	return ca.Applier()
}
