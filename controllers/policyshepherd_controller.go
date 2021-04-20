/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyv1alpha1 "github.com/open-cluster-management/policy-shepherd/api/v1alpha1"
)

// PolicyShepherdReconciler reconciles a PolicyShepherd object
type PolicyShepherdReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

var freq uint = 60
var reconciler *PolicyShepherdReconciler
var deletedPolicies []string

var policiesMap map[string]policyv1alpha1.PolicyShepherd

const grcCategory = "system-and-information-integrity"

// Reconcile the policy with the latest content
// +kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policyshepherds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policyshepherds/status,verbs=get;update;patch
func (r *PolicyShepherdReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("policyshepherd", req.NamespacedName)

	if reconciler == nil {
		reconciler = r
		policiesMap = make(map[string]policyv1alpha1.PolicyShepherd)
		deletedPolicies = make([]string, 0, 10)
		go PeriodicCheckPolicies(false)
	}

	shepherd := &policyv1alpha1.PolicyShepherd{}
	err := r.Client.Get(context.TODO(), req.NamespacedName, shepherd)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			handleRemovingPolicy(req.NamespacedName.Name, req.NamespacedName.Namespace)
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	if shepherd.ObjectMeta.DeletionTimestamp.IsZero() {
		updateNeeded := false
		if !ensureDefaultLabel(shepherd) {
			updateNeeded = true
		}
		if updateNeeded {
			if err := r.Client.Update(context.Background(), shepherd); err != nil {
				return reconcile.Result{Requeue: true}, nil
			}
		}
		shepherd.Status.Status = policyv1alpha1.Pending //reset Status

		r.Log.Info("New ShepherdPolicy was found, adding it...")
		handleAddingPolicy(shepherd)

	}
	r.Log.Info("Reconcile complete.")
	return ctrl.Result{}, nil
}

// PeriodicCheckPolicies makes sure policies have been applied to ACS periodically
func PeriodicCheckPolicies(exitExecLoop bool) {
	for {
		start := time.Now()
		printMap(policiesMap)

		for _, policy := range policiesMap {
			if policy.Status.DeleteStatus == nil {
				policy.Status.DeleteStatus = make([]policyv1alpha1.PolicyUpdateStatus, len(policy.Spec.DeletePolicyList))
			}
			if policy.Status.CreateStatus == nil {
				policy.Status.CreateStatus = make([]policyv1alpha1.PolicyUpdateStatus, len(policy.Spec.CreatePolicyList))
			}
			if policy.Status.EnableStatus == nil {
				policy.Status.EnableStatus = make([]policyv1alpha1.PolicyUpdateStatus, len(policy.Spec.EnablePolicyList))
			}
			if policy.Status.DisableStatus == nil {
				policy.Status.DisableStatus = make([]policyv1alpha1.PolicyUpdateStatus, len(policy.Spec.DisablePolicyList))
			}

			// Process the policy specification
			update, err := processACSPolicies(&policy)

			// Update the Policy Status based on processed results
			if update || err != nil {
				if err != nil {
					policy.Status.Status = policyv1alpha1.Failed
				} else {
					policy.Status.Status = getPolicyStatus(policy)
				}
				//update status of all policies that changed:
				err := reconciler.Client.Status().Update(context.TODO(), &policy)
				if err != nil {
					reconciler.Log.Error(err, "Reason: shepherd update error: ",
						"namespace", policy.Namespace, "name", policy.Name)
				}
			}
		}

		//check if continue
		if exitExecLoop == true {
			return
		}
		//making sure that if processing is > freq we don't sleep
		//if freq > processing we sleep for the remaining duration
		elapsed := time.Since(start) / 1000000000 // convert to seconds
		if float64(freq) > float64(elapsed) {
			remainingSleep := float64(freq) - float64(elapsed)
			time.Sleep(time.Duration(remainingSleep) * time.Second)
		}
	}
}

func containsPolicyState(s []policyv1alpha1.PolicyState, e policyv1alpha1.PolicyState) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func getPolicyStatus(policy policyv1alpha1.PolicyShepherd) policyv1alpha1.PolicyState {
	list := make([]policyv1alpha1.PolicyState, 4)
	list[0] = getPolicyUpdateStatus(policy.Status.DeleteStatus)
	list[1] = getPolicyUpdateStatus(policy.Status.CreateStatus)
	list[2] = getPolicyUpdateStatus(policy.Status.EnableStatus)
	list[3] = getPolicyUpdateStatus(policy.Status.DisableStatus)
	if containsPolicyState(list, policyv1alpha1.Failed) {
		return policyv1alpha1.Failed
	}
	if containsPolicyState(list, policyv1alpha1.Pending) {
		return policyv1alpha1.Pending
	}
	return policyv1alpha1.Completed
}

func getPolicyUpdateStatus(status []policyv1alpha1.PolicyUpdateStatus) policyv1alpha1.PolicyState {
	s := policyv1alpha1.Completed
	for _, pstat := range status {
		if pstat.UploadStatus == policyv1alpha1.Failed {
			return policyv1alpha1.Failed
		}
		if pstat.UploadStatus == policyv1alpha1.Pending {
			s = policyv1alpha1.Pending
		}
	}
	return s
}

func printMap(myMap map[string]policyv1alpha1.PolicyShepherd) {
	if len(myMap) == 0 {
		fmt.Println("Waiting for shepherd policies to be available for processing... ")
		return
	}
	fmt.Println("Available shepherd policies: ")
	for key := range myMap {
		fmt.Printf("policy = %v \n", key)
	}
}

func handleAddingPolicy(policy *policyv1alpha1.PolicyShepherd) {
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	policiesMap[key] = *policy
}

func handleRemovingPolicy(name string, namespace string) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	delete(policiesMap, key)
}

func ensureDefaultLabel(instance *policyv1alpha1.PolicyShepherd) (updateNeeded bool) {
	//we need to ensure this label exists -> category: "System and Information Integrity"
	if instance.ObjectMeta.Labels == nil {
		newlbl := make(map[string]string)
		newlbl["category"] = grcCategory
		instance.ObjectMeta.Labels = newlbl
		return true
	}
	if _, ok := instance.ObjectMeta.Labels["category"]; !ok {
		instance.ObjectMeta.Labels["category"] = grcCategory
		return true
	}
	if instance.ObjectMeta.Labels["category"] != grcCategory {
		instance.ObjectMeta.Labels["category"] = grcCategory
		return true
	}
	return false
}

// SetupWithManager sets up the controller
func (r *PolicyShepherdReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.PolicyShepherd{}).
		Complete(r)
}

// Returns the API Key for the ACS Server.
func getAPIKey() (string, error) {
	token := os.Getenv("ROX_API_TOKEN")
	if len(token) == 0 {
		return token, errors.NewBadRequest("The ROX_API_TOKEN is not valid")
	}
	return token, nil
}

// getHTTPClient creates a HTTP Client that
func getHTTPClient() *http.Client {
	client := &http.Client{Timeout: time.Second * 10}

	caCertPool := x509.NewCertPool()
	caCertFile, found := os.LookupEnv("CA_CERT_FILE")
	insecure := false
	if found {
		caCert, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			caCertPool.AppendCertsFromPEM(caCert)
		}
	} else {
		// allow insecure certs for now if the CA is not provided
		insecure = true
	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: insecure,
			},
		},
	}
	return client
}

// getStackroxHostname get the stackrox central server hostname and port to use
func getStackroxHostname() string {
	host := "central.stackrox:443"
	envHost, found := os.LookupEnv("ACS_HOST")
	if found {
		host = envHost
	}
	return host
}

// processACSPolicies handles updating the ACS policy based on the PolicyShepherd
// policy spec to create, delete, enable or disable the policy.
func processACSPolicies(shepherd *policyv1alpha1.PolicyShepherd) (bool, error) {

	update := false
	_, err := getAPIKey()
	if err != nil {
		reconciler.Log.Error(err, "Failed to obtain the required ACS API key in the environment as ROX_API_TOKEN.")
		return update, err
	}

	list, err := getPolicyList()
	if err != nil {
		reconciler.Log.Error(err, "Failed to obtain the list of ACS policies.")
		return update, err
	}

	// delete policies in the spec
	for index, policyName := range shepherd.Spec.DeletePolicyList {
		if ok, id, _ := doesPolicyExist(list, policyName); ok {
			if contains(deletedPolicies, policyName) {
				reconciler.Log.Info("The policy was previously deleted and will not be deleted again", "name", policyName)
			} else {
				reconciler.Log.Info("The policy exists in ACS so will be deleted", "name", policyName, "id", id)
				deletePolicy(id)
				deletedPolicies = append(deletedPolicies, policyName)
			}
			shepherd.Status.DeleteStatus[index].Name = policyName
			shepherd.Status.DeleteStatus[index].UploadStatus = policyv1alpha1.Completed
		} else {
			shepherd.Status.DeleteStatus[index].Name = policyName
			shepherd.Status.DeleteStatus[index].UploadStatus = policyv1alpha1.Completed
		}
	}

	// assuming the policy list and the status list are 1:1
	for index, jsonstring := range shepherd.Spec.CreatePolicyList {
		var policyName string
		var objectDef map[string]interface{}
		err := json.Unmarshal([]byte(jsonstring), &objectDef)
		if err != nil {
			reconciler.Log.Error(err, "Failed to decode the Policy resource", "index", index)
			shepherd.Status.CreateStatus[index].Name = "Unknown"
			shepherd.Status.CreateStatus[index].UploadStatus = policyv1alpha1.Failed
		} else if val, ok := objectDef["name"]; ok {
			policyName = fmt.Sprintf("%s", val)
			reconciler.Log.Info("Obtained policy name from ACS Policy: ", "name", policyName)
			if ok, id, _ := doesPolicyExist(list, policyName); ok {
				reconciler.Log.Info("The policy already exists in ACS", "id", id)
				shepherd.Status.CreateStatus[index].Name = policyName
				shepherd.Status.CreateStatus[index].UploadStatus = policyv1alpha1.Completed
			} else {
				id, err := createPolicy(jsonstring)
				shepherd.Status.CreateStatus[index].Name = policyName
				if err != nil {
					reconciler.Log.Error(err, "Failed to create the policy.", "name", policyName)
					shepherd.Status.CreateStatus[index].UploadStatus = policyv1alpha1.Failed
				} else {
					reconciler.Log.Info("The policy was created in ACS", "id", id, "name", policyName)
					shepherd.Status.CreateStatus[index].UploadStatus = policyv1alpha1.Completed
				}
			}
		}
	}

	// disable policies
	for index, policyName := range shepherd.Spec.DisablePolicyList {
		if ok, id, entry := doesPolicyExist(list, policyName); ok {
			reconciler.Log.Info("The policy exists in ACS so it will be disabled", "name", policyName, "id", id)
			err = setPolicyDisabled(entry, id, true)
			shepherd.Status.DisableStatus[index].Name = policyName
			if err != nil {
				shepherd.Status.DisableStatus[index].UploadStatus = policyv1alpha1.Failed
			} else {
				shepherd.Status.DisableStatus[index].UploadStatus = policyv1alpha1.Completed
			}
		} else {
			// What is the status if the policy to disable does not exist - assuming OK since
			// a missing policy is definitely disabled
			shepherd.Status.DisableStatus[index].Name = policyName
			shepherd.Status.DisableStatus[index].UploadStatus = policyv1alpha1.Completed
		}
	}

	// enable policies
	for index, policyName := range shepherd.Spec.EnablePolicyList {
		if ok, id, entry := doesPolicyExist(list, policyName); ok {
			reconciler.Log.Info("The policy exists in ACS so it will be enabled", "name", policyName, "id", id)
			err = setPolicyDisabled(entry, id, false)
			shepherd.Status.EnableStatus[index].Name = policyName
			if err != nil {
				shepherd.Status.EnableStatus[index].UploadStatus = policyv1alpha1.Failed
			} else {
				shepherd.Status.EnableStatus[index].UploadStatus = policyv1alpha1.Completed
			}
		} else {
			// What is the status if the policy to enable does not exist - assuming Failed since
			// a missing policy is definitely not enabled
			shepherd.Status.EnableStatus[index].Name = policyName
			shepherd.Status.EnableStatus[index].UploadStatus = policyv1alpha1.Failed
		}
	}

	// the processing is done, errors are in the status fields of the policies
	return true, nil
}

func setPolicyDisabled(acspolicy map[string]interface{}, id string, flag bool) error {
	var err error
	if isPolicyDisabled(acspolicy) == flag {
		reconciler.Log.Info("The policy enablement is correct", "id", id, "disabled", flag)
		return err
	}

	url := fmt.Sprintf("https://%s/v1/policies/%s", getStackroxHostname(), id)
	policy := fmt.Sprintf("{\"id\":\"%s\",\"disabled\":%t}", id, flag)
	req, err := http.NewRequest(http.MethodPatch, url, strings.NewReader(policy))
	if err != nil {
		reconciler.Log.Error(err, "Error reading request.")
		return err
	}

	err = setHeaders(req)
	if err != nil {
		reconciler.Log.Error(err, "Error obtaining the ACS API token")
		return err
	}
	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		reconciler.Log.Error(err, "Error reading response.")
		return err
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		reconciler.Log.Error(err, "Error reading response body.")
		return err
	}
	reconciler.Log.Info("Response from patch policy request to ACS: ", "responseBody", string(responseBody))

	if resp.StatusCode >= 400 {
		err = errors.NewBadRequest("error response code returned by REST Stackrox policy patch call " + fmt.Sprint(resp.StatusCode))
		reconciler.Log.Error(err, "Error returned from Stackrox Central query: ", "StatusCode", resp.StatusCode)
		return err
	}
	return err
}

func deletePolicy(id string) error {
	var err error

	url := fmt.Sprintf("https://%s/v1/policies/%s", getStackroxHostname(), id)
	req, err := http.NewRequest(http.MethodDelete, url, http.NoBody)
	if err != nil {
		reconciler.Log.Error(err, "Error reading request.")
		return err
	}

	err = setHeaders(req)
	if err != nil {
		reconciler.Log.Error(err, "Error obtaining the ACS API token")
		return err
	}
	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		reconciler.Log.Error(err, "Error reading response.")
		return err
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		reconciler.Log.Error(err, "Error reading response body.")
		return err
	}
	reconciler.Log.Info("Response from delete policy request to ACS: ", "responseBody", string(responseBody))

	if resp.StatusCode >= 400 {
		err = errors.NewBadRequest("error response code returned by REST Stackrox policy delete call " + fmt.Sprint(resp.StatusCode))
		reconciler.Log.Error(err, "Error returned from Stackrox Central query: ", "StatusCode", resp.StatusCode)
		return err
	}
	return err
}

func isPolicyDisabled(acspolicy map[string]interface{}) bool {
	return acspolicy["disabled"].(bool)
}

func setHeaders(request *http.Request) error {
	token, err := getAPIKey()
	request.Header.Set("Authorization", "Bearer "+token)
	return err
}

// createPolicy tells the ACS Central Server to create a policy with the contents specified
func createPolicy(policy string) (string, error) {
	var id string
	url := fmt.Sprintf("https://%s/v1/policies", getStackroxHostname())

	req, err := http.NewRequest("POST", url, strings.NewReader(policy))
	if err != nil {
		reconciler.Log.Error(err, "Error reading request.")
		return id, err
	}

	err = setHeaders(req)
	if err != nil {
		reconciler.Log.Error(err, "Error obtaining the ACS API token")
		return id, err
	}
	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		reconciler.Log.Error(err, "Error reading response.")
		return id, err
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		reconciler.Log.Error(err, "Error reading response body.")
		return id, err
	}
	reconciler.Log.Info("Response from create policy request to ACS: ", "responseBody", string(responseBody))

	if resp.StatusCode >= 400 {
		err = errors.NewBadRequest("error response code returned by REST Stackrox policy create call " + fmt.Sprint(resp.StatusCode))
		reconciler.Log.Error(err, "Error returned from Stackrox Central query: ", "StatusCode", resp.StatusCode)
		return id, err
	}
	var objectDef map[string]interface{}
	err = json.Unmarshal(responseBody, &objectDef)
	if err != nil {
		reconciler.Log.Error(err, "Failed to decode the ACS list result")
	} else if value, ok := objectDef["id"]; ok {
		id = value.(string)
	}
	return id, nil
}

// getPolicyList queries the ACS Central Server for the list of policies and return the
// array of policies
func getPolicyList() ([]interface{}, error) {
	var list []interface{}

	// NOTE: I couldn't get the query or from-search to work with "name", so we have to get a full list
	// and search on our end.
	url := fmt.Sprintf("https://%s/v1/policies", getStackroxHostname())

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		reconciler.Log.Error(err, "Error reading request.")
	} else {
		err = setHeaders(req)
		if err != nil {
			reconciler.Log.Error(err, "Error obtaining the ACS API token")
			return list, err
		}
		client := getHTTPClient()
		resp, err := client.Do(req)
		if err != nil {
			reconciler.Log.Error(err, "Error reading response.")
		} else {
			defer resp.Body.Close()

			responseBody, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				reconciler.Log.Error(err, "Error reading response body.")
			} // else {
			//	reconciler.Log.Info("Response from list policy request to ACS: ", "responseBody", string(responseBody))
			//}
			if resp.StatusCode >= 400 {
				err = errors.NewBadRequest("error response code returned by REST Stackrox policy create call " + fmt.Sprint(resp.StatusCode))
				reconciler.Log.Error(err, "Error returned from Stackrox Central query: ", "StatusCode", resp.StatusCode)
			} else {
				var objectDef map[string]interface{}
				err = json.Unmarshal(responseBody, &objectDef)
				if err != nil {
					reconciler.Log.Error(err, "Failed to decode the ACS list result")
				} else if policies, ok := objectDef["policies"]; ok {
					list = policies.([]interface{})
				}
			}
		}
	}

	return list, err
}

// doesPolicyExist lists the stackrox policies and looks for one with the name specified.
func doesPolicyExist(list []interface{}, name string) (bool, string, map[string]interface{}) {
	exists := false
	policyid := ""

	var thispolicy map[string]interface{}
	for _, policy := range list {
		thispolicy = policy.(map[string]interface{})
		if thispolicy["name"] == name {
			exists = true
			policyid = thispolicy["id"].(string)
			reconciler.Log.Info("Found the policy name in ACS, not updating the existing policy",
				"id", policyid, "name", name)
			break
		}
	}

	return exists, policyid, thispolicy
}
