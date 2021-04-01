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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyState shows the state of enforcement
type PolicyState string

const (
	// Pending is an PolicyState
	Pending PolicyState = "Pending"

	// Completed is an PolicyState
	Completed PolicyState = "Completed"

	// Failed is an PolicyState
	Failed PolicyState = "Failed"
)

// PolicyShepherdSpec defines the desired state of PolicyShepherd
type PolicyShepherdSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// DeletePolictList is a list of policy names that the controller will remove from ACS
	DeletePolicyList []string `json:"deletePolicyList,omitempty"`
	// CreatePolicyList is a list of policies that will be created in ACS. The string is the json content of the policy.
	CreatePolicyList []string `json:"createPolicyList,omitempty"`
	// EnablePolicyList is a list of policy names that the controller will enable in ACS
	EnablePolicyList []string `json:"enablePolicyList,omitempty"`
	// DisablePolicyList is a list of policy names that the controller will disable in ACS
	DisablePolicyList []string `json:"disablePolicyList,omitempty"`
}

// PolicyShepherdStatus defines the observed state of PolicyShepherd
type PolicyShepherdStatus struct {
	Status        PolicyState          `json:"status,omitempty"`
	DeleteStatus  []PolicyUpdateStatus `json:"deletePolicyStatus,omitempty"`
	CreateStatus  []PolicyUpdateStatus `json:"createPolicyStatus,omitempty"`
	EnableStatus  []PolicyUpdateStatus `json:"enablePolicyStatus,omitempty"`
	DisableStatus []PolicyUpdateStatus `json:"disablePolicyStatus,omitempty"`
}

// PolicyUpdateStatus defines the status of a single policy
type PolicyUpdateStatus struct {
	Name         string      `json:"name,omitempty"`
	UploadStatus PolicyState `json:"uploadStatus,omitempty"`
}

// +kubebuilder:object:root=true

// PolicyShepherd is the Schema for the policyshepherds API
// +kubebuilder:subresource:status
type PolicyShepherd struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyShepherdSpec   `json:"spec,omitempty"`
	Status PolicyShepherdStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PolicyShepherdList contains a list of PolicyShepherd
type PolicyShepherdList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyShepherd `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PolicyShepherd{}, &PolicyShepherdList{})
}
