// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyShepherd) DeepCopyInto(out *PolicyShepherd) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyShepherd.
func (in *PolicyShepherd) DeepCopy() *PolicyShepherd {
	if in == nil {
		return nil
	}
	out := new(PolicyShepherd)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PolicyShepherd) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyShepherdList) DeepCopyInto(out *PolicyShepherdList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]PolicyShepherd, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyShepherdList.
func (in *PolicyShepherdList) DeepCopy() *PolicyShepherdList {
	if in == nil {
		return nil
	}
	out := new(PolicyShepherdList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PolicyShepherdList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyShepherdSpec) DeepCopyInto(out *PolicyShepherdSpec) {
	*out = *in
	if in.DeletePolicyList != nil {
		in, out := &in.DeletePolicyList, &out.DeletePolicyList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.CreatePolicyList != nil {
		in, out := &in.CreatePolicyList, &out.CreatePolicyList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.EnablePolicyList != nil {
		in, out := &in.EnablePolicyList, &out.EnablePolicyList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DisablePolicyList != nil {
		in, out := &in.DisablePolicyList, &out.DisablePolicyList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyShepherdSpec.
func (in *PolicyShepherdSpec) DeepCopy() *PolicyShepherdSpec {
	if in == nil {
		return nil
	}
	out := new(PolicyShepherdSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyShepherdStatus) DeepCopyInto(out *PolicyShepherdStatus) {
	*out = *in
	if in.DeleteStatus != nil {
		in, out := &in.DeleteStatus, &out.DeleteStatus
		*out = make([]PolicyUpdateStatus, len(*in))
		copy(*out, *in)
	}
	if in.CreateStatus != nil {
		in, out := &in.CreateStatus, &out.CreateStatus
		*out = make([]PolicyUpdateStatus, len(*in))
		copy(*out, *in)
	}
	if in.EnableStatus != nil {
		in, out := &in.EnableStatus, &out.EnableStatus
		*out = make([]PolicyUpdateStatus, len(*in))
		copy(*out, *in)
	}
	if in.DisableStatus != nil {
		in, out := &in.DisableStatus, &out.DisableStatus
		*out = make([]PolicyUpdateStatus, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyShepherdStatus.
func (in *PolicyShepherdStatus) DeepCopy() *PolicyShepherdStatus {
	if in == nil {
		return nil
	}
	out := new(PolicyShepherdStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyUpdateStatus) DeepCopyInto(out *PolicyUpdateStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyUpdateStatus.
func (in *PolicyUpdateStatus) DeepCopy() *PolicyUpdateStatus {
	if in == nil {
		return nil
	}
	out := new(PolicyUpdateStatus)
	in.DeepCopyInto(out)
	return out
}
