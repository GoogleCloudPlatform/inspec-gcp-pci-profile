# encoding: utf-8
# Copyright 2019 The inspec-gcp-pci-profile Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

gcp_project_id = attribute('gcp_project_id')
gce_zones = attribute('gce_zones')
pci_version = attribute('pci_version')
pci_url = attribute('pci_url')
pci_section = '8.5'

gce_instances = GCECache(project: gcp_project_id, gce_zones: gce_zones).gce_instances_cache

title "[PCI-DSS-#{pci_version}][#{pci_section}] Do not use group, shared, or generic IDs, passwords, or other authentication methods"

# 8.5
pci_req = "#{pci_section}"
pci_req_title = "Do not use group, shared, or generic IDs, passwords, or other authentication methods"
pci_req_guidance = "If multiple users share the same authentication credentials (for example, user account and password), it becomes impossible to trace system access and activities to an individual. This in turn prevents an entity from assigning accountability for, or having effective logging of, an individual’s actions, since a given action could have been performed by anyone in the group that has knowledge of the authentication credentials."
pci_req_coverage = 'partial'

control "pci-dss-#{pci_version}-#{pci_req}" do
  title "[PCI-DSS #{pci_version}][#{pci_req}] #{pci_req_title}"
  desc "#{pci_req_guidance}"
  impact 1.0

  tag project: "#{gcp_project_id}"
  tag standard: "pci-dss"
  tag pci_version: "#{pci_version}"
  tag pci_section: "#{pci_section}"
  tag pci_req: "#{pci_req}"
  tag coverage: "#{pci_req_coverage}"

  ref "PCI DSS #{pci_version}", url: "#{pci_url}"

  # Ensure the default compute service account is not attached to GCE/GKE instances
  gce_instances.each do |instance|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Instance: #{instance[:zone]}/#{instance[:name]}'s"  do
      subject { google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name]) }
      it "service account should not be the Default Compute Service Account" do
        expect(subject.service_accounts[0].email).not_to match /-compute@developer.gserviceaccount.com$/
      end
    end
  end

  # Ensure the Default SA is not attached to Editor
  google_project_iam_bindings(project: gcp_project_id).where(iam_binding_role: 'roles/editor').iam_binding_roles.each do |role|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] The IAM Role 'roles/editor'" do
      subject { google_project_iam_binding(project: gcp_project_id, role: role) }
      it "should not be bound to the default compute service account" do
        subject.members.should_not include /-compute@developer.gserviceaccount.com/
      end
    end
  end

  # Service Account User should not be bound at the project level
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure the role iam.serviceAccountUser is not bound at the project level" do
    subject { google_project_iam_bindings(project: gcp_project_id).where(iam_binding_role: 'roles/iam.serviceAccountUser') }
    its('count') { should be == 0 }
  end

end
