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
pci_section = '7.1'

project_owners_list = attribute('project_owners_list')
gce_instances = GCECache(project: gcp_project_id, gce_zones: gce_zones).gce_instances_cache

title "[PCI-DSS-#{pci_version}][#{pci_section}] Limit access to system components and cardholder data to only those individuals whose job requires such access."

# 7.1.2
pci_req = "#{pci_section}.2"
pci_req_title = "Restrict access to privileged user IDs to least privileges necessary to perform job responsibilities."
pci_req_guidance = "When assigning privileged IDs, it is important to assign individuals only the privileges they need to perform their job (the “least privileges”). For example, the database administrator or backup administrator should not be assigned the same privileges as the overall systems administrator."
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

  # Ensure IAM Role bindings are to groups and not users directly
  google_project_iam_bindings(project: gcp_project_id).iam_binding_roles.each do |role|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] IAM Role #{role}" do
      subject { google_project_iam_binding(project: gcp_project_id, role: role) }
      it "should not have any \"user:<users>@\" bound" do
        subject.members.to_s.should_not match /user:/
      end
    end
  end

  # Ensure the list of owners is known
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure Owners" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/owner') }
    it "matches the Owners allow list" do
      expect(subject.members).to cmp(project_owners_list).or eq([])
    end
  end

  # Ensure the default compute service account is not attached to GCE/GKE instances
  gce_instances.each do |instance|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Instance: #{instance[:zone]}/#{instance[:name]}'s"  do
      subject { google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name]) }
      it "service account should not be the Default Compute Service Account" do
        expect(subject.service_accounts[0].email).not_to match /-compute@developer.gserviceaccount.com$/
      end
    end
  end

  # Ensure that primitive roles (Owner/Editor/Viewer) are not bound to GCE or GKE node pools
  # Get the unique list of attached SAs to GCE/GKE instances
  attached_service_accounts = []
  gce_instances.each do |instance|
    sa = google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name]).service_accounts
    if sa.length > 0
       attached_service_accounts << sa[0].email 
    end
  end
  
  # The unique list of attached SAs to instances
  attached_service_accounts.uniq!
  # Search primitive role bindings for members that should not include these attached SAs
  google_project_iam_bindings(project: gcp_project_id).where{ iam_binding_role == 'roles/editor' || iam_binding_role == 'roles/owner' || iam_binding_role == 'roles/viewer' }.iam_binding_roles.each do |role|
    attached_service_accounts.each do |sa_name|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] ServiceAccount #{sa_name}" do
        subject { google_project_iam_binding(project: gcp_project_id, role: role) }
        it "should not be bound to #{role}" do
          subject.members.should_not include "serviceAccount:#{sa_name}"
        end
      end
    end
  end

end
