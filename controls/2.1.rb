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
gcp_gke_locations = attribute('gcp_gke_locations')
gce_zones = attribute('gce_zones')
pci_version = attribute('pci_version')
pci_url = attribute('pci_url')
pci_section = '2.1'

gke_clusters = GKECache(project: gcp_project_id, gke_locations: gcp_gke_locations).gke_clusters_cache
gce_instances = GCECache(project: gcp_project_id, gce_zones: gce_zones).gce_instances_cache

title "[PCI-DSS-#{pci_version}][#{pci_section}] Always change vendor-supplied defaults and remove or disable unnecessary default accounts"

# 2.1
pci_req = "#{pci_section}"
pci_req_title = "Always change vendor-supplied defaults and remove or disable unnecessary default accounts before installing a system on the network."
pci_req_guidance = "Malicious individuals (external and internal to an organization) often use vendor default settings, account names, and passwords to compromise operating system software, applications, and the systems on which they are installed. Because these default settings are often published and are well known in hacker communities, changing these settings will leave systems less vulnerable to attack.  Even if a default account is not intended to be used, changing the default password to a strong unique password and then disabling the account will prevent a malicious individual from re-enabling the account and gaining access with the default password. "
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
    describe "[#{gcp_project_id}] The IAM Role 'roles/editor'" do
      subject { google_project_iam_binding(project: gcp_project_id, role: role) }
      it "should not be bound to the default compute service account" do
        subject.members.should_not include /-compute@developer.gserviceaccount.com/
      end
    end
  end

  # Ensure all GKE clusters do not have basic auth and have client certs auth disabled
  gke_clusters.each do |gke_cluster|
    describe "[#{gcp_project_id}] GKE Cluster #{gke_cluster[:location]}/#{gke_cluster[:cluster_name]}'s" do
      subject { google_container_cluster(project: gcp_project_id, location: gke_cluster[:location], name: gke_cluster[:cluster_name]) }
      #its('master_auth.username') { should cmp nil }
      it "Basic Authentication should be disabled" do
        subject.master_auth.username.should cmp(nil)
      end
      # master_auth.password should also be nil, but we don't want to put that sensitive info in the output
      it "Client Certificate Authentication should be disabled" do
        subject.master_auth.client_certificate.should cmp(nil)
      end
    end
  end

end
