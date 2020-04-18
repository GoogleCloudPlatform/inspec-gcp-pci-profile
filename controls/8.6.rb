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
pci_version = attribute('pci_version')
pci_url = attribute('pci_url')
pci_section = '8.6'

gke_clusters = GKECache(project: gcp_project_id, gke_locations: gcp_gke_locations).gke_clusters_cache

title "[PCI-DSS-#{pci_version}][#{pci_section}] Where other authentication mechanisms are used, authentication mechanisms must be assigned to an individual account and not shared among multiple accounts and physical and/or logical controls must be in place to ensure only the intended account can use that mechanism to gain access."

# 8.6
pci_req = "#{pci_section}"
pci_req_title = "Where other authentication mechanisms are used, authentication mechanisms must be assigned to an individual account and not shared among multiple accounts and physical and/or logical controls must be in place to ensure only the intended account can use that mechanism to gain access."
pci_req_guidance = "If user authentication mechanisms such as tokens, smart cards, and certificates can be used by multiple accounts, it may be impossible to identify the individual using the authentication mechanism.  Having physical and/or logical controls (for example, a PIN, biometric data, or a password) to uniquely identify the user of the account will prevent unauthorized users from gaining access through use of a shared authentication mechanism."
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

  # Ensure all GKE clusters do not have basic auth and have client certs auth disabled
  gke_clusters.each do |gke_cluster|
    describe "[#{gcp_project_id}] GKE Cluster #{gke_cluster[:location]}/#{gke_cluster[:cluster_name]}'s" do
      subject { google_container_cluster(project: gcp_project_id, location: gke_cluster[:location], name: gke_cluster[:cluster_name]) }
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
