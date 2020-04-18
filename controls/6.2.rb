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
pci_section = '6.2'

gke_clusters = GKECache(project: gcp_project_id, gke_locations: gcp_gke_locations).gke_clusters_cache

title "[PCI-DSS-#{pci_version}][#{pci_section}] Ensure that all system components and software are protected from known vulnerabilities by installing applicable vendor supplied security patches. Install critical security patches within one month of release."

# 6.2
pci_req = "#{pci_section}"
pci_req_title = "Ensure that all system components and software are protected from known vulnerabilities by installing applicable vendorsupplied security patches. Install critical security patches within one month of release."
pci_req_guidance = "There is a constant stream of attacks using widely published exploits, often called \"zero day\" (an attack that exploits a previously unknown vulnerability), against otherwise secured systems. If the most recent patches are not implemented on critical systems as soon as possible, a malicious individual can use these exploits to attack or disable a system, or gain access to sensitive data.

Prioritizing patches for critical infrastructure ensures that high-priority systems and devices are protected from vulnerabilities as soon as possible after a patch is released. Consider prioritizing patch installations such that security patches for critical or at-risk systems are installed within 30 days, and other lower-risk patches are installed within 2-3 months.

This requirement applies to applicable patches for all installed software, including payment applications (both those that are PA-DSS validated and those that are not)."
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

  # GKE Nodes have auto upgrade enabled and run COS
  gke_clusters.each do |gke_cluster|
    google_container_node_pools(project: gcp_project_id, location: gke_cluster[:location], cluster_name: gke_cluster[:cluster_name]).node_pool_names.each do |nodepoolname|
      describe "[#{gcp_project_id}] Cluster #{gke_cluster[:location]}/#{gke_cluster[:cluster_name]}, Node Pool: #{nodepoolname}" do
        subject { google_container_node_pool(project: gcp_project_id, location: gke_cluster[:location], cluster_name: gke_cluster[:cluster_name], nodepool_name: nodepoolname) }
        its('config.image_type') { should match /COS/ }
        its('management.auto_upgrade') { should cmp true }
      end
    end
  end

end
