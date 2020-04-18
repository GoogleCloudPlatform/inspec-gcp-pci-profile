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
pci_section = '6.3'

gke_clusters = GKECache(project: gcp_project_id, gke_locations: gcp_gke_locations).gke_clusters_cache

title "[PCI-DSS-#{pci_version}][#{pci_section}] Develop internal and external software applications (including web-based administrative access to applications) securely"

# 6.3.2
pci_req = "#{pci_section}.2"
pci_req_title = "Review custom code prior to release to production or customers in order to identify any potential coding vulnerability (using either manual or automated processes)"
pci_req_guidance = "Security vulnerabilities in custom code are commonly exploited by malicious individuals to gain access to a network and compromise cardholder data.

An individual knowledgeable and experienced in code-review techniques should be involved in the review process. Code reviews should be performed by someone other than the developer of the code to allow for an independent, objective review.  Automated tools or processes may also be used in lieu of manual reviews, but keep in mind that it may be difficult or even impossible for an automated tool to identify some coding issues.

Correcting coding errors before the code is deployed into a production environment or released to customers prevents the code exposing the environments to potential exploit. Faulty code is also far more difficult and expensive to address after it has been deployed or released into production environments.

Including a formal review and signoff by management prior to release helps to ensure that code is approved and has been developed in accordance with policies and procedures."
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

  # GKE Clusters have Binary Authorization enabled
  # Binary Auth should be configured to permit only allowed/signed images from known registries.
  gke_clusters.each do |gke_cluster|
    describe "[#{gcp_project_id}] Cluster #{gke_cluster[:location]}/#{gke_cluster[:cluster_name]}" do
      subject { google_container_cluster(project: gcp_project_id, location: gke_cluster[:location], name: gke_cluster[:cluster_name]) }
      its('binary_authorization.enabled') { should eq true }
    end
  end

end
