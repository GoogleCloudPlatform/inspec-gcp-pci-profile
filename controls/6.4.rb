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
pci_section = '6.4'

environment_label = attribute('environment_label')
gke_clusters = GKECache(project: gcp_project_id, gke_locations: gcp_gke_locations).gke_clusters_cache
gce_instances = GCECache(project: gcp_project_id, gce_zones: gce_zones).gce_instances_cache

title "[PCI-DSS-#{pci_version}][#{pci_section}] Follow change control processes and procedures for all changes to system components"

# 6.4.1
pci_req = "#{pci_section}.1"
pci_req_title = "Separate development/test environments from production environments, and enforce the separation with access controls."
pci_req_guidance = "Due to the constantly changing state of development and test environments, they tend to be less secure than the production environment. Without adequate separation between environments, it may be possible for the production environment, and cardholder data, to be compromised due to less stringent security configurations and possible vulnerabilities in a test or development environment."
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

  # GCE/GKE Instances have a label indicating the environment
  gce_instances.each do |instance|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Instance: #{instance[:zone]}/#{instance[:name]}'s"  do
      subject { google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name]) }
      it "should have an instance label key of #{environment_label}" do
        expect(subject.labels_keys).to include(/#{environment_label}/)
      end
    end
  end

  # One GKE cluster per project
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}]" do
    subject { gke_clusters }
    it "should have no more than one GKE cluster in this project" do
      expect(subject.length).to be <= 1
    end
  end

end
