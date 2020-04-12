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
pci_version = attribute('pci_version')
pci_url = attribute('pci_url')
pci_section = '2.4'

cai_inventory_bucket_name = attribute('cai_inventory_bucket_name')
cai_inventory_file_path = attribute('cai_inventory_file_path')
cai_inventory_age_seconds = attribute('cai_inventory_age_seconds')

title "[PCI-DSS-#{pci_version}][#{pci_section}] Maintain an inventory of system components that are in scope for PCI DSS."

# 2.4
pci_req = "#{pci_section}"
pci_req_title = "Maintain an inventory of system components that are in scope for PCI DSS."
pci_req_guidance = "Maintaining a current list of all system components will enable an organization to accurately and efficiently define the scope of their environment for implementing PCI DSS controls. Without an inventory, some system components could be forgotten, and be inadvertently excluded from the organization’s configuration standards."
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

  # Ensure the CAI inventory file on a bucket was last updated recently
  describe "[#{gcp_project_id}] The object for CAI inventory at #{cai_inventory_bucket_name}/#{cai_inventory_file_path}" do
    subject { google_storage_bucket_object(bucket: cai_inventory_bucket_name,  object: cai_inventory_file_path) }
    it { should exist }
    its('time_updated') { should be >= (Time.now - cai_inventory_age_seconds) }
  end
end
