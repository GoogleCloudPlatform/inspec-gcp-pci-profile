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
pci_section = '3.1'

gcs_pii_buckets = attribute('gcs_pii_buckets')

title "[PCI-DSS-#{pci_version}][#{pci_section}] Keep cardholder data storage to a minimum by implementing data retention and disposal policies, procedures and processes"

# 3.1
pci_req = "#{pci_section}"
pci_req_title = "Keep cardholder data storage to a minimum by implementing data retention and disposal policies, procedures and processes"
pci_req_guidance = "A formal data retention policy identifies what data needs to be retained, and where that data resides so it can be securely destroyed or deleted as soon as it is no longer needed.

The only cardholder data that may be stored after authorization is the primary account number or PAN (rendered unreadable), expiration date, cardholder name, and service code.

Understanding where cardholder data is located is necessary so it can be properly retained or disposed of when no longer needed. In order to define appropriate retention requirements, an entity first needs to understand their own business needs as well as any legal or regulatory obligations that apply to their industry, and/or that apply to the type of data being retained."
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

  # Ensure each sensitive data GCS bucket has logging/versioning/retention policy set
  gcs_pii_buckets.each do |bucket|
    describe "[#{gcp_project_id}] Sensitive data bucket: #{bucket}" do
      subject { google_storage_bucket(name: bucket) }
      it { should exist }
      its('versioning.enabled') { should eq true }
      its('logging.log_bucket') { should_not eq nil }
    end
  end

end
