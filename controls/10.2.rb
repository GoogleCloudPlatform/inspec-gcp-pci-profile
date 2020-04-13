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
pci_section = '10.2'

logging_viewer_list = attribute('logging_viewer_list')
bucket_logging_ignore_regex = attribute('bucket_logging_ignore_regex')

title "[PCI-DSS-#{pci_version}][#{pci_section}] Implement automated audit trails for all system components"

# 10.2
pci_req = "#{pci_section}"
pci_req_title = "Implement automated audit trails for all system components"
pci_req_guidance = "Generating audit trails of suspect activities alerts the system administrator, sends data to other monitoring mechanisms (like intrusion detection systems), and provides a history trail for postincident follow-up. Logging of the following events enables an organization to identify and trace potentially malicious activities"
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

  # Subnets should have VPC flow logs enabled
  google_compute_regions(project: gcp_project_id).region_names.each do |region|
    google_compute_subnetworks(project: gcp_project_id, region: region).subnetwork_names.each do |subnet|
      subnet_obj = google_compute_subnetwork(project: gcp_project_id, region: region, name: subnet)
      describe "[#{gcp_project_id}] #{region}/#{subnet}" do
        subject { subnet_obj }
        if subnet_obj.methods.include?(:log_config) == true
          its('log_config.enable') { should be true }
        end
      end
    end
  end

  # GCS Buckets should have logging enabled
  google_storage_buckets(project: gcp_project_id).bucket_names.each do |bucket|
    next if bucket =~ /#{bucket_logging_ignore_regex}/
    describe "[#{gcp_project_id}] GCS Bucket #{bucket}" do
      subject { google_storage_bucket(name: bucket).logging }
      its('log_bucket') { should_not eq nil }
    end
  end

end

# 10.2.1
pci_req = "#{pci_section}.1"
pci_req_title = "All individual user accesses to cardholder data"
pci_req_guidance = "Malicious individuals could obtain knowledge of a user account with access to systems in the CDE, or they could create a new, unauthorized account in order to access cardholder data. A record of all individual accesses to cardholder data can identify which accounts may have been compromised or misused."
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

  # Project audit logging should be set with data_read/write logging enabled
  describe "[#{gcp_project_id}] The project audit logging configuration" do
    subject { google_project_logging_audit_config(project: gcp_project_id) }
    its('default_types') { should include 'DATA_READ' }
    its('default_types') { should include 'DATA_WRITE' }
  end

end

# 10.2.2
pci_req = "#{pci_section}.2"
pci_req_title = "All actions taken by any individual with root or administrative privileges"
pci_req_guidance = "Accounts with increased privileges, such as the “administrator” or “root” account, have the potential to greatly impact the security or operational functionality of a system. Without a log of the activities performed, an organization is unable to trace any issues resulting from an administrative mistake or misuse of privilege back to the specific action and individual."
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

  # Project Audit logging should exist
  describe "[#{gcp_project_id}] The project audit logging configuration for admin activity" do
    subject { google_project_logging_audit_config(project: gcp_project_id) }
    it { should exist }
  end

end

# 10.2.3
pci_req = "#{pci_section}.3"
pci_req_title = "Access to all audit trails"
pci_req_guidance = "Malicious users often attempt to alter audit logs to hide their actions, and a record of access allows an organization to trace any inconsistencies or potential tampering of the logs to an individual account. Having access to logs identifying changes, additions, and deletions can help retrace steps made by unauthorized personnel. "
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

  # Ensure only a desired list of accounts have logging.*
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure a whitelist of users/SAs/groups have access to logging viewer" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/logging.viewer') }
    it "matches the Logging Viewer allow list" do
      expect(subject.members).to cmp(logging_viewer_list).or eq(nil).or cmp([])
    end
  end

end

# 10.2.6
pci_req = "#{pci_section}.6"
pci_req_title = "Initialization, stopping, or pausing of the audit logs"
pci_req_guidance = "Turning the audit logs off (or pausing them) prior to performing illicit activities is a common practice for malicious users wishing to avoid detection.  Initialization of audit logs could indicate that the log function was disabled by a user to hide their actions."
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

  # Project Audit log should not have exempted members
  describe "[#{gcp_project_id}] The project audit logging configuration" do
    subject { google_project_logging_audit_config(project: gcp_project_id) }
    it { should_not have_default_exempted_members }
  end
end
