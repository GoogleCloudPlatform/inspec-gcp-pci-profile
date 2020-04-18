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
pci_section = '10.5'

gke_clusters = GKECache(project: gcp_project_id, gke_locations: gcp_gke_locations).gke_clusters_cache
gcs_logging_buckets = attribute('gcs_logging_buckets')
logging_viewer_list = attribute('logging_viewer_list')
logging_admin_list = attribute('logging_admin_list')

title "[PCI-DSS-#{pci_version}][#{pci_section}] Secure audit trails so they cannot be altered."

# 10.5.1
pci_req = "#{pci_section}.1"
pci_req_title = "Limit viewing of audit trails to those with a job-related need."
pci_req_guidance = "Adequate protection of the audit logs includes strong access control (limit access to logs based on “need to know” only), and use of physical or network segregation to make the logs harder to find and modify.

Promptly backing up the logs to a centralized log server or media that is difficult to alter keeps the logs protected even if the system generating the logs becomes compromised."
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

  # Ensure only a desired list of accounts have logging.viewer
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure a whitelist of users/SAs/groups have access to logging viewer" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/logging.viewer') }
    it "matches the Logging Viewer allow list" do
      expect(subject.members).to cmp(logging_viewer_list).or eq(nil).or cmp([])
    end
  end

end

# 10.5.2
pci_req = "#{pci_section}.2"
pci_req_title = "Protect audit trail files from unauthorized modifications."
pci_req_guidance = "Adequate protection of the audit logs includes strong access control (limit access to logs based on “need to know” only), and use of physical or network segregation to make the logs harder to find and modify.

Promptly backing up the logs to a centralized log server or media that is difficult to alter keeps the logs protected even if the system generating the logs becomes compromised."
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

  # Ensure only a desired list of accounts have logging.admin
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure a whitelist of users/SAs/groups have access to logging Admin" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/logging.admin') }
    it "matches the Logging Admin allow list" do
      expect(subject.members).to cmp(logging_admin_list).or eq(nil).or cmp([])
    end
  end

end

# 10.5.4
pci_req = "#{pci_section}.4"
pci_req_title = " Write logs for external-facing technologies onto a secure, centralized, internal log server or media device."
pci_req_guidance = "By writing logs from external-facing technologies such as wireless, firewalls, DNS, and mail servers, the risk of those logs being lost or altered is lowered, as they are more secure within the internal network.

Logs may be written directly, or offloaded or copied from external systems, to the secure internal system or media. "
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

  # Ensure that Stackdriver Logging is enabled on all GKE Clusters
  gke_clusters.each do |gke_cluster|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Cluster #{gke_cluster[:location]}/#{gke_cluster[:cluster_name]}" do
      subject { google_container_cluster(project: gcp_project_id, location: gke_cluster[:location], name: gke_cluster[:cluster_name]) }
      its('logging_service') { should match /^logging.googleapis.com/ }
    end
  end

end

# 10.5.5
pci_req = "#{pci_section}.5"
pci_req_title = "Use file-integrity monitoring or change-detection software on logs to ensure that existing log data cannot be changed without generating alerts"
pci_req_guidance = "File-integrity monitoring or change-detection systems check for changes to critical files, and notify when such changes are noted. For fileintegrity monitoring purposes, an entity usually monitors files that don’t regularly change, but when changed indicate a possible compromise."
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

  # Ensure each logging bucket has versioning policy set
  gcs_logging_buckets.each do |bucket|
    next if bucket.empty?
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Logging bucket: #{bucket}" do
      subject { google_storage_bucket(name: bucket) }
      it { should exist }
      its('versioning.enabled') { should eq true }
    end
  end

end
