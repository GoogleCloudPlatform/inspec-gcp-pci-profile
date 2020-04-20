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
pci_section = '8.7'

memorystore_admins_list = attribute('memorystore_admins_list')
cloudsql_admins_list = attribute('cloudsql_admins_list')
cloudsql_clients_list = attribute('cloudsql_clients_list')
bq_admins_list = attribute('bq_admins_list')
spanner_admins_list = attribute('spanner_admins_list')

title "[PCI-DSS-#{pci_version}][#{pci_section}] All access to any database containing cardholder data (including access by applications, administrators, and all other users) is restricted."

# 8.7
pci_req = "#{pci_section}"
pci_req_title = "All access to any database containing cardholder data (including access by applications, administrators, and all other users) is restricted"
pci_req_guidance = "Without user authentication for access to databases and applications, the potential for unauthorized or malicious access increases, and such access cannot be logged since the user has not been authenticated and is therefore not known to the system. Also, database access should be granted through programmatic methods only (for example, through stored procedures), rather than via direct access to the database by end users (except for DBAs, who may need direct access to the database for their administrative duties)."
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

  # Ensure whitelisted memorystore user accounts only
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure MemoryStore Admins" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/redis.admin') }
    it "matches the MemoryStore Admins allow list" do
      expect(subject.members).to cmp(memorystore_admins_list).or eq(nil).or cmp([])
    end
  end

  # Ensure whitelisted cloudsql admin accounts only
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure CloudSQL Admins" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/cloudsql.admin') }
    it "matches the CloudSQL Admins allow list" do
      expect(subject.members).to cmp(cloudsql_admins_list).or eq(nil).or cmp([])
    end
  end

  # Ensure whitelisted cloudsql client accounts only
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure CloudSQL Clients" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/cloudsql.client') }
    it "matches the CloudSQL client allow list" do
      expect(subject.members).to cmp(cloudsql_clients_list).or eq(nil).or cmp([])
    end
  end

  # Ensure whitelisted BigQuery admin accounts only
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure BigQuery Admins" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/bigquery.admin') }
    it "matches the BigQuery Admins allow list" do
      expect(subject.members).to cmp(bq_admins_list).or eq(nil).or cmp([])
    end
  end

  # Ensure whitelisted Cloud Spanner admin accounts only
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure Cloud Spanner Admins" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/spanner.admin') }
    it "matches the Cloud Spanner Admins allow list" do
      expect(subject.members).to cmp(spanner_admins_list).or eq(nil).or cmp([])
    end
  end

end
