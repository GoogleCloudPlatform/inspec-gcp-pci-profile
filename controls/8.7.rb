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

gcp_project_id = input('gcp_project_id')
pci_version = input('pci_version')
pci_url = input('pci_url')
pci_section = '8.7'

memorystore_admins_list = input('memorystore_admins_list')
cloudsql_admins_list = input('cloudsql_admins_list')
cloudsql_clients_list = input('cloudsql_clients_list')
bq_admins_list = input('bq_admins_list')
spanner_admins_list = input('spanner_admins_list')

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

  iam_cache = IAMBindingsCache(project: gcp_project_id)

  # Ensure allowlisted memorystore user accounts only
  redis_admin_bindings = iam_cache.iam_bindings['roles/redis.admin']
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure MemoryStore Admins" do
    subject { redis_admin_bindings }
    if redis_admin_bindings.nil? || redis_admin_bindings.members.empty?
      skip 'There are no MemoryStore Admins in the project'
    else
      it "matches the MemoryStore Admins allow list" do
        expect(subject.members).to cmp(memorystore_admins_list)
      end
    end
  end

  # Ensure allowlisted cloudsql admin accounts only
  cloud_sql_admin_bindings = iam_cache.iam_bindings['roles/cloudsql.admin']
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure CloudSQL Admins" do
    subject { cloud_sql_admin_bindings }
    if cloud_sql_admin_bindings.nil? || cloud_sql_admin_bindings.members.empty?
      skip 'There are no Cloud SQL Admins in the project'
    else
      it "matches the Cloud SQL Admins allow list" do
        expect(subject.members).to cmp(cloudsql_admins_list)
      end
    end
  end

  # Ensure allowlisted cloudsql client accounts only
  cloud_sql_client_bindings = iam_cache.iam_bindings['roles/cloudsql.client']
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure CloudSQL Clients" do
    subject { cloud_sql_client_bindings }
    if cloud_sql_client_bindings.nil? || cloud_sql_client_bindings.members.empty?
      skip 'There are no Cloud SQL Clients in the project'
    else
      it "matches the CloudSQL client allow list" do
        expect(subject.members).to cmp(cloudsql_clients_list)
      end
    end
  end

  # Ensure allowlisted BigQuery admin accounts only
  bq_admin_bindings = iam_cache.iam_bindings['roles/bigquery.admin']
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure BigQuery Admins" do
    subject { bq_admin_bindings }
    if bq_admin_bindings.nil? || bq_admin_bindings.members.empty?
      skip 'There are no BigQuery Admins in the project'
    else
      it "matches the BigQuery Admins allow list" do
        expect(subject.members).to cmp(bq_admins_list)
      end
    end
  end

  # Ensure allowlisted Cloud Spanner admin accounts only
  spanner_admin_bindings = iam_cache.iam_bindings['roles/spanner.admin']
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure Cloud Spanner Admins" do
    subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/spanner.admin') }
    if spanner_admin_bindings.nil? || spanner_admin_bindings.members.empty?
      skip 'There are no Cloud Spanner Admins in the project'
    else
      it "matches the Cloud Spanner Admins allow list" do
        expect(subject.members).to cmp(spanner_admins_list)
      end
    end
  end
end
