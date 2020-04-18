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
pci_section = '7.2'

gke_clusters = GKECache(project: gcp_project_id, gke_locations: gcp_gke_locations).gke_clusters_cache
gce_instances = GCECache(project: gcp_project_id, gce_zones: gce_zones).gce_instances_cache

title "[PCI-DSS-#{pci_version}][#{pci_section}] Establish an access control system(s) for systems components that restricts access based on a user’s need to know, and is set to “deny all” unless specifically allowed. "

# 7.2.3
pci_req = "#{pci_section}.3"
pci_req_title = "Default “deny-all” setting."
pci_req_guidance = "Confirm that the access control systems have a default “deny-all” setting."
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

  # Default subnets are not in use and not legacy
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Subnets" do
    subject { google_compute_networks(project: gcp_project_id) }
    its('network_names') { should_not include 'default' }
  end

  # Ensure all networks do not have default FW rules
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'INGRESS').where{ firewall_name =~ /^default-allow-/ }.firewall_names.each do |firewall_name|
    fw = google_compute_firewall(project: gcp_project_id, name: firewall_name)
    next if fw.disabled == true
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Firewall Rule: #{firewall_name}" do
      subject { fw }
      it { should_not exist }
    end
  end

  # Ensure the default compute service account is not attached to GCE/GKE instances
  gce_instances.each do |instance|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Instance: #{instance[:zone]}/#{instance[:name]}'s"  do
      subject { google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name]) }
      it "service account should not be the Default Compute Service Account" do
        expect(subject.service_accounts[0].email).not_to match /-compute@developer.gserviceaccount.com$/
      end
    end
  end

  # Ensure the Default SA is not attached to Editor
  google_project_iam_bindings(project: gcp_project_id).where(iam_binding_role: 'roles/editor').iam_binding_roles.each do |role|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] The IAM Role 'roles/editor'" do
      subject { google_project_iam_binding(project: gcp_project_id, role: role) }
      it "should not be bound to the default compute service account" do
        subject.members.should_not include /-compute@developer.gserviceaccount.com/
      end
    end
  end

  # GCE Instances should block ssh keys  
  gce_instances.each do |instance|
    next if instance[:name] =~ /^gke-/
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Instance: #{instance[:zone]}/#{instance[:name]}'s"  do
      subject { google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name]) }
      its('block_project_ssh_keys') { should cmp true }
    end
  end

  # GKE Clusters should not use Legacy ABAC in favor of RBAC
  gke_clusters.each do |gke_cluster|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] GKE Cluster #{gke_cluster[:location]}/#{gke_cluster[:cluster_name]}" do
      subject { google_container_cluster(project: gcp_project_id, location: gke_cluster[:location], name: gke_cluster[:cluster_name]) }
      it "should enable RBAC" do
        expect(subject.legacy_abac.enabled).not_to cmp(true)
      end
    end
  end

  # GCE/GKE Instances should not have an OAuth Scope of cloud-platform
  gce_instances.each do |instance|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Instance: #{instance[:zone]}/#{instance[:name]}"  do
      subject { google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name]) }
      it "should not have an OAuth Scope of 'cloud-platform'" do
        expect(subject.service_account_scopes).to_not include('https://www.googleapis.com/auth/cloud-platform')
      end
    end
  end

  # GCS Buckets should not have allUsers or allAuthenticatedUsers (All) set on any bucket role
  google_storage_buckets(project: gcp_project_id).bucket_names.each do |bucket|
    google_storage_bucket_iam_bindings(bucket: bucket).iam_binding_roles.each do |role|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] GCS Bucket #{bucket}, Role: #{role}" do
        subject { google_storage_bucket_iam_binding(bucket: bucket, role: role) }
        its('members') { should_not include 'allUsers' }
        its('members') { should_not include 'allAuthenticatedUsers' }
      end
    end
  end

end
