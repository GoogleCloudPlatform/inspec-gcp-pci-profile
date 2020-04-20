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
pci_section = '1.3'

gke_clusters = GKECache(project: gcp_project_id, gke_locations: gcp_gke_locations).gke_clusters_cache
gce_instances = GCECache(project: gcp_project_id, gce_zones: gce_zones).gce_instances_cache
fw_change_control_id_regex = attribute('fw_change_control_id_regex')

title "[PCI-DSS-#{pci_version}][#{pci_section}] Prohibit direct public access between the Internet and any system component in the cardholder data environment."

# 1.3.2
pci_req = "#{pci_section}.2"
pci_req_title = "Limit inbound Internet traffic to IP addresses within the DMZ."
pci_req_guidance = "The DMZ is that part of the network that manages connections between the Internet (or other untrusted networks), and services that an organization needs to have available to the public (like a web server).

This functionality is intended to prevent malicious individuals from accessing the organization's internal network from the Internet, or from using services, protocols, or ports in an unauthorized manner."
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

  # Ensure ingress from 0.0.0.0 only to target tags or service accounts
  ingress_from_all_fw_rules = []
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'INGRESS').where{ firewall_name !~ /^gke/ }.firewall_names.each do |firewall_name|
    fw = google_compute_firewall(project: gcp_project_id, name: firewall_name)
    if !fw.disabled && fw.respond_to?('source_ranges') && !fw.source_ranges.nil? && fw.allow_ip_range_list(['0.0.0.0/0'])
      ingress_from_all_fw_rules << firewall_name
    end
  end
  if (ingress_from_all_fw_rules == [])
    describe "There are no applicable firewall rules" do
      skip 'There are no applicable firewall rules in this project'
    end
  else
    ingress_from_all_fw_rules.each do |fw_rule|
      fw = google_compute_firewall(project: gcp_project_id, name: fw_rule)
      if !fw.respond_to?('target_tags') && !fw.respond_to?('target_service_accounts')
        describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ingress firewall rule #{fw_rule} that does not target tags or service accounts" do
          subject { fw }
          it { should_not exist }
        end
      end
      if fw.allow_port_protocol?("0","all")
        describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ingress firewall rule #{fw_rule} that allows all ports/protocols" do
          subject { fw }
          it { should_not exist }
        end
      end
    end
  end
end

# 1.3.4
pci_req = "#{pci_section}.4"
pci_req_title = "Do not allow unauthorized outbound traffic from the cardholder data environment to the Internet."
pci_req_guidance = "All traffic outbound from the cardholder data environment should be evaluated to ensure that it follows established, authorized rules. Connections should be inspected to restrict traffic to only authorized communications (for example by restricting source/destination addresses/ports, and/or blocking of content)."
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

  # Explicit egress deny all rule in place
  egress_deny_all_fw_rules = []
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'EGRESS').where{ firewall_name !~ /^gke/ }.firewall_names.each do |firewall_name|
    fw = google_compute_firewall(project: gcp_project_id, name: firewall_name)
    if !fw.disabled && fw.respond_to?('denied') && !fw.denied.nil? && fw.denied[0].ip_protocol == "all"
      egress_deny_all_fw_rules << firewall_name
    end
  end
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}]" do 
    it "has a deny all egress rule" do
      expect(egress_deny_all_fw_rules.count).to be >= 1
    end
  end

  # Non-GKE Firewall egress Rules have description that includes the change control ID
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'EGRESS').where{ firewall_name !~ /^gke/ }.firewall_names.each do |firewall_name|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] #{firewall_name}'s" do
      subject { google_compute_firewall(project: gcp_project_id, name: firewall_name) }
      it "description should include a change control ID" do
        subject.description.should match /#{fw_change_control_id_regex}/
      end
    end
  end

end

# 1.3.6
pci_req = "#{pci_section}.6"
pci_req_title = "Place system components that store cardholder data (such as a database) in an internal network zone, segregated from the DMZ and other untrusted networks."
pci_req_guidance = "If cardholder data is located within the DMZ, it is easier for an external attacker to access this information, since there are fewer layers to penetrate. Securing system components that store cardholder data in an internal network zone that is segregated from the DMZ and other untrusted networks by a firewall can prevent unauthorized network traffic from reaching the system component."
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

  # GCE Instances should not have public IPs
  gce_instances.each do |instance|
    next if instance[:name] =~ /^gke-/
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Instance: #{instance[:zone]}/#{instance[:name]}'s" do
      subject { google_compute_instance(project: gcp_project_id, zone: instance[:zone], name: instance[:name]) }
      it "should not have a public IP assigned" do
        expect(!subject.network_interfaces[0].respond_to?('access_configs') || subject.first_network_interface_type != "one_to_one_nat").to eq(true)
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

  # GKE Clusters have private API and nodes
  gke_clusters.each do |gke_cluster|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Cluster #{gke_cluster[:location]}/#{gke_cluster[:cluster_name]}" do
      subject { google_container_cluster(project: gcp_project_id, location: gke_cluster[:location], name: gke_cluster[:cluster_name]) }
      its('private_cluster_config.enable_private_endpoint') { should cmp true }
      its('private_cluster_config.enable_private_nodes') { should cmp true }
    end
  end

  # CloudSQL instances require SSL, are not allowed from 0.0.0.0/0, and use a private IP endpoint
  google_sql_database_instances(project: gcp_project_id).instance_names.each do |db|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] CloudSQL #{db}" do
      subject { google_sql_database_instance(project: gcp_project_id, database: db) }
      it { should have_ip_configuration_require_ssl }
      its('authorized_networks') { should_not include '0.0.0.0/0' }
      it "should use a private IP address only" do
        expect(subject.settings.ip_configuration.respond_to?('private_network') && !subject.settings.ip_configuration.private_network.nil?).to eq(true)
        expect(subject.settings.ip_configuration.ipv4_enabled).to cmp(false)
      end
    end
  end
end
