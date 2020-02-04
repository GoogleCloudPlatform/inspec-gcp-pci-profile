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
pci_section = '1.2'

allow_all_tcp_ports = attribute('allow_all_tcp_ports')
allow_all_udp_ports = attribute('allow_all_udp_ports')

title "[PCI-DSS-#{pci_version}][#{pci_section}] Build firewall and router configurations that restrict connections between untrusted networks and any system components in the cardholder data environment."

# 1.2.1
pci_req = "#{pci_section}.1"
pci_req_title = "Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment, and specifically deny all other traffic."
pci_req_guidance = "Examination of all inbound and outbound connections allows for inspection and restriction of traffic based on the source and/or destination address, thus preventing unfiltered access between untrusted and trusted environments. This prevents malicious individuals from accessing the entity’s network via unauthorized IP addresses or from using services, protocols, or ports in an unauthorized manner (for example, to send data they've obtained from within the entity’s network out to an untrusted server).  Implementing a rule that denies all inbound and outbound traffic that is not specifically needed helps to prevent inadvertent holes that would allow unintended and potentially harmful traffic in or out."
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
    if fw.respond_to?('denied') && !fw.denied.nil? && fw.denied[0].ip_protocol == "all"
      egress_deny_all_fw_rules << firewall_name
    end
  end
  describe "[#{gcp_project_id}]" do
    it "has a deny all egress rule" do
      expect(egress_deny_all_fw_rules.count).to be >= 1
    end
  end

  # At least one egress rule in place
  egress_fw_rules = []
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'EGRESS').where{ firewall_name !~ /^gke/ }.firewall_names.each do |firewall_name|
    egress_fw_rules << firewall_name 
  end
  describe "[#{gcp_project_id}]" do
    it "has at least one egress rule" do
      expect(egress_fw_rules.count).to be >= 1
    end
  end

  # Does not have an allow-all egress rule
  egress_allow_all_fw_rules = []
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'EGRESS').where{ firewall_name !~ /^gke/ }.firewall_names.each do |firewall_name|
    fw = google_compute_firewall(project: gcp_project_id, name: firewall_name)
    if fw.respond_to?('allowed') && !fw.allowed.nil? && fw.allowed[0].ip_protocol == "all"
      egress_allow_all_fw_rules << firewall_name
    end
  end
  describe "[#{gcp_project_id}]" do
    it "does not have an allow all egress rule" do
      expect(egress_allow_all_fw_rules.count).to eq(0)
    end
  end

  # Specific egress TCP ports allowed to 0.0.0.0/0
  egress_allow_tcp_to_any_fw_rules = []
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'EGRESS').where{ firewall_name !~ /^gke/ }.firewall_names.each do |firewall_name|
    fw = google_compute_firewall(project: gcp_project_id, name: firewall_name)
    if fw.respond_to?('allowed') && !fw.allowed.nil? && fw.destination_ranges == ["0.0.0.0/0"]
      fw.allowed.each do |allow_item|
        if allow_item.ip_protocol == "tcp"
          egress_allow_tcp_to_any_fw_rules += allow_item.ports
        end
      end
    end
  end
  describe "[#{gcp_project_id}]" do
    it "should allow specific TCP ports outbound to 0.0.0.0/0" do
      expect(egress_allow_tcp_to_any_fw_rules).to eq(allow_all_tcp_ports)
    end
  end
  
  # Specific egress UDP ports allowed to 0.0.0.0/0
  egress_allow_udp_to_any_fw_rules = []
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'EGRESS').where{ firewall_name !~ /^gke/ }.firewall_names.each do |firewall_name|
    fw = google_compute_firewall(project: gcp_project_id, name: firewall_name)
    if fw.respond_to?('allowed') && !fw.allowed.nil? && fw.destination_ranges == ["0.0.0.0/0"]
      fw.allowed.each do |allow_item|
        if allow_item.ip_protocol == "udp"
          egress_allow_udp_to_any_fw_rules += allow_item.ports
        end
      end
    end
  end
  describe "[#{gcp_project_id}]" do
    it "should allow specific UDP ports outbound to 0.0.0.0/0" do
      expect(egress_allow_udp_to_any_fw_rules).to eq(allow_all_udp_ports)
    end
  end

end
