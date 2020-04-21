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
pci_section = '1.1'

fw_change_control_id_regex = attribute('fw_change_control_id_regex')
fw_override_control_id_regex = attribute('fw_override_control_id_regex')
fw_checked_insecure_tcp_ports = attribute('fw_checked_insecure_tcp_ports')
fw_checked_insecure_udp_ports = attribute('fw_checked_insecure_udp_ports')
dmz_login_ports = attribute('dmz_login_ports')


title "[PCI-DSS-#{pci_version}][#{pci_section}] Establish and implement firewall and router configuration standards"

# 1.1.1
pci_req = "#{pci_section}.1"
pci_req_title = "A formal process for approving and testing all network connections and changes to the firewall and router configurations"
pci_req_guidance = "A documented and implemented process for approving and testing all connections and changes to the firewalls and routers will help prevent security problems caused by misconfiguration of the network, router, or firewall.
Without formal approval and testing of changes, records of the changes might not be updated, which could lead to inconsistencies between network documentation and the actual configuration."
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

  # Non-GKE Firewall Rules have description that includes the change control ID
  google_compute_firewalls(project: gcp_project_id).where{ firewall_name !~ /^gke/ }.firewall_names.each do |firewall_name|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] #{firewall_name}" do
      subject { google_compute_firewall(project: gcp_project_id, name: firewall_name) }
      its('description') { should match /#{fw_change_control_id_regex}/ }
    end
  end
end

# 1.1.4
pci_req = "#{pci_section}.4"
pci_req_title = "Requirements for a firewall at each Internet connection and between any demilitarized zone (DMZ) and the internal network zone"
pci_req_guidance = "Using a firewall on every Internet connection coming into (and out of) the network, and between any DMZ and the internal network, allows the organization to monitor and control access and minimizes the chances of a malicious individual obtaining access to the internal network via an unprotected connection."
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

  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'INGRESS').firewall_names.each do |firewall_name|
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] #{firewall_name}" do
      subject { google_compute_firewall(project: gcp_project_id, name: firewall_name) }
      dmz_login_ports.each do |port|
        it "should not allow #{port} from 0.0.0.0/0" do
          expect((subject.allow_port_protocol?(port, 'tcp')) && (subject.allow_ip_ranges? ['0.0.0.0/0'])).to eq(false)
        end
      end
    end
  end
end

# 1.1.6
pci_req = "#{pci_section}.6"
pci_req_title = "Documentation of business justification and approval for use of all services, protocols, and ports allowed, including documentation of security features implemented for those protocols considered to be insecure."
pci_req_guidance = "Compromises often happen due to unused or insecure service and ports, since these often have known vulnerabilities and many organizations don’t patch vulnerabilities for the services, protocols, and ports they don't use (even though the vulnerabilities are still present). By clearly defining and documenting the services, protocols, and ports that are necessary for business, organizations can ensure that all other services, protocols, and ports are disabled or removed.  Approvals should be granted by personnel independent of the personnel managing the configuration.

If insecure services, protocols, or ports are necessary for business, the risk posed by use of these protocols should be clearly understood and accepted by the organization, the use of the protocol should be justified, and the security features that allow these protocols to be used securely should be documented and implemented. If these insecure services, protocols, or ports are not necessary for business, they should be disabled or removed.  For guidance on services, protocols, or ports considered to be insecure, refer to industry standards and guidance (e.g., NIST, ENISA, OWASP, etc.)."
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

  # Firewall Rules for insecure ports have description that includes the overriding change control ID
  google_compute_firewalls(project: gcp_project_id).where{firewall_name !~ /^gke-/ }.firewall_names.each do |firewall_name|
    fwrule = google_compute_firewall(project: gcp_project_id, name: firewall_name)
    fw_checked_insecure_tcp_ports.each do |port|
      if fwrule.allow_port_protocol?("#{port}",'tcp')
        describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Insecure port tcp/#{port} in #{firewall_name}" do
          subject { google_compute_firewall(project: gcp_project_id, name: firewall_name) }
          its('description') { should match /#{fw_override_control_id_regex}/ }
        end
      end
    end
    fw_checked_insecure_udp_ports.each do |port|
      if fwrule.allow_port_protocol?("#{port}",'udp')
        describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Insecure port udp/#{port} in #{firewall_name}" do
          subject { google_compute_firewall(project: gcp_project_id, name: firewall_name) }
          its('description') { should match /#{fw_override_control_id_regex}/ }
        end
      end
    end
  end
end
