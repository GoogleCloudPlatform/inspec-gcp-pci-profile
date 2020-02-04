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
pci_section = '2.3'

title "[PCI-DSS-#{pci_version}][#{pci_section}] Encrypt all non-console administrative access using strong cryptography."

# 2.3
pci_req = "#{pci_section}"
pci_req_title = "Encrypt all non-console administrative access using strong cryptography."
pci_req_guidance = "If non-console (including remote) administration does not use secure authentication and encrypted communications, sensitive administrative or operational level information (like administrator’s IDs and passwords) can be revealed to an eavesdropper. A malicious individual could use this information to access the network, become administrator, and steal data.

Clear-text protocols (such as HTTP, telnet, etc.) do not encrypt traffic or logon details, making it easy for an eavesdropper to intercept this information."
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

  # Ensure telnet is not allowed by any non-GKE firewall rule
  google_compute_firewalls(project: gcp_project_id).where(firewall_direction: 'INGRESS').where{ firewall_name !~ /^gke-/ }.firewall_names.each do |firewall_name|
    describe "[#{gcp_project_id}] #{firewall_name}" do
      subject { google_compute_firewall(project: gcp_project_id, name: firewall_name) }
      it "should not allow Telnet (tcp/23)" do
        subject.allow_port_protocol?('23', 'tcp').should_not eq(true)
      end
    end
  end
end
