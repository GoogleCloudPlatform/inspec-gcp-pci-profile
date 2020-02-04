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
pci_section = '4.1'

title "[PCI-DSS-#{pci_version}][#{pci_section}] Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open, public networks"

# 4.1
pci_req = "#{pci_section}"
pci_req_title = "Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open, public networks"
pci_req_guidance = "Sensitive information must be encrypted during transmission over public networks, because it is easy and common for a malicious individual to intercept and/or divert data while in transit.

Secure transmission of cardholder data requires using trusted keys/certificates, a secure protocol for transport, and proper encryption strength to encrypt cardholder data. Connection requests from systems that do not support the required encryption strength, and that would result in an insecure connection, should not be accepted.

Note that some protocol implementations (such as SSL, SSH v1.0, and early TLS) have known vulnerabilities that an attacker can use to gain control of the affected system. Whichever security protocol is used, ensure it is configured to use only secure versions and configurations to prevent use of an insecure connection—for example, by using only trusted certificates and supporting only strong encryption (not supporting weaker, insecure protocols or methods).

Verifying that certificates are trusted (for example, have not expired and are issued from a trusted source) helps ensure the integrity of the secure connection. "
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

  # All load balancers have custom/strong TLS profiles set
  google_compute_target_https_proxies(project: gcp_project_id).names.each do |proxy|
    describe "[#{gcp_project_id}] HTTPS Proxy: #{proxy}" do
      subject { google_compute_target_https_proxy(project: gcp_project_id, name: proxy) }
      it "should have a custom SSL policy configured" do
        subject.ssl_policy.should_not cmp(nil)
      end
    end
  end
  # Ensure SSL Policies use strong TLS
  google_compute_ssl_policies(project: gcp_project_id).names.each do |policy|
    describe "[#{gcp_project_id}] SSL Policy: #{policy}" do
      subject { google_compute_ssl_policy(project: gcp_project_id, name: policy) }
      it "should minimally require TLS 1.2" do
        subject.min_tls_version.should cmp "TLS_1_2"
      end
      it "profile should be RESTRICTED" do
        subject.profile.should cmp "RESTRICTED"
      end
    end 
  end

end
