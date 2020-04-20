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
pci_section = '3.6'

kms_rotation_period_seconds = attribute('kms_rotation_period_seconds')

title "[PCI-DSS-#{pci_version}][#{pci_section}] Fully document and implement all keymanagement processes and procedures for cryptographic keys used for encryption of cardholder data"

# 3.6.4
pci_req = "#{pci_section}.4"
pci_req_title = "Cryptographic key changes for keys that have reached the end of their cryptoperiod."
pci_req_guidance = "A cryptoperiod is the time span during which a particular cryptographic key can be used for its defined purpose. Considerations for defining the cryptoperiod include, but are not limited to, the strength of the underlying algorithm, size or length of the key, risk of key compromise, and the sensitivity of the data being encrypted.

Periodic changing of encryption keys when the keys have reached the end of their cryptoperiod is imperative to minimize the risk of someone’s obtaining the encryption keys, and using them to decrypt data."
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

  # Get all "normal" regions and add "global"
  locations = google_compute_regions(project: gcp_project_id).region_names
  locations << 'global'

  # Ensure KMS keys autorotate 90d or less
  locations.each do |location|
    google_kms_key_rings(project: gcp_project_id, location: location).key_ring_names.each do |keyring|
      sleep 6
      google_kms_crypto_keys(project: gcp_project_id, location: location, key_ring_name: keyring).crypto_key_names.each do |keyname|
        sleep 6
        key = google_kms_crypto_key(project: gcp_project_id, location: location, key_ring_name: keyring, name: keyname)
        rotation_period_int = key.rotation_period.delete_suffix('s').to_i
        if key.primary_state == "ENABLED"
          describe "[#{gcp_project_id}] #{key.crypto_key_name}" do
            subject { key }
            it "should have a lower or equal rotation period than #{kms_rotation_period_seconds}" do
              expect(rotation_period_int).to be <= kms_rotation_period_seconds
            end
            its('next_rotation_time') { should be <= (Time.now + kms_rotation_period_seconds) }
          end
        end
      end
    end
  end

end
