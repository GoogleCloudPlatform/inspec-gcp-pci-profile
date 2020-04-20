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
pci_section = '3.5'

kms_regions_list = attribute('kms_regions_list')
kms_admins_list = attribute('kms_admins_list')
kms_encrypters_list = attribute('kms_encrypters_list')
kms_decrypters_list = attribute('kms_decrypters_list')
kms_encrypterdecrypters_list = attribute('kms_encrypterdecrypters_list')
kms_rotation_period_seconds = attribute('kms_rotation_period_seconds')

title "[PCI-DSS-#{pci_version}][#{pci_section}] Document and implement procedures to protect keys used to secure stored cardholder data against disclosure and misuse"

# 3.5.2
pci_req = "#{pci_section}.2"
pci_req_title = "Restrict access to cryptographic keys to the fewest number of custodians necessary"
pci_req_guidance = "There should be very few who have access to cryptographic keys (reducing the potential for rending cardholder data visible by unauthorized parties), usually only those who have key custodian responsibilities. "
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

  keyrings = false 
  locations.each do |location|
    sleep 6
    if google_kms_key_rings(project: gcp_project_id, location: location).key_ring_names.count > 0
      keyrings = true
      break
    end
  end

  if keyrings
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure KMS Admins" do
      subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/cloudkms.admin') }
      it "matches the KMS admins allow list" do
        expect(subject.members).to cmp(kms_admins_list).or eq(nil).or cmp([])
      end
    end
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure KMS Encrypter are on a white list" do
      subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/cloudkms.encrypter') }
      it "matches the KMS Encrypters allow list" do
        expect(subject.members).to cmp(kms_encrypters_list).or eq(nil).or cmp([])
      end
    end
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure KMS Decrypter are on a white list" do
      subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/cloudkms.decrypter') }
      it "matches the KMS Decrypters allow list" do
        expect(subject.members).to cmp(kms_decrypters_list).or eq(nil).or cmp([])
      end
    end
    describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Ensure KMS Encrypter/Decrypter are on a white list" do
      subject { google_project_iam_binding(project: gcp_project_id, role: 'roles/cloudkms.encrypterdecrypter') }
      it "matches the KMS EncrypterDecrypters allow list" do
        expect(subject.members).to cmp(kms_encrypterdecrypters_list).or eq(nil).or cmp([])
      end
    end
  end

end

# 3.5.3
pci_req = "#{pci_section}.3"
pci_req_title = "Store secret and private keys used to encrypt/decrypt cardholder data in a KMS"
pci_req_guidance = "Cryptographic keys must be stored securely to prevent unauthorized or unnecessary access that could result in the exposure of cardholder data.

It is not intended that the key-encrypting keys be encrypted, however they are to be protected against disclosure and misuse as defined in Requirement 3.5. If key-encrypting keys are used, storing the key-encrypting keys in physically and/or logically separate locations from the dataencrypting keys reduces the risk of unauthorized access to both keys."
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

  # Ensure all KMS Keys in each Keyring are HSM-backed.
  locations.each do |location|
    google_kms_key_rings(project: gcp_project_id, location: location).key_ring_names.each do |keyring|
      google_kms_crypto_keys(project: gcp_project_id, location: location, key_ring_name: keyring).crypto_key_names.each do |keyname|
        key = google_kms_crypto_key(project: gcp_project_id, location: location, key_ring_name: keyring, name: keyname)
        if key.primary_state == "ENABLED"
          describe "[#{gcp_project_id}] #{key.crypto_key_name}" do
            subject { key }
            its('version_template.protection_level') { should match /HSM/i }
          end
        end
      end
    end
  end

end

# 3.5.4
pci_req = "#{pci_section}.4"
pci_req_title = "Store cryptographic keys in the fewest possible locations."
pci_req_guidance = "Storing cryptographic keys in the fewest locations helps an organization to keep track and monitor all key locations, and minimizes the potential for keys to be exposed to unauthorized parties."
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

  # Ensure all KMS Keys are in the fewest locations possible
  keyring_locations = []
  locations.each do |location|
    google_kms_key_rings(project: gcp_project_id, location: location).key_ring_names.each do |keyring|
      keyring_locations << location
    end
  end
  keyring_locations.sort!.uniq! unless keyring_locations.empty?

  describe "[#{gcp_project_id}] KMS Regions #{ keyring_locations }" do
    subject { keyring_locations }
    it { should be_in kms_regions_list.sort }
  end

end
