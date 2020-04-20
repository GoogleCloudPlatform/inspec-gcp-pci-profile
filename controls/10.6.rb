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
pci_section = '10.6'

title "[PCI-DSS-#{pci_version}][#{pci_section}] Review logs and security events for all system components to identify anomalies or suspicious activity."

# 10.6
pci_req = "#{pci_section}"
pci_req_title = "Review logs and security events for all system components to identify anomalies or suspicious activity."
pci_req_guidance = "Many breaches occur over days or months before being detected. Regular log reviews by personnel or automated means can identify and proactively address unauthorized access to the cardholder data environment.

The log review process does not have to be manual. The use of log harvesting, parsing, and alerting tools can help facilitate the process by identifying log events that need to be reviewed."
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

  # Ensure project-level export sink is configured
  empty_filter_sinks = []
  google_logging_project_sinks(project: gcp_project_id).names.each do |sink_name|
    if google_logging_project_sink(project: gcp_project_id, name: sink_name).filter == nil
      empty_filter_sinks.push(sink_name)
    end
  end
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Project level Log sink with an empty filter" do
    subject { empty_filter_sinks }
    it "is expected to exist" do
      expect(empty_filter_sinks.count).to be > 0
    end
  end

  # Ensure project ownership changes filter exists
  log_filter = "(protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"REMOVE\" AND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\" AND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")"
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Project Ownership changes filter" do
    subject { google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter) }
    it { should exist }
  end

  # Ensure project ownership alert policy is configured
  google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter).metric_types.each do |metrictype|
    filter = "metric.type=\"#{metrictype}\" resource.type=\"audited_resource\""
    google_project_alert_policies(project: gcp_project_id).where{ policy_filter_list.include? filter }.where(policy_enabled_state: true).policy_names.each do |policy|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Project Ownership changes alert policy" do
        subject { google_project_alert_policy_condition(policy: policy, filter: filter) }
        it { should exist }
        its('aggregation_cross_series_reducer') { should eq 'REDUCE_COUNT' }
        its('aggregation_per_series_aligner') { should eq 'ALIGN_RATE' }
        its('condition_threshold_value') { should eq 0.001 }
        its('aggregation_alignment_period') { should eq '60s' }
      end
    end
  end

  # Ensure audit configuration changes filter exists
  log_filter = "protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*"
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Audit configuration changes filter" do
    subject { google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter) }
    it { should exist }
  end

  # Ensure audit configuration alert policy is configured
  google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter).metric_types.each do |metrictype|
    filter = "metric.type=\"#{metrictype}\" resource.type=\"audited_resource\""
    google_project_alert_policies(project: gcp_project_id).where{ policy_filter_list.include? filter}.where(policy_enabled_state: true).policy_names.each do |policy|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Audit configuration changes alert policy" do
        subject { google_project_alert_policy_condition(policy: policy, filter: filter) }
        it { should exist }
        its('aggregation_cross_series_reducer') { should eq 'REDUCE_COUNT' }
        its('aggregation_per_series_aligner') { should eq 'ALIGN_RATE' }
        its('condition_threshold_value') { should eq 0.001 }
        its('aggregation_alignment_period') { should eq '60s' }
      end
    end
  end

  # Ensure custom role alert metric exists
  log_filter = "resource.type=\"iam_role\" AND protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\""
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Custom Role changes filter" do
    subject { google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter) }
    it { should exist }
  end

  # Ensure custom role alert policy is configured
  google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter).metric_types.each do |metrictype|
    filter = "metric.type=\"#{metrictype}\" resource.type=\"audited_resource\""
    google_project_alert_policies(project: gcp_project_id).where{ policy_filter_list.include? filter }.where(policy_enabled_state: true).policy_names.each do |policy|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Custom Role changes alert policy" do
        subject { google_project_alert_policy_condition(policy: policy, filter: filter) }
        it { should exist }
        its('aggregation_cross_series_reducer') { should eq 'REDUCE_COUNT' }
        its('aggregation_per_series_aligner') { should eq 'ALIGN_RATE' }
        its('condition_threshold_value') { should eq 0.001 }
        its('aggregation_alignment_period') { should eq '60s' }
      end
    end
  end

  # Ensure VPC FW Rule Changes alert metric exists" do
  log_filter = "resource.type=\"gce_firewall_rule\" AND jsonPayload.event_subtype=\"compute.firewalls.patch\" OR jsonPayload.event_subtype=\"compute.firewalls.insert\""
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] VPC FW Rule changes filter" do
    subject { google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter) }
    it { should exist }
  end

  # Ensure VPC FW Rule alert policy is configured
  google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter).metric_types.each do |metrictype|
    filter = "metric.type=\"#{metrictype}\" resource.type=\"audited_resource\""
    google_project_alert_policies(project: gcp_project_id).where{ policy_filter_list.include? filter }.where(policy_enabled_state: true).policy_names.each do |policy|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] VPC FW Rule changes alert policy" do
        subject { google_project_alert_policy_condition(policy: policy, filter: filter) }
        it { should exist }
        its('aggregation_cross_series_reducer') { should eq 'REDUCE_COUNT' }
        its('aggregation_per_series_aligner') { should eq 'ALIGN_RATE' }
        its('condition_threshold_value') { should eq 0.001 }
        its('aggregation_alignment_period') { should eq '60s' }
      end
    end
  end

  # Ensure VPC Route Changes alert metric exists" do
  log_filter = "resource.type=\"gce_route\" AND jsonPayload.event_subtype=\"compute.routes.delete\" OR jsonPayload.event_subtype=\"compute.routes.insert\""
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] VPC Route changes filter" do
    subject { google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter) }
    it { should exist }
  end

  # Ensure VPC Route Changes alert policy is configured
  google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter).metric_types.each do |metrictype|
    filter = "metric.type=\"#{metrictype}\" resource.type=\"audited_resource\""
    google_project_alert_policies(project: gcp_project_id).where{ policy_filter_list.include? filter }.where(policy_enabled_state: true).policy_names.each do |policy|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] VPC Route changes alert policy" do
        subject { google_project_alert_policy_condition(policy: policy, filter: filter) }
        it { should exist }
        its('aggregation_cross_series_reducer') { should eq 'REDUCE_COUNT' }
        its('aggregation_per_series_aligner') { should eq 'ALIGN_RATE' }
        its('condition_threshold_value') { should eq 0.001 }
        its('aggregation_alignment_period') { should eq '60s' }
      end
    end
  end

  # Ensure VPC Network changes alert metric exists" do
  log_filter = "resource.type=gce_network AND jsonPayload.event_subtype=\"compute.networks.insert\" OR jsonPayload.event_subtype=\"compute.networks.patch\" OR jsonPayload.event_subtype=\"compute.networks.delete\" OR jsonPayload.event_subtype=\"compute.networks.removePeering\" OR jsonPayload.event_subtype=\"compute.networks.addPeering\""
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] VPC Network changes filter" do
    subject { google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter) }
    it { should exist }
  end

  # Ensure VPC Network alert policy is configured
  google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter).metric_types.each do |metrictype|
    filter = "metric.type=\"#{metrictype}\" resource.type=\"audited_resource\""
    google_project_alert_policies(project: gcp_project_id).where{ policy_filter_list.include? filter }.where(policy_enabled_state: true).policy_names.each do |policy|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] VPC Network changes alert policy" do
        subject { google_project_alert_policy_condition(policy: policy, filter: filter) }
        it { should exist }
        its('aggregation_cross_series_reducer') { should eq 'REDUCE_COUNT' }
        its('aggregation_per_series_aligner') { should eq 'ALIGN_RATE' }
        its('condition_threshold_value') { should eq 0.001 }
        its('aggregation_alignment_period') { should eq '60s' }
      end
    end
  end

  # Ensure Cloud Storage IAM changes alert metric exists" do
  log_filter = "resource.type=gcs_bucket AND protoPayload.methodName=\"storage.setIamPermissions\""
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Cloud Storage changes filter" do
    subject { google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter) }
    it { should exist }
  end

  # Ensure Cloud Storage IAM alert policy is configured
  google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter).metric_types.each do |metrictype|
    filter = "metric.type=\"#{metrictype}\" resource.type=\"audited_resource\""
    google_project_alert_policies(project: gcp_project_id).where{ policy_filter_list.include? filter }.where(policy_enabled_state: true).policy_names.each do |policy|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Cloud Storage changes alert policy" do
        subject { google_project_alert_policy_condition(policy: policy, filter: filter) }
        it { should exist }
        its('aggregation_cross_series_reducer') { should eq 'REDUCE_COUNT' }
        its('aggregation_per_series_aligner') { should eq 'ALIGN_RATE' }
        its('condition_threshold_value') { should eq 0.001 }
        its('aggregation_alignment_period') { should eq '60s' }
      end
    end
  end

  # Ensure Cloud SQL instance changes alert metrics exists" do
  log_filter = "protoPayload.methodName=\"cloudsql.instances.update\""
  describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Cloud SQL changes filter" do
    subject { google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter) }
    it { should exist }
  end

  # Ensure Cloud SQL alert policy is configured
  google_project_metrics(project: gcp_project_id).where(metric_filter: log_filter).metric_types.each do |metrictype|
    filter = "metric.type=\"#{metrictype}\" resource.type=\"audited_resource\""
    google_project_alert_policies(project: gcp_project_id).where{ policy_filter_list.include? filter }.where(policy_enabled_state: true).policy_names.each do |policy|
      describe "[#{pci_version}][#{pci_req}][#{gcp_project_id}] Cloud SQL changes alert policy" do
        subject { google_project_alert_policy_condition(policy: policy, filter: filter) }
        it { should exist }
        its('aggregation_cross_series_reducer') { should eq 'REDUCE_COUNT' }
        its('aggregation_per_series_aligner') { should eq 'ALIGN_RATE' }
        its('condition_threshold_value') { should eq 0.001 }
        its('aggregation_alignment_period') { should eq '60s' }
      end
    end
  end

end
