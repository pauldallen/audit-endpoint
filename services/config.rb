coreo_aws_rule "ec2-ip-address-whitelisted" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-ip-address-whitelisted.html"
  description "Security Group contains IP address"
  category "Security"
  suggested_action "Review Security Group to ensure that the host ip address added is to allowed access."
  level "Warning"
  objectives ["security_groups"]
  audit_objects ["security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["=~"]
  raise_when [/\/32/]
end

coreo_aws_rule_runner "ec2" do
  service :ec2
  id_map ["object.security_groups.group_id"]
  rules ["ec2-ip-address-whitelisted"]
  regions ["us-east-1"]
  action :run
end
coreo_agent_selector_rule "check-echo" do
  action :define
  timeout 5
  control 'nutcracker-connect-redis-001' do
    describe command('echo') do
      it { should exist }
    end
  end
end

coreo_agent_audit_rule 'echo-hello' do
  action :define
  link 'http://kb.cloudcoreo.com/'
  display_name 'Echo hello'
  description 'Echo hello and check for the output'
  category 'Security'
  suggested_action 'Unset MySQL password in your ENV'
  level 'High'
  selectors ['check-echo']
  timeout 0
  control 'echo-hello' do
    impact 1.0
    describe command('echo hello') do
      its('stdout') { should eq "hello\n" }
      its('stderr') { should eq '' }
      its('exit_status') { should eq 0 }
    end
  end
end

coreo_agent_selector_rule "check-mysql" do
  action :define
  timeout 5
  control 'nutcracker-connect-redis-001' do
    describe command('mysqld') do
      it { should exist }
    end
  end
end

coreo_agent_audit_rule "mysql-3" do
  action :define
  link "http://kb.cloudcoreo.com/"
  display_name "Do not store your MySQL password in your ENV"
  description "Storing credentials in your ENV may easily expose them to an attacker. Prevent this at all costs."
  category "Security"
  suggested_action "Unset MySQL password in your ENV"
  level "High"
  selectors ["check-mysql"]
  control 'mysql-3' do
    impact 1.0
    title 'Do not store your MySQL password in your ENV'
    desc '
  Storing credentials in your ENV may easily expose
  them to an attacker. Prevent this at all costs.
      '
    describe command('env') do
      its('stdout') { should_not match(/^MYSQL_PWD=/) }
    end
  end
  timeout 60
end

coreo_agent_rule_runner 'agent-rules' do
  action :run
  regions ['us-east-1', 'us-west-2']
  rules ['echo-hello', 'mysql-3']
end

coreo_uni_util_notify "agent-email" do
  action :notify
  type 'email'
  allow_empty true
  payload 'COMPOSITE::coreo_agent_rule_runner.agent-rules.report'
  endpoint ({
      to: 'nandesh@cloudcoreo.com'
  })
end
