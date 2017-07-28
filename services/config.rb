coreo_agent_selector_rule "check-echo" do
  action :define
  timeout 5
  control 'check if echo exist' do
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
  suggested_action 'Make sure hello is the output.'
  level 'low'
  selectors ['check-echo']
  timeout 5
  control 'echo-hello' do
    impact 1.0
    describe command('echo hello') do
      its('stdout') { should eq "hello\n" }
      its('stderr') { should eq '' }
      its('exit_status') { should eq 0 }
    end
  end
end

coreo_agent_audit_rule "mysql-env-password" do
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
  timeout 5
end

coreo_agent_rule_runner 'agent-rules' do
  action :run
  rules ${AUDIT_AGENT_ALERT_LIST}
end
