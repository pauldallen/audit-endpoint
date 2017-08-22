coreo_agent_selector_rule 'check-echo' do
  action :define
  timeout 30
  control 'check if echo exist' do
    describe command('echo') do
      it { should exist }
    end
  end
end

coreo_agent_audit_profile 'linux-cis' do
  action :define
  selectors ['check-echo']
  profile 'https://github.com/dev-sec/cis-dil-benchmark/archive/master.zip'
  timeout 120
end

coreo_agent_rule_runner 'agent-rules' do
  action :run
  profiles ['linux-cis']
end
