require_relative 'common'
require 'fileutils'
require 'tmpdir'
require 'net/ssh'

require 'timeout'

# see Vagrantfile,playbook for env.
# we're running as net_ssh_1 user password foo
# and usually connecting to net_ssh_2 user password foo2pwd
class TestCertHostAuth < NetSSHTest
  include IntegrationTestHelpers

  def setup_ssh_env(principals: "one.hosts.netssh", validity: "+30d", &block)
    tmpdir do |dir|
      cert_type = "rsa"
      # cert_type = "ssh-ed25519"
      host_key_type = "ecdsa"
      # host_key_type = "ed25519"

      # create a cert, and sign the host key
      @cert = "#{dir}/ca"
      sh "rm -rf #{@cert} #{@cert}.pub"
      sh "ssh-keygen -t #{cert_type} -N '' -C 'ca@hosts.netssh' -f #{@cert} #{debug ? '' : '-q'}"
      FileUtils.cp "/etc/ssh/ssh_host_#{host_key_type}_key.pub", "#{dir}/one.hosts.netssh.pub"
      Dir.chdir(dir) do
        principals_arg = principals.to_s.empty? ? "" : "-n #{principals}"
        sh "ssh-keygen -s #{@cert} -h -I one.hosts.netssh -V #{validity} #{principals_arg} #{debug ? '' : '-q'} #{dir}/one.hosts.netssh.pub"
        sh "ssh-keygen -L -f one.hosts.netssh-cert.pub" if debug
      end
      signed_host_key = "/etc/ssh/ssh_host_#{host_key_type}_key-cert.pub"
      sh "sudo cp -f #{dir}/one.hosts.netssh-cert.pub #{signed_host_key}"

      # we don't use this for signing the cert
      @badcert = "#{dir}/badca"
      sh "rm -rf #{@badcert} #{@badcert}.pub"
      sh "ssh-keygen -t #{cert_type} -N '' -C 'ca@hosts.netssh' -f #{@badcert} #{debug ? '' : '-q'}"
      yield(cert_pub: "#{@cert}.pub", badcert_pub: "#{@badcert}.pub", signed_host_key: signed_host_key)
    end
  end

  def debug
    false
  end

  def test_host_should_match_when_host_key_was_signed_by_key
    Tempfile.open('cert_kh') do |f|
      setup_ssh_env do |params|
        data = File.read(params[:cert_pub])
        f.write("@cert-authority [*.hosts.netssh]:2200 #{data}")
        f.close

        config_lines = ["HostCertificate #{params[:signed_host_key]}"]
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(500) do
            # sleep 0.2
            # sh "ssh -v -i ~/.ssh/id_ed25519 one.hosts.netssh -o UserKnownHostsFile=#{f.path} -p 2200"
            ret = Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path]) do |ssh|
              ssh.exec! "echo 'foo'"
            end
            assert_equal "foo\n", ret
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end

  def test_with_other_pub_key_host_key_should_not_match
    Tempfile.open('cert_kh') do |f|
      setup_ssh_env do |params|
        data = File.read(params[:badcert_pub])
        f.write("@cert-authority [*.hosts.netssh]:2200 #{data}")
        f.close

        config_lines = ["HostCertificate #{params[:signed_host_key]}"]
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(100) do
            sleep 0.2
            assert_raises(Net::SSH::HostKeyMismatch) do
              Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path]) do |ssh|
                ssh.exec! "echo 'foo'"
              end
            end
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end

  def test_with_expired_certificate_should_fail
    Tempfile.open('cert_kh') do |f|
      setup_ssh_env(validity: "-30d:-1d") do |params|
        data = File.read(params[:cert_pub])
        f.write("@cert-authority [*.hosts.netssh]:2200 #{data}")
        f.close

        config_lines = ["HostCertificate #{params[:signed_host_key]}"]
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(500) do
            # sleep 0.2
            # sh "ssh -v -i ~/.ssh/id_ed25519 one.hosts.netssh -o UserKnownHostsFile=#{f.path} -p 2200"
            assert_raises(Net::SSH::HostKeyMismatch) do
              Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path]) do |ssh|
                ssh.exec! "echo 'foo'"
              end
            end
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end

  def test_host_should_match_when_host_key_was_signed_by_key_and_matching_principal
    Tempfile.open('cert_kh') do |f|
      setup_ssh_env do |params|
        data = File.read(params[:cert_pub])
        f.write("@cert-authority [*.hosts.netssh]:2200 #{data}")
        f.close

        config_lines = ["HostCertificate #{params[:signed_host_key]}"]
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(500) do
            # sleep 0.2
            # sh "ssh -v -i ~/.ssh/id_ed25519 one.hosts.netssh -o UserKnownHostsFile=#{f.path} -p 2200"
            ret = Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path]) do |ssh|
              ssh.exec! "echo 'foo'"
            end
            assert_equal "foo\n", ret
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end

  def test_host_should_match_when_host_key_was_signed_by_key_and_no_principal_in_certificate
    Tempfile.open('cert_kh') do |f|
      setup_ssh_env(principals: "") do |params|
        data = File.read(params[:cert_pub])
        f.write("@cert-authority [*.hosts.netssh]:2200 #{data}")
        f.close

        config_lines = ["HostCertificate #{params[:signed_host_key]}"]
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(500) do
            # sleep 0.2
            # sh "ssh -v -i ~/.ssh/id_ed25519 one.hosts.netssh -o UserKnownHostsFile=#{f.path} -p 2200"
            ret = Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path]) do |ssh|
              ssh.exec! "echo 'foo'"
            end
            assert_equal "foo\n", ret
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end

  def test_host_should_not_match_when_host_key_was_signed_by_key_not_not_matching_principal
    Tempfile.open('cert_kh') do |f|
      setup_ssh_env do |params|
        data = File.read(params[:cert_pub])
        f.write("@cert-authority [*.hosts.netssh]:2200 #{data}")
        f.close

        config_lines = ["HostCertificate #{params[:signed_host_key]}"]
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(500) do
            sleep 0.2
            # sh "ssh -v -i ~/.ssh/id_ed25519 anotherone.hosts.netssh -o UserKnownHostsFile=#{f.path} -p 2200"
            assert_raises(Net::SSH::HostKeyUnknown) do
              Net::SSH.start("anotherone.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path]) do |ssh|
                ssh.exec! "echo 'foo'"
              end
            end
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end
end
