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
        OptBool.new("CLEANUP", [true, "Cleanup artifacts or not.", true])
      ])
  end

  def clean
    print_status("Cleaning up artifacts")

    cmd = "rm ~/t1153-source.sh ~/t1153-dot.sh ~/t1153-source-proof.txt ~/t1153-dot-proof.txt || echo fail"
    rm_script = cmd_exec(cmd)
    # Test for success
    if rm_script.include? 'fail'
      print_error("Failed to remove artifacts")
    end

    print_status("Cleanup complete")

  end

  def crontab_file
    ### Start replace conrtab with file
    puts('')
    print_status('Backing up current crontab')
    old_crontab_cmd = cmd_exec('crontab -l > ~/old_crontab')

    print_status('Replacing crontab with file')
    cmd = 'echo "* * * * * echo T1168-crontab-file-proof > '
    cmd += '~/T1168-crontab-file-proof.txt" > ~/t1168-crontab && crontab '
    cmd += '~/t1168-crontab || echo fail'
    crontab_file_cmd = cmd_exec(cmd)
    print_error('Crontab file tactic failed to stage') if crontab_file_cmd.include? 'fail'
    # Ensure job runs
    sleep 3

    cmd = 'ls ~/T1168-crontab-file-proof.txt || echo fail'
    proof = cmd_exec(cmd)
    if proof.include? 'fail'
      print_error('Crontab file tactic executed but no proof was found.')
    else
      print_good('Crontab file tactic successful!')
    end

    if datastore['CLEANUP'] == true
      print_status('Cleaning up files...')
      cmd = 'rm ~/T1168-crontab-file-proof.txt ~/t1168-crontab || echo fail'
      cleanup = cmd_exec(cmd)
      if cleanup.include? 'fail'
        print_error('Unable to cleaup crontab files')
      else
        print_status('Cleaned up crontab files')
      end

      print_status("Restoring crontab...")
      cmd = 'crontab old_crontab || echo fail'
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
    cmd = "echo 'echo T1168-cron-daily-proof > ~/T1168-crontab-file-proof.txt' "
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
    print_status('Adding at task')
    at_installed = cmd_exec('which at || echo fail')
    if at_installed.include? 'fail'
      print_error('at not installed...skipping')
      return
    end

    cmd = "echo 'echo T1168-at > ~/T1168-at-proof.txt' | at now + 1 minute"
    task = cmd_exec(cmd)
    print_status("Sleeping 1 minute to check execution")
    # Make sure task has time to execute
    sleep 62

    cmd = 'ls ~/T1168-at-proof.txt || echo fail'
    proof = cmd_exec(cmd)
    if proof.include? 'fail'
      print_error('at tactic executed but no proof was found.')
    else
      print_good('at tactic successful!')
    end

    if datastore['CLEANUP'] == true
      cmd = 'rm ~/T1168-at-proof.txt || echo fail'
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

  def run
    return 0 if session.type != "meterpreter"

    print_status("Identified OS as: #{sysinfo['OS']}")

    # Module starting
    print_status('Testing tactics in the following order: ')
    print_status("\tReplace crontab with file (Unix and OSX)")
    print_status("\tAdd script to cron folder (Unix only)")
    print_status("\tCreate an at task (Unix and OSX)")
    print_status("\tEvent Monitor Daemon Persistence (OSX only)")
    print_status("\tlaunchd (OSX only)")
    puts('')

    crontab_file
    cron_daily if !sysinfo['OS'].include? 'macOS'
    at

  end
end
