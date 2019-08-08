##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'AppleScript (T1155) macOS - Purple Team',
      'Description'    => %q(
        macOS and OS X applications send AppleEvent messages to each other for
        interprocess communications (IPC). These messages can be easily
        scripted with AppleScript for local or remote IPC. Osascript executes
        AppleScript and any other Open Scripting Architecture (OSA) language
        scripts. A list of OSA languages installed on a system can be found by
        using the osalang program. AppleEvent messages can be sent
        independently or as part of a script. These events can locate open
        windows, send keystrokes, and interact with almost any open application
        locally or remotely.  Adversaries can use this to interact with open
        SSH connection, move to remote machines, and even present users with
        fake dialog boxes. These events cannot start applications remotely
        (they can start them locally though), but can interact with
        applications if they're already running remotely. Since this is a
        scripting language, it can be used to launch more common techniques
        as well such as a reverse shell via python (Citation: Macro Malware
        Targets Macs). Scripts can be run from the command-line via osascript
        /path/to/script or osascript -e "script here".
      ),
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx' ],
      'References'     => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1155' ] ],
      'SessionTypes'   => [ 'meterpreter' ]))
    register_options(
      [
        OptBool.new("CLEANUP", [true, "Cleanup artifacts or not.", true]),
      ])
  end

  def run
    return 0 if session.type != "meterpreter"
    print_status('Using AppleScript to execute Python to run arbitrary commands...')

    # Run the command
    cmd = %q(osascript -e 'do shell script "touch /tmp/t1155m.txt"')
    puts(cmd)
    output = cmd_exec(cmd)
    puts(output)
    if output.include? 'fail'
      print_error('Command failed to execute!')
      return
    end

    # Check for success
    success = cmd_exec('ls /tmp/t1155m.txt || echo fail')
    if success.include? 'fail'
      print_error('Tactic executed but proof file was not found.')
      return
    end
    print_good('Tactic T1155 successfully executed!')

    # Cleanup
    if datastore['CLEANUP']
      print_status('Cleaning up artifacts...')
      clean_file = cmd_exec('rm -f /tmp/t1155m.txt || echo fail')
      if clean_file.include? 'fail'
        print_error('Failed to remove artifacts.')
      end
    end
  end
end
