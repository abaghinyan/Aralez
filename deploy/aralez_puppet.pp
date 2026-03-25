# =============================================================================
# Puppet module manifest for deploying Aralez
# Save this as module/aralez/manifests/init.pp
# =============================================================================
#
# Usage in node definition:
# node 'default' {
#   class { 'aralez':
#     binary_source => 'puppet:///modules/aralez/aralez_x64_linux',
#     output_dest   => 'sftp://forensic@collector.corp/incoming',
#   }
# }
#

class aralez (
  String $binary_source = 'puppet:///modules/aralez/aralez_x64_linux',
  String $output_dest   = 's3://forensic-bucket/incoming',
  String $work_dir      = '/opt/aralez',
  Boolean $run_once     = true,
) {

  # Create the working directory
  file { $work_dir:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # Download the binary
  file { "${work_dir}/aralez":
    ensure  => file,
    source  => $binary_source,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    require => File[$work_dir],
  }

  # Flag file to prevent running on every puppet agent run if run_once is true
  $flag_file = "${work_dir}/.aralez_ran"

  # The exact command to run
  $cmd = "cd ${work_dir} && ./aralez --output '${output_dest}'"
  
  if $run_once {
    $exec_cmd = "${cmd} && touch ${flag_file}"
    $creates  = $flag_file
  } else {
    $exec_cmd = $cmd
    $creates  = undef
  }

  # Execute Aralez
  exec { 'run_aralez':
    command     => $exec_cmd,
    path        => ['/usr/bin', '/usr/sbin', '/bin', '/sbin'],
    user        => 'root',
    timeout     => 3600, # 1 hour max
    require     => File["${work_dir}/aralez"],
    creates     => $creates, # Only runs if this file does NOT exist (if run_once is true)
    logoutput   => on_failure,
  }
}
