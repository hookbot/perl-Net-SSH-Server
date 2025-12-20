package Net::SSH::Server::Plugin::InetD;

use strict;
use warnings;
use FindBin qw($Script);
use Net::SSH::Server::Plugin;

our @ISA = qw(Net::SSH::Server::Plugin);

=pod

=head1 NAME

Net::SSH::Server::Plugin::InetD - Plugin to support InetD mode

=head1 SYNOPSYS

  #!/usr/bin/env perl
  # Example daemon launcher script
  # Usage: /usr/sbin/my-custom-ssh-server
  use strict;
  use warnings;
  use Net::SSH::Server;
  Net::SSH::Server->new
    ->register( inetd_mode_preferred => 1 )
    ->run;

=head1 DESCRIPTION

This plugin provides a way to switch from either the
security-hardened -R re-exec mode or the -r undocumented
internal sshd fork mode to an external inetd mode.
This is intended to be used on systems without re-exec
mode in order to provide more functionality.
This InetD mode is disabled by default unless re-exec
mode is not supported at all by the real sshd.
You can force inetd mode by installing Net::Server::Fork
and enabling the "inetd_mode_preferred" register flag.

=head1 METHODS

The following methods are utilitized:

=head2 new()

Constructor stolen from Net::Server::Fork for compatibility

=cut
sub new {
    my $class = shift || die "Missing class";
    my $args  = @_ == 1 ? shift : {@_};
    return bless {server => {%$args}}, $class;
}

sub load {
    my $plugin_obj = shift;
    shift; # Ignore main Server engine object
    $plugin_obj->register( hook_exec_target => "inetd_check_reexec" );
    $plugin_obj->create_method( inetd_check_reexec => \&inetd_check_reexec );
    $plugin_obj->register( hook_connection => "inetd_client" );
    $plugin_obj->create_method( inetd_client => \&inetd_client );
}

=head2 inetd_client( $sockaddr)

Triggered when a client connects

=cut
sub inetd_client {
    my $plugin_obj = shift;
    shift; # Ignore main Server engine object
    shift; # Ignore client sockaddr
    # Flag this execution as a client connection for later
    $plugin_obj->register( inetd_client_connection => 1 );
}

=head2 inetd_check_reexec()

Check "inetd_mode_preferred" flag or missing "has_reexec" support.
If so, then try switching from "-R" reexec mode to "-i" inetd mode.
If Net::Server is not installed, then falls back to system setting.

=cut
sub inetd_check_reexec {
    my $plugin_obj = shift;
    my $sshd = shift;
    $sshd->trace("inetd_check_reexec:top");
    my $target = $sshd->target;
    if (!$sshd->register("inetd_client_connection")->[0] # Skip if it's an actual client connection
        and !grep { /^-\w*[dirRtT]/ } $sshd->cmdline) {
        # Not a client connection
        # Not -d Debug mode
        # Not -i Inet mode
        # Not -R Re-exec child mode
        # Not -r forced Re-exec server mode
        # Not -t Test validation
        # Not -T extended Test mode
        # So we must actually bind, listen, & do accept loop.
        # So we need to do either sshd re-exec mode or Net::Server mode:
        if ($sshd->register("inetd_mode_preferred")->[0]  # Desires to use Net::Server::Fork mode
            or !$sshd->do_method( supported => "has_reexec" )) {  # Or reexec not supported
            # So need to pretend like sshd and bind the port and listen for connections and run the inetd children for each connection.
            # Don't let sshd attempt to do send_rexec_state using -R reexec mode.
            if (eval { require Net::Server::Fork; 1; }) {
                $sshd->trace("inetd_check_reexec:Switching to Net::Server::Fork mode");
                my $conf = $sshd->sshd_config;
                # Conjure ports so Net::Server bind()s compatibly like sshd would
                my $port = [ map { /^((\d+\.\d+\.\d+\.\d+)|\[[0-9a-fA-F:]+\]):(\d+)$/ ? { host => $1, port => $3, ipv => ($2?4:6) } : () } @{ $conf->{listenaddress} } ];
                my $run_args = {
                    port => $port,
                    pid_file => ($conf->{pidfile}->[0] || "/var/run/$Script.pid"),
                };
                my $log_file = undef;
                foreach ($sshd->cmdline) {
                    $log_file = $_ if defined $log_file;  # Specify log_file: -E <log_file>
                    $log_file = $1 if /^-\w*E(.*)$/;      # Specify log_file: -E<log_file>
                    $log_file = '/dev/null' if /^-\w*q/;  # Don't log for Quiet Mode: -q
                    $log_file = 'STDERR' if /^-\w*e/;     # Log to STDERR: -e
                    last if $log_file;
                }
                $log_file //= do { $run_args->{syslog_ident} = $Script; 'Sys::Syslog' }; # Default to syslog
                $run_args->{log_file} = $log_file if $log_file ne 'STDERR'; # Omit {log_file} for option: -e
                $sshd->cmdline("-i");
                my @run = @{ $sshd->{run} };
                unshift @ISA, 'Net::Server::Fork' if !grep { $_ eq 'Net::Server::Fork' } @ISA;
                $plugin_obj->{run_inet} = sub { exec { $run[0] } @run or die "$0: spawn failure: $!\n" };
                $plugin_obj->run($run_args) or die "$0: Failed to launch Net::Server\n";
            }
            $sshd->trace("inetd_check_reexec:Net::Server FAILURE: $@");
        }
    }
    # Falling back to -r or -R mode.
    $sshd->trace("inetd_check_reexec:Not using Net::Server");
}

=head2 process_request()

This handles the incoming connection by spawning
myself with the "-i" flag for inetd mode.

=cut
sub process_request {
    my $plugin_obj = shift;
    my $code = $plugin_obj->{run_inet} or die "$0: Invalid invocation\n";;
    $code->($plugin_obj);
    die "$0: inet failed\n";
}

1;

=head1 SEE ALSO

  Net::Server::Fork

=head1 AUTHOR

  Rob Brown <bbb@cpan.org>

  Copyright 2025

  Perl Artistic License

=cut
