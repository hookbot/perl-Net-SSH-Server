package MySSHDaemon;

use strict;
use base qw(Net::SSH::Server);

sub init {
    my $self = shift;
    $self->SUPER::init();
    $self->register( trace_debug => \&stamp );
    $self->register( override_config_file => "/etc/ssh/sshdproxy_config" );
    $self->register( override_config_directory => "/etc/ssh/sshdproxy_config.d" );
    $self->register( preauth_message => \&preauth );
    $self->register( failover_user => "sshproxy" );
    $self->register( skip_unix_password_validation => 0 );
    $self->register( password_validation_error => \&password_error );
    $self->register( skip_unix_username_validation => 0 );
    $self->register( username_validation_error => \&username_error );
    $self->register( skip_unix_shell => 0 );
    $self->register( shell => \&do_shell );
    $self->trace("MySSHDaemon:init:done");
    return;
}

# envdump: Show all %ENV on a single line
sub envdump {
    return join " ", map { (/^[A-Z_]+$/ ? do { my $v = $ENV{$_}; my $q = $v=~s/\\/\\\\/g + $v=~s/\"/\\\"/g + $v=~s/\$/\\\$/g + $v=~s/\n/\\n/ + $v=~s/ / /; ($q ? qq{$_="$v"} : "$_=$v") } : ()); } sort keys %ENV;
}

sub stamp {
    my $self = shift;
    my $tag = shift || "unknown";
    my $now = do {require Time::HiRes;local$_=[Time::HiRes::gettimeofday()];unshift@$_,localtime$_->[0];sprintf"%04d-%02d-%02d_%02d:%02d:%02d.%06d",$_->[5]+1900,$_->[4]+1,@$_[3,2,1,0,10]};
    my $ppid = getppid;
    my @run = @{ $self->{run} };
    my $stash = $self->json->encode($self->stash);
    $stash =~ s/\'/'"\'"'/g;
    open my $fh, ">>", "/tmp/sshclient.log";
    chmod 0666, "/tmp/sshclient.log";
    print $fh "$now [$ppid] [$$] uid=$<:$> [$tag] [@run] STASH[$stash] ENV: @{[$self->envdump]}\n";
    close $fh;
}

sub preauth {
    my $self = shift;
    my ($remote_addr, $remote_port, $server_addr, $server_port) = split / /, $ENV{SSH_CONNECTION};
    $remote_addr = "[$remote_addr]" if $remote_addr =~ /:/;
    $server_addr = "[$server_addr]" if $server_addr =~ /:/;
    $self->trace("preauth($remote_addr:$remote_port=>$server_addr:$server_port)");
    print "**** Welcome to the BASTION BOUNCER BOX! ****\n";
    warn qq{MySSHDaemon custom message for service $ENV{PAM_SERVICE}
Connected from $remote_addr:$remote_port to $server_addr:$server_port
For SSH Public Key help, go here:
https://website.com/settings.html
};
    return;
}

# password_error( $username, $password )
# When "PasswordAuthentication yes" is enabled, then check passwd provided.
# Return PAM_* error code or 0 [PAM_SUCCESS] if no problem:
sub password_error {
    my $self = shift;
    my $user = shift or return 7; # PAM_AUTH_ERR  /* Authentication failure */
    my $pass = shift // "";
    $self->trace("password_error");
    if (getpwnam $user) {
        # Real user, so use the default validator
        return $self->unix_password_validation_error($user, $pass);
    }
    # Return SUCCESS if any non-empty password is provided
    return length $pass ?
        0 : # PAM_SUCCESS   /* Successful function return */
        7 ; # PAM_AUTH_ERR  /* Authentication failure */
}

# username_validation_error( $user )
# Return PAM_* error code or 0 [PAM_SUCCESS] if no problem:
sub username_error {
    my $self = shift;
    my $user = shift        or return 8;  # PAM_CRED_INSUFFICIENT  /* Can not access authentication data */
    my @ent = getpwnam $user;
    $self->trace("MySSHDaemon->username_validation_error:USER=[$user]:FOUND[@ent]");
    @ent > 3               and return 0;  # PAM_SUCCESS   /* Successful function return */
    # Allow any other user that smells okay:
    $user=~/^[\w\-\.\@]+$/ and return 0;  # PAM_SUCCESS   /* Successful function return */
    return 10; # PAM_USER_UNKNOWN       /* User not known to the underlying authentication module */
}

# Spawn shell. Never return.
sub do_shell {
    my $self = shift;
    my $user = shift;
    my $cmd = shift // '';
    $| = 1;
    if (getpwnam $user) {
        # Real user, so fall back to the default handler
        warn localtime().": MySSHDaemon found real user $user\n";
        die "10 # PAM_USER_UNKNOWN";
    }
    #my @pw = getpwnam $user;
    #$self->trace("do_shell:user=$user:pw[@pw]");
    $self->trace("do_shell:user=$user");
    warn localtime().": DEBUG: Running MySSHDaemon do_shell for fake user $user ...\n";
    #if (@pw) {
    #    warn localtime().": MySSHDaemon found real user $user\n";
    #    exit $self->unix_shell($user,$cmd);
    #}
    #my @pw = getpwuid $<;
    #$self->trace("do_shell:uid=$<:pw[@pw]");
    #print "Ran as user: [@pw]\n";
    print "Running as user: $user\n";
    print "Requested command: [$cmd]\n" if length $cmd;
    print "Spawn shell: [@{ $self->{run} }]\n";
    print "ENV: @{[$self->envdump]}\n";
    # This is a fake user so don't actually provide a real shell.
    # Just pretend like the operation was successful.
    print "Created TTY: $ENV{SSH_TTY}\n" if $ENV{SSH_TTY};
    print "Please wait while pretending to run a fake ssh session ...\n";
    for (1..10) { print "."; sleep 1; }
    print "\nBYE!\n";
    sleep 1;
    exit 0;
}

1;
