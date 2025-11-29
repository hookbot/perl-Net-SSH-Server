package MySSHDaemon;

use strict;
use base qw(Net::SSH::Server);

sub init {
    my $self = shift;
    $self->trace("MySSHDaemon:init");
    $self->SUPER::init();
    $self->register( trace_debug => \&stamp );
    $self->register( override_config_file => "/etc/ssh/sshdproxy_config" );
    $self->register( override_config_directory => "/etc/ssh/sshdproxy_config.d" );
    $self->register( banner => \&banner );
    $self->register( failover_user => "sshproxy" );
    $self->register( skip_unix_password_validation => 0 );
    $self->register( password_validation_error => \&password_error );
    $self->register( skip_unix_username_validation => 0 );
    $self->register( username_validation_error => \&username_error );
    return;
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
    print $fh "$now [$ppid] [$$] uid=$<:$> [$tag] [@run] STASH[$stash] ENV: ".(join " ", map { "$_=$ENV{$_}" } sort keys %ENV)."\n";
    close $fh;
}

sub banner {
    my $self = shift;
    my ($remote_addr, $remote_port, $server_addr, $server_port) = split / /, $ENV{SSH_CONNECTION};
    $remote_addr = "[$remote_addr]" if $remote_addr =~ /:/;
    $server_addr = "[$server_addr]" if $server_addr =~ /:/;
    $self->trace("banner($remote_addr:$remote_port=>$server_addr:$server_port)");
    return qq{
**** Welcome to the BASTION BOUNCER BOX! ****
MySSHDaemon custom banner for service $ENV{PAM_SERVICE}
Connected from $remote_addr:$remote_port to $server_addr:$server_port
For SSH Public Key help, go here:
https://website.com/settings.html
};
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

1;
