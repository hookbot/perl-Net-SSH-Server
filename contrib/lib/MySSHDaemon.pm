package MySSHDaemon;

use strict;
use base qw(Net::SSH::Server);

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
    print $fh "$now [$$] [$ppid] [$tag] [@run] STASH[$stash] ENV: ".(join " ", map { "$_=$ENV{$_}" } sort keys %ENV)."\n";
    close $fh;
}

sub trace {
    my $self = shift;
    my $tag = shift || "unknown_stamp";
    $self->stamp($tag);
    return $self->SUPER::trace();
}

sub init {
    my $self = shift;
    $self->trace("init");
    $self->register( override_config_file => "/etc/ssh/sshdproxy_config" );
    $self->register( override_config_directory => "/etc/ssh/sshdproxy_config.d" );
    $self->register( banner => \&banner );
    $self->register( failover_user => "sshproxy" );
    return $self->SUPER::init();
}

sub run_sshd {
    my $self = shift;
    #$self->stash->{banner_code} = sub { "Hello World" };
    #$self->stash->{banner_method} = "banner";
    #$self->stash->{banner_txt} = "WELCOME TO SSH SERVER!\n";
    $self->trace("MySSHDaemon:run_sshd");
    return $self->SUPER::run_sshd();
}

sub banner {
    my $self = shift;
    my ($remote_addr, $remote_port, $server_addr, $server_port) = split / /, $ENV{SSH_CONNECTION};
    $remote_addr = "[$remote_addr]" if $remote_addr =~ /:/;
    $server_addr = "[$server_addr]" if $server_addr =~ /:/;
    return qq{
**** Welcome to the BASTION BOUNCER BOX! ****
MySSHDaemon custom banner for service $ENV{PAM_SERVICE}
Connected from $remote_addr:$remote_port to $server_addr:$server_port
For SSH Public Key help, go here:
https://website.com/settings.html
};
}

# validate_pw
# When "PasswordAuthentication yes" is enabled, then check passwd provided.
# Return PAM_* error code or 0 [PAM_SUCCESS] if no problem:
sub validate_pw {
    my $self = shift;
    my $user = $ENV{PAM_USER}  or return 7; # PAM_AUTH_ERR  /* Authentication failure */
    my $pass = $ENV{PAM_PW} // "";
    $self->stamp("validate_pw:MySSHDaemon");
    if (getpwnam $user) {
        # Real user, so use the default validator
        return $self->SUPER::validate_pw;
    }
    # SUCCESS if any non-empty password is provided
    return $self->validate_nonempty;
}

# validate_user
# Input: $user
# Return: $uid if valid
# DIE with PAM_* error code if $user is not valid user.
sub validate_user {
    my $self = shift;
    my $user = shift         or die 8;  # PAM_CRED_INSUFFICIENT  /* Can not access authentication data */
    my @ent = getpwnam $user;
    $self->trace("MySSHDaemon::validate_user:USER=[$user]:FOUND[@ent]");
    my $uid = @ent > 3 && $ent[2];
    return $uid if defined $uid and length $uid;
    # Allow any user that smells okay:
    $user =~ /^[\w\-\.\@]+$/ or die 10; # PAM_USER_UNKNOWN       /* User not known to the underlying authentication module */
    $uid = getpwnam $self->register("failover_user")->[0];
    return $uid if defined $uid and length $uid;
    die 10; # PAM_USER_UNKNOWN       /* User not known to the underlying authentication module */
}

1;
