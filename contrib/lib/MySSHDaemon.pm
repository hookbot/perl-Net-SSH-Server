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
    $self->stamp("init");
}

sub run_sshd {
    my $self = shift;
    $self->stash->{override_config_file} = "/etc/ssh/sshdproxy_config";
    $self->stash->{override_config_directory} = "/etc/ssh/sshdproxy_config.d";
    #$self->stash->{banner_code} = sub { "Hello World" };
    #$self->stash->{banner_method} = "banner";
    #$self->stash->{banner_txt} = "WELCOME TO SSH SERVER!\n";
    $self->stamp("run_sshd");
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

# When "PasswordAuthentication yes" is enabled, then check passwd provided.
# Return PAM_* error code or 0 [PAM_SUCCESS] if no problem:
sub validate_pw {
    my $self = shift;
    #my $user = $ENV{PAM_USER}  or return 7; # PAM_AUTH_ERR  /* Authentication failure */
    my $pass = $ENV{PAM_PW} // "";
    $self->stamp("validate_pw:MySSHDaemon");
    # SUCCESS if any non-empty password is provided
    return length $ENV{PAM_PW} ?
        0 : # PAM_SUCCESS   /* Successful function return */
        7 ; # PAM_AUTH_ERR  /* Authentication failure */
}

# Verify PAM_USER provided.
# Return PAM_* error code or 0 [PAM_SUCCESS] if no problem:
sub validate_user {
    my $self = shift;
    my $user = $ENV{PAM_USER} or return 8;  # PAM_CRED_INSUFFICIENT  /* Can not access authentication data */
    my @ent = getpwnam $user;
    $self->trace("MySSHDaemon::validate_user:USER=[$user]:FOUND[@ent]");
    #@ent                     or return 10; # PAM_USER_UNKNOWN       /* User not known to the underlying authentication module */
    # Allow any user that smells okay:
    $user =~ /^[\w\-\@]+$/    or return 10; # PAM_USER_UNKNOWN       /* User not known to the underlying authentication module */
    $self->pam_putenv( SSH_USER => $user );
    #$self->pam_putenv( USER => $user ); ### Totally doesn't work because bash bricks over $USER immediately
    return 0;                               # PAM_SUCCESS            /* Successful function return */
}

1;
