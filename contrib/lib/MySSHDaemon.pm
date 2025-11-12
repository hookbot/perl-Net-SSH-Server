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
    return qq{
**** Welcome to the BASTION BOUNCER BOX! ****
MySSHDaemon custom banner.
Connected from $remote_addr to $server_addr
For SSH Public Key help, go here:
https://website.com/settings.html
};
}

sub run_pam_exec {
    my $self = shift;
    $self->stamp("run_pam_exec");
    return $self->SUPER::run_pam_exec();
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

1;
