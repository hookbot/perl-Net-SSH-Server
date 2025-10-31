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
    $self->stamp("run_sshd");
    $self->SUPER::run_sshd();
}

sub run_pam_exec {
    my $self = shift;
    $self->stamp("run_pam_exec");
    $self->SUPER::run_pam_exec();
}

sub auth_check {
    my $self = shift;
    $self->stamp("auth_check:MySSHDaemon");
    return 7; # PAM_AUTH_ERR /* Authentication failure */
}

1;
