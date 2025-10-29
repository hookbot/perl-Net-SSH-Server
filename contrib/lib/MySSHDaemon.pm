package MySSHDaemon;

use strict;
use base qw(Net::SSH::Server);

sub stamp {
    my $self = shift;
    my $now = do {require Time::HiRes;local$_=[Time::HiRes::gettimeofday()];unshift@$_,localtime$_->[0];sprintf"%04d-%02d-%02d_%02d:%02d:%02d.%06d",$_->[5]+1900,$_->[4]+1,@$_[3,2,1,0,10]};
    my $ppid = getppid; my @run = @{ $self->{run} };
    system "echo $now [$$] [$ppid] [@run] ENV: \$(env|sort) >> /tmp/sshclient.log"; chmod 0666, "/tmp/sshclient.log";
}

sub run_sshd {
    my $self = shift;
    $self->stash->{override_config_file} = "/etc/ssh/sshdproxy_config";
    $self->stamp;
    $self->SUPER::run_sshd();
}

sub run_pam_exec {
    my $self = shift;
    $self->stamp;
    $self->SUPER::run_pam_exec();
}

1;
