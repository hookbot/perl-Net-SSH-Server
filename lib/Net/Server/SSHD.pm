package Net::Server::SSHD;

use strict;
use warnings;
our @ISA = qw(Net::Server::Fork);
sub process_request {
    my $self = shift;
    my $code = $self->{run_inet} or die "$0: Invalid invocation\n";;
    $code->($self);
    die "$0: inet failed\n";
}

1;
