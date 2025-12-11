package Net::SSH::Server::Supported;

use strict;
use warnings;

sub load {
    my $self = shift;
    return if $self->stash->{supported};
    my $target = $self->target;
    my $feature = $self->stash->{supported} = {};
    $feature->{has_reexec} = do {
        local $_ = `$target -e -R 2>&1`;
        # [ssh_msg_recv: read: header\nrecv_rexec_state: ssh_msg_recv failed] or [-R not supported here]
        /recv_rexec_state/ ? 1 : /not supported/ ? 0 : undef;
    };
    return;
};

1;
