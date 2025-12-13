package Net::SSH::Server::Plugin::Supported;

use strict;
use warnings;
use base qw(Net::SSH::Server::Plugin);
use Carp qw(croak);

=head1 NAME

Net::SSH::Server::Plugin::Supported - Plugin to probe for sshd capabilities depending on the Version and OS

=head1 METHODS:

=cut

sub load {
    my $self = shift;
    shift; # Ignore main Server engine object
    $self->create_method( supported => \&supported );
}

=pod

=head2 supported( $capability )

Returns whether or not $capability is supported.

=cut
sub supported {
    my $self = shift;
    my $sshd = shift;
    my $capability = shift or croak 'supported( $capability ): Syntax error';
    # Cache supported capabilites since they never change
    $self->{cache_supported} ||= do {
        my $s = {};
        my $target = $sshd->target;
        $s->{has_reexec} = do {
            local $_ = `$target -e -R 2>&1`;
            # [ssh_msg_recv: read: header\nrecv_rexec_state: ssh_msg_recv failed] or [-R not supported here]
            /recv_rexec_state/ ? 1 : /not supported/ ? 0 : undef;
        };
        $s;
    };
    return $self->{cache_supported}->{$capability};
};

1;
