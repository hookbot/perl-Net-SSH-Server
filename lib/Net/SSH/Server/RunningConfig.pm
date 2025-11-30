package Net::SSH::Server::RunningConfig;

use strict;
use warnings;

# Magic File Descriptor used for recv_rexec_state
# Hard Coded into the sshd binary?
our $recv_rexec_state = 5;

sub load {
    my $self = shift;
    require POSIX;  # dup
    require Socket; # MSG_PEEK
    require IO::Handle; # new_from_fd
    my $daddy_pid = $ENV{NET_SSH_EXEC_PID} or return; # ERROR: Missing or unknown daddy parent.
    my $cache_running_config = $self->base()."/running-config-$daddy_pid.payload";
    -s $cache_running_config and return $self->{running_config_file} = $cache_running_config; # SUCCESS: Already loaded. YEY!
    if (my $fd = POSIX::dup($recv_rexec_state)) {
        # Just for fun, peek at the live sshd configuration
        # slurped in by the big daddy parent sshd daemon:
        my $fh = IO::Handle->new_from_fd($fd, "r");
        my $buffer = '';
        recv $fh, $buffer, 4, Socket::MSG_PEEK();
        defined $buffer && length $buffer or return; # ERROR: Couldn't even read the size of the payload.
        my $bytes = unpack N => $buffer or return;   # ERROR: Zero is impossible. Need at least a file name.
        recv $fh, $buffer, ($bytes += 4), Socket::MSG_PEEK();
        $bytes == length $buffer or return; # ERROR: Couldn't see exactly the number of bytes expected in the socketpair buffer.
        open $fh, ">", $cache_running_config or return; # ERROR: Unable to create cache file: $!
        chmod 0600, $cache_running_config;
        print $fh $buffer;
        close $fh;
        -s $cache_running_config or return; # ERROR: Failed to dump all the goodness into the cache
        return $self->{running_config_file} = $cache_running_config; # SUCCESS!
    }
    return; # ERROR: dup() failure
}

1;
