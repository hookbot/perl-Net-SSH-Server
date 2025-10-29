package Net::SSH::Server;

use strict;
use warnings;
our $VERSION = '0.021';

use FindBin qw($Script);

use Data::Dumper;
open my $fh, ">>", "/tmp/sshd-server.log"; chmod 0666, "/tmp/sshd-server.log";
#open $fh, ">", "/dev/null";

sub new {
    my $class = shift;
    my $self = shift || {};
    bless $self, $class;
    $self->init;
    return bless $self, $class;
}

# Method: init
# Purpose: Run when a new instance is created
# Default is to do nothing
sub init {}

sub run {
    my $self = shift || __PACKAGE__;
    ref $self or $self = $self->new;
    $self->stash->{run} = [ $0, @ARGV ];
print $fh localtime().": DEBUG: run 0: ".Dumper { self => $self, pkg => __PACKAGE__ };
    if (1 < @{ $self->stash->{run} } and $self->stash->{run}->[1] =~ /^PAM_EXEC_STEP=(.+)/) {
        splice @{ $self->stash->{run} }, 0, 2, $1;
        $self->generate_pam_config if !-f $self->pam_file;
print $fh localtime().": DEBUG: run A: ".Dumper { self => $self, pkg => __PACKAGE__ };
        exit $self->run_pam_exec;
    }
    else {
print $fh localtime().": DEBUG: run B: ".Dumper { self => $self, pkg => __PACKAGE__ };
        exit $self->run_sshd;
    }
}

sub run_pam_exec {
    my $self = shift;
print $fh localtime().": DEBUG: run_pam_exec: ".Dumper { self => $self, pkg => __PACKAGE__ };
    exit 0;
}

sub run_sshd {
    my $self = shift;
print $fh localtime().": DEBUG: run_sshd: ".Dumper { self => $self, pkg => __PACKAGE__ };
    my $target = $self->target;
    die "$target: Not executable\n" if !-x $target;
    #die "$0: Invalid invocation\n" if $target eq $self->stash->{run}->[0];
    exec { $target } @{ $self->stash->{run} } or die "$0: spawn failure: $!\n";
}

sub target {
    return shift()->stash->{target} ||= eval { require File::Which; File::Which::which("sshd") } || "/usr/sbin/sshd";
}

sub stash {
    my $self = shift;
    return $self->{stash} ||= {};
}

sub pam_service {
    return $ENV{PAM_SERVICE} ||= $Script;
}

sub pam_file {
    "/etc/pam.d/".pam_service();
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::SSH::Server - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Net::SSH::Server;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Net::SSH::Server, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Rob Brown, E<lt>bbb@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2025 by Rob Brown

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.34.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
