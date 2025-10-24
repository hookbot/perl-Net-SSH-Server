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
        $self->get_module;
        $self->generate_pam_config if !-f $self->pam_file;
print $fh localtime().": DEBUG: run A: ".Dumper { self => $self, pkg => __PACKAGE__ };
        exit $self->run_pam_exec;
    }
    else {
        $self->set_module;
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
    my $class = ref $self;
    #$self->envtostash;
print $fh localtime().": DEBUG: 1 self: ".Dumper { self => $self };
    if ($class eq __PACKAGE__) {
        $self->get_module;
print $fh localtime().": DEBUG: 2 self: ".Dumper { self => $self };
    }
    $self->stash->{run} = [ $0, @ARGV ];
print $fh localtime().": DEBUG: 3 self: ".Dumper { self => $self };
    (my $file = $class) =~ s/::/\//g;
    $file .= ".pm";
    if (!$self->stash->{mod} and my $path = $INC{$file}) {
        $self->stash->{mod}  = $class;
        $self->stash->{file} = $path;
    }
print $fh localtime().": DEBUG: 4 self: ".Dumper { self => $self };
close $fh;

    my $target = $self->target;
    die "$target: Not executable\n" if !-x $target;
    die "$0: Invalid invocation\n" if $target eq $self->stash->{run}->[0];
    $self->generate_pam_config if !-f $self->pam_file;
    #$self->stashtoenv;
    $self->set_module;
    #$self->pre_spawn;
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

sub module_file {
    return "/var/run/sshd/".pam_service().".mod";
}

sub get_module {
    my $self = shift;
    open my $fh, "<", module_file() or return (ref($self) ? ref($self) : ($self || __PACKAGE__));
    chomp(my $class = <$fh> || __PACKAGE__);
    return $class if $class eq ref $self;
    if (!UNIVERAL::can($class, "new")) {
        chomp (my $inc = <$fh>);
        #chomp (my $path = <$fh> || __FILE__);
        #require $path;
        (my $file = $class) =~ s/::/\//g;
        $file .= ".pm";
        #$INC{$file} = $path;
        eval { require $file };
    }
    if (UNIVERAL::can($class, "new")) {
        bless $self, $class;
    }
    return $class;
}

sub set_module {
    my $self = shift;
    my $class = shift || ref($self) || $self || __PACKAGE__;
    if ($class ne $self->get_module()) {
        (my $file = $class) =~ s/::/\//g;
        $file .= ".pm";
        if (my $path = $INC{$file} ||
            eval { require $file; $INC{$file} }) {
            if ($path =~ m{^(/.+)/\Q$file\E$}) {
                my $inc = $1;
                open my $fh, ">", module_file();
                print $fh "$class\n";
                print $fh "$inc\n";
                close $fh;
            }
        }
    }
    return $class;
}

sub stashtoenv {
    my $self = shift;
    eval {
        require JSON;
        $ENV{SSHD_TRANSPORT} = JSON->new->canonical->encode($self->stash);
    } or eval {
        require Data::Dumper;
        $ENV{SSHD_TRANSPORT} = Data::Dumper::Dumper($self->stash);
    };
    return $self->stash;
}

sub envtostash {
    my $self = shift;
print $fh localtime().": DEBUG: 0-A-envtostash self: ".Dumper { self => $self };
    if (my $t = $ENV{SSHD_TRANSPORT}) {
print $fh localtime().": DEBUG: 0-B-envtostash env: ".Dumper { st => $t };
        if (my $new_stash = $t && $t =~ /^\{/
            ? eval { require JSON; JSON->new->decode($t); }
            : eval $t) {
print $fh localtime().": DEBUG: 0-C-envtostash new_stash: ".Dumper $new_stash;
            foreach my $k (keys %$new_stash) {
                $self->stash->{$k} //= $new_stash->{$k};
            }
        }
    }
print $fh localtime().": DEBUG: 0-D-envtostash self: ".Dumper { self => $self };
    return $self->stash;
}

sub pam_file {
    my $self = shift;
    my $prog = ($self->stash->{run} && $self->stash->{run}->[0]) || $0;
    my $script = $prog =~ m{([\w\-]+)$} ? $1 : "sshd";
    return "/etc/pam.d/$script";
}

# Hook: pre_spawn
# Run before spawning the sshd binary
sub pre_spawn {}

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
