package Net::SSH::Server;

use strict;
use warnings;
our $VERSION = '0.021';

use FindBin qw($Script);
use Fcntl qw(O_CREAT O_EXCL O_RDONLY O_RDWR O_WRONLY);

# Method: new
# Purpose: Initializer
sub new {
    my $class = shift;
    my $self = shift || {};
    bless $self, $class;
    $self->{run} = [ $0, @ARGV ];
    $self->init;
    return bless $self, $class;
}

# Method: init
# Purpose: Run when a new instance is created
# Default is to do nothing
sub init {}

sub run {
    my $self = shift || __PACKAGE__;
    # Make sure $self is a real object instead of just a class
    ref $self or $self = $self->new;
    if ($< and $ENV{SHELL}) {
        exit $self->run_shell;
    }
    # Detect pam_exec case
    if (1 < @{ $self->{run} } and $self->{run}->[1] =~ /^pam_exec_step=(.+)/) {
        eval { $self->generate_pam_config } if !-f $self->pam_file;
        $ENV{PAM_ID} = $self->{pam_id} = getppid();
        $self->{pam_env_needed} = !$ENV{SESSION_FILE};
        exit $self->run_pam_exec;
    }
    # Implement missing "-D" case, by Detaching and launching WITH "-D":
    if (!grep { $_ eq "-D" } @{ $self->{run} }) {
        $self->cmdline("-D");
        exit if fork;
    }
    # Now we know it's the perfect non-detach mode to allow easy monitoring
    $ENV{NET_SSH_EXEC_PID} = $$;
    $ENV{PAM_ID} = $self->{pam_id} = $ENV{NET_SSH_SERVICE} ? $ENV{NET_SSH_EXEC_PID} : "master-".($ENV{NET_SSH_SERVICE}=$self->pam_service);
    exit $self->run_sshd;
}

sub run_shell {
    my $self = shift;
    my @pw = getpwuid $<;
    print "Ran as user: [@pw]\n";
    print "Spawn shell: [@{ $self->{run} }]\n";
    print "ENV: ".(join " ", map { "$_=$ENV{$_}" } sort keys %ENV)."\n";
    return 0;
}

sub cmdline {
    my $self = shift;
    splice @{ $self->{run} }, 1, 0, @_ if @_;
    return @{ $self->{run} }[1..$#{ $self->{run} }] if wantarray;
    return;
}

sub pam_args {
    my $self = shift;
    return $self->{pam_args} ||= do {
        my $args = {};
        foreach my $arg ($self->cmdline) {
            $args->{$1} = $2 if $arg =~ /^(\w+)=(.*)/;
        }
        $args;
    };
}

sub session_file {
    my $self = shift;
    my $id = $self->{pam_id} ||= $ENV{PAM_ID};
    my $service = $self->pam_service;
    return $self->{session_file} ||= "/var/run/sshd/session-$service-$id.env";
}

sub pam_getenv {
    my $self = shift;
    my $name = shift // "";
    if (sysopen my $fh, $self->session_file, O_RDONLY, 0600) {
        my $contents = join "", <$fh>;
        close $fh;
        while ($contents =~ s/^(\w+)(=?)(.*)\n//) {
            my $n = $1;
            if (!$2) {
                delete $ENV{$n};
                next;
            }
            my $v = $3;
            $v =~ s/\\n/\n/g;
            $ENV{$n} = $v;
        }
    }
    return $ENV{$name};
}

sub pam_putenv {
    my $self = shift;
    my $name = shift;
    my $value = shift;
    my $old_value = $self->pam_getenv($name);
    return if !defined($value) && !defined($old_value) or defined($value) && defined($old_value) && $value eq $old_value;
    if (defined $value) {
        $ENV{$name} = $value;
    }
    else {
        delete $ENV{$name};
    }
    $self->{pam_env_needed} = 1;
    my $file = $self->session_file;
    my $prev = {};
    sysopen my $fh, $file, O_CREAT | O_RDWR, 0600 or die "$file: open failure! $!\n";
    my $contents = join "", <$fh>;
    $value =~ s/\n/\\n/g if defined $value;
    while ($contents =~ s/^(\w+)(=?)(.*)\n//) {
        $prev->{$1} = $2 ? $3 : undef;
    }
    $prev->{$name} = $value;
    $contents = "";
    foreach my $n (sort keys %$prev) {
        $contents .= $n . (defined($prev->{$n}) ? "=$prev->{$n}" : "") . "\n";
    }
    seek $fh, 0, 0; # SEEK_SET
    print $fh $contents;
    truncate($fh, tell $fh);
    close $fh;
    return $self;
}

sub run_pam_exec {
    my $self = shift;
    my $type = $ENV{PAM_TYPE} or die "pam_exec: type failure\n";
    my $step = $self->pam_args->{pam_exec_step} or die "pam_exec: step failure\n";
    $step =~ s/-/_/g;
    my $method = "$type\_$step";
    my $code = $self->can($method) || "";
    $self->trace("run_pam_exec:[method=$method][code=$code]");
    $code ||= sub {2}; # PAM_SYMBOL_ERR  /* Symbol not found */
    $self->loadstash;
    $self->trace("run_pam_exec:[loadstash=".($self->session_file)."]");
    if (my $file = $ENV{BANNER_FILE}) {
        unlink $file;
        $self->pam_putenv( BANNER_FILE => undef );
    }
    return [$code->($self), $self->trace("run_pam_exec:savestash"), $self->savestash]->[0];
}

# Munge commandline arguments based on settings
sub init_commandline_args {
    my $self = shift;
    $self->trace("init_commandline_args:TopOverRide=[".($ENV{NET_SSH_OVERRIDE} // "(undef)")."]");
    if (!$ENV{NET_SSH_OVERRIDE}) {
        my $dir = $self->stash->{override_config_directory};
        $dir = undef if $dir and !-d $dir;
        my $file = $self->stash->{override_config_file};
        $file = undef if $file and !-e $file;
        if ($dir) {
            $file ||= "/etc/ssh/sshd_config";
            $ENV{NET_SSH_OVERRIDE} = "/var/run/sshd/".$self->pam_service().".conf";
            open my $cnf, ">", $ENV{NET_SSH_OVERRIDE};
            print $cnf "# DO NOT EDIT MANUALLY!\n";
            print $cnf "# Auto-generated by $0\n";
            print $cnf "# Override settings using any *.conf file under $dir/\n";
            print $cnf "Include $dir/*.conf\n";
            print $cnf "Include $file\n" if $file;
            close $cnf;
        }
        elsif ($file) {
            $ENV{NET_SSH_OVERRIDE} = $file;
        }
        else {
            $ENV{NET_SSH_OVERRIDE} = "/dev/null";
        }
        $self->cmdline(-f => $ENV{NET_SSH_OVERRIDE}) if $dir || $file;
    }
    return;
}

# Run immediately after SSH client connects
sub init_connection {
    my $self = shift;
    # Extract connection info early in case it's needed for an early hook.
    if (!$ENV{SSH_CONNECTION}) {
        require Socket;
        my $sockaddr = getpeername STDIN;
        my ($family, $port) = unpack vn => $sockaddr;
        $ENV{SSH_CONNECTION}  = $family == Socket::AF_INET() ? Socket::inet_ntoa([Socket::sockaddr_in($sockaddr)]->[1]) : Socket::inet_ntop($family, [Socket::sockaddr_in6($sockaddr)]->[1]);
        $ENV{SSH_CONNECTION} .= " $port ";
        ($family, $port) = unpack vn => ($sockaddr = getsockname STDIN);
        $ENV{SSH_CONNECTION} .= $family == Socket::AF_INET() ? Socket::inet_ntoa([Socket::sockaddr_in($sockaddr)]->[1]) : Socket::inet_ntop($family, [Socket::sockaddr_in6($sockaddr)]->[1]);
        $ENV{SSH_CONNECTION} .= " $port";
    }
    my $failover_user = exists $self->stash->{failover_user} ? $self->stash->{failover_user} : do {
        # No explicit failover_user? Try auto-detecting with random bogus fake user:
        my @pw;
        my $test = "a";
        my $tries = 100;
        while ($tries-->0 and @pw = getpwnam ++$test) {}
        my $name = undef;
        if (!@pw) {
            # Found a bogus user $test, so run it through validate_user to see if it passes.
            my $uid = -1;
            my $pam_error = 0; # PAM_SUCCESS
            eval {
                #local $SIG{__DIE__} = sub { $pam_error = $_[0] };
                $uid = $self->validate_user;
            };
            $pam_error = $@ =~ /^(\d+)/ ? $1 : 0;
            $self->trace("init_connection:[test_user=$test][uid=$uid][pam_error=$pam_error]");
            ($name) = getpwuid $uid if defined $uid;
        }
        $name;
    };
    if ($failover_user) {
        $ENV{NET_SSH_FALLBACK_USER} = $failover_user;
        $ENV{NET_SSH_FALLBACK_SHELL} = $self->{run}->[0];
        $self->preload_so("/var/lib/sshproxy/lib/netssh_getpwnam_override.so");
    }
    my $banner_code = $self->can("banner");
    if ($banner_code and my $banner_text = eval { $banner_code->($self) }) {
        my $banner_file = $self->banner_file;
        $self->pam_putenv( BANNER_FILE => $banner_file );
        if (open my $fh, ">", $banner_file) {
            print $fh $banner_text;
            close $fh;
            $self->cmdline("-o", "Banner $banner_file");
        }
    }
    $self->trace("init_connection:end");
    return $ENV{SSH_CONNECTION};
}

sub preload_so {
    my $self = shift;
    if (my $shared_object_file = shift) {
        $ENV{LD_PRELOAD} ||= "";
        if ($ENV{LD_PRELOAD} !~ /(^|:)\Q$shared_object_file\E($|:)/) {
            $ENV{LD_PRELOAD} = join ":", $shared_object_file, split /:+/, $ENV{LD_PRELOAD};
        }
    }
    return $ENV{LD_PRELOAD};
}

sub run_sshd {
    my $self = shift;
    $self->trace("run_sshd:top");
    $self->init_commandline_args;
    my $target = $self->target;
    die "$target: Not executable\n" if !-x $target;
    die "$0: Invalid invocation\n" if $target eq $self->{run}->[0];
    if (my $sockaddr = getpeername STDIN) {
        # Probably -R mode or xinetd-style connection.
        $ENV{PAM_ID} = $self->{pam_id} = $$;
        $self->init_connection;
    }
    $self->trace("run_sshd:EndOverRide=[".($ENV{NET_SSH_OVERRIDE} // "(undef)")."]");
    exec { $target } @{ $self->{run} } or die "$0: spawn failure: $!\n";
}

sub banner_file {
    my $self = shift;
    my $id = $self->{pam_id} ||= $ENV{PAM_ID};
    my $service = $self->pam_service;
    return "/var/run/sshd/banner-$service-$id.txt";
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

sub auth_sniff {
    my $self = shift;
    $self->trace("auth_sniff");
    return 0; # PAM_SUCCESS
}

sub auth_check {
    my $self = shift;
    $self->trace("auth_check:top");
    my $pw = <STDIN> // "";
    $self->pam_putenv( PAM_PW => $pw );
    push @{ $self->stash->{auth_pw} ||= [] }, $pw;
    $self->trace("auth_check:end");
    return $self->validate_pw;
}

sub validate_nonempty {
    my $self = shift;
    my $pw = $ENV{PAM_PW} // "";
    # Return SUCCESS if any random non-empty password is provided
    return length $pw ?
        0 : # PAM_SUCCESS   /* Successful function return */
        7 ; # PAM_AUTH_ERR  /* Authentication failure */
}

# When "PasswordAuthentication yes" is enabled, then check passwd provided.
# Return PAM_* error code or 0 [PAM_SUCCESS] if no problem:
sub validate_pw {
    my $self = shift;
    my $user = $ENV{PAM_USER}  or return 8; # PAM_CRED_INSUFFICIENT  /* Can not access authentication data */
    my $pass = $ENV{PAM_PW};
    length ($pass // "")       or return 7; # PAM_AUTH_ERR  /* Authentication failure */
    my @pwent = getpwnam $user or return 7; # PAM_AUTH_ERR  /* Authentication failure */
    $pwent[1] && $pwent[1] =~ /^\$/;
    # Compare UNIX password to ensure it matches
    if (crypt($pass, $pwent[1]) eq $pwent[1]) {
        return 0;  # PAM_SUCCESS   /* Successful function return */
    }
    else {
        return 6;  # PAM_PERM_DENIED  /* Permission denied */
    }
}

sub account_sniff {
    my $self = shift;
    $self->trace("account_sniff");
    return 0; # PAM_SUCCESS
}

sub account_acquire_session_lock {
    my $self = shift;
    $self->trace("auth_acquire_session_lock");
    my $lock_file = $self->pam_args->{lockfile} or !warn "auth_acquire_session_lock lockfile missing\n" or return 14; # PAM_SESSION_ERR
    my $env_file  = $self->pam_args->{envfile}  or !warn "auth_acquire_session_lock envfile missing\n"  or return 14; # PAM_SESSION_ERR
    my $expire = 10 + time;
    my $save_env = "";
    if (open my $fh, "<", $self->session_file) {
        $save_env = join "", <$fh>;
        close $fh;
    }
    my $lock_goal = "$self->{pam_id}\n";
    if (open my $fh, "<", $lock_file) {
        my $old_pam_id = <$fh> || "";
        close $fh;
        if ($old_pam_id eq $lock_goal) {
            $lock_goal = "";
        }
        elsif ($old_pam_id =~ /^(\d+)/ and !kill 0 => $1) {
            # Get rid of crusty stale mismatched lock file
            unlink $lock_file;
        }
    }
    while ($lock_goal) {
        if (sysopen my $fh, $lock_file, O_WRONLY | O_CREAT | O_EXCL, 0600) {
            print $fh $lock_goal;
            close $fh;
            last;
        }
        select undef,undef,undef, 0.1;
        time > $expire and warn "$lock_file: FAILURE!\n" and return 22; # PAM_AUTHTOK_LOCK_BUSY
    }
    if (open my $fh, ">", $env_file) {
        print $fh $save_env;
        close $fh;
    }
    $self->savestash;
    return 0; # PAM_SUCCESS
}

sub account_check {
    my $self = shift;
    $self->trace("account_check:top");
    my $uid = undef;
    my $pam_error = 0; # PAM_SUCCESS
    eval {
        #local $SIG{__DIE__} = sub { $pam_error = $_[0] };
        $uid = $self->validate_user($ENV{PAM_USER});
    };
    $pam_error = $@ =~ /^(\d+)/ ? $1 : 0;
    $pam_error ||= 10 if !defined $uid; # PAM_USER_UNKNOWN       /* User not known to the underlying authentication module */
    $self->trace("account_check:[uid=".($uid // "(undef)")."][pam_error=$pam_error]");
    return $pam_error;
}

# Input: $user
# Return: $uid if valid
# DIE with PAM_* error code if $user is not valid user.
sub validate_user {
    my $self = shift;
    my $user = shift or die 8;  # PAM_CRED_INSUFFICIENT  /* Can not access authentication data */
    my @ent = getpwnam $user;
    $self->trace("validate_user:USER=[$user]:FOUND[@ent]");
    defined(my $uid = @ent > 3 && $ent[2]) or die 10; # PAM_USER_UNKNOWN       /* User not known to the underlying authentication module */
    return $uid;
}

# account pam_env burner runs after "account" phase and before "session" phase.

sub open_session_release_session_lock {
    my $self = shift;
    $self->trace("session_release_session_lock[pam_env_needed:$self->{pam_env_needed}]");
    return 0 if $self->{pam_env_needed};
    my $lock_file = $self->pam_args->{lockfile} or !warn "account_release_session_lock lockfile missing\n" or return 14; # PAM_SESSION_ERR
    my $env_file  = $self->pam_args->{envfile}  or !warn "account_release_session_lock envfile missing\n"  or return 14; # PAM_SESSION_ERR
    my $session_file = $self->session_file      or !warn "account_release_session_lock session missing\n"  or return 14; # PAM_SESSION_ERR
    unlink $env_file;
    unlink $lock_file;
    unlink $session_file;
    return 0; # PAM_SUCCESS
}

sub open_session_check {
    my $self = shift;
    $self->trace("session_check:top");
    return $self->stash->{pam_error} || 0;
}

sub open_session_sniff {
    my $self = shift;
    $self->trace("open_session_sniff");
    return 0; # PAM_SUCCESS
}

sub open_session_printout {
    my $self = shift;
    if (my $output = $self->stash->{session_output}) {
        print STDERR $output;
    }
    return 0; # PAM_SUCCESS
}

sub json {
    my $self = shift;
    return $self->{json} ||= eval { require JSON; JSON->new->utf8->allow_unknown->allow_nonref->convert_blessed->canonical } || die "Could not load JSON: $@";
}

sub savestash {
    my $self = shift;
    $self->trace("savestash:top");
    if ($self->{pam_env_needed}) {
        $self->pam_putenv( STASH_JSON => $self->json->encode($self->stash) );
        $self->pam_putenv( SESSION_FILE => $self->session_file );
    }
    $self->trace("savestash:end");
    return $self->stash;
}

sub loadstash {
    my $self = shift;
    my $json = $self->pam_getenv( "STASH_JSON" ) or return;
    $json = $self->json->decode($json);
    my $monkey_stash = 0;
    foreach my $k (keys %$json) {
        my $v = $self->stash->{$k};
        if ($v and "ARRAY" eq ref $v) {
            push @$v, $json->{$k};
            $monkey_stash++;
        }
        else {
            $self->stash->{$k} = $json->{$k};
        }
    }
    $self->savestash if $monkey_stash;
    return $self->stash;
}

sub trace {
    my $self = shift;
    my $tag = shift || "unknown_trace";
    # Nothing to do
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
