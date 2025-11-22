package Net::SSH::Server;

use strict;
use warnings;
our $VERSION = '0.021';

use FindBin qw($Script);
use Fcntl qw(O_CREAT O_EXCL O_RDONLY O_RDWR O_WRONLY);

=pod

=head1 NAME

Net::SSH::Server - SSH Server with support for Perl hooks and features

=head1 SYNOPSYS

  #!/usr/bin/env perl
  # Example daemon launcher script
  # Usage: /usr/sbin/my-custom-ssh-server
  use strict;
  use warnings;
  use Net::SSH::Server;
  Net::SSH::Server->new
    ->register( override_config_directory => "/etc/ssh/my-custom-ssh-server.d" )
    ->run;

=head1 DESCRIPTION

Although this module allows to register some Perl hooks for
certain features, it is not a replacement for sshd.
The real sshd is just run using the appropriate options in order
to apply the features registered and actually handles accepting
connections and performing the session encryption, etc.

=head1 REGISTER

Register a feature with a given setting.

  register( $feature => $value )

=head2 override_config_file

Use specified config file.

Example:

  $self->register( override_config_file => "/etc/ssh/sshd-custom_config" );

Default "/etc/ssh/sshd_config"

=head2 override_config_directory

All *.conf files found within provided directory will
override any settings found in the config file.

Example:

  $self->register( override_config_directory => "/etc/ssh/sshd-custom_config.d/." );

No default (unless Include'd within the config_file).

=head2 failover_user

Specify a username to fallback to if the username attempted
to login with is not a real user.

  $self->register( failover_user => "git" );

Default is to FAIL for any non-existing user.

=head1 SEE ALSO

  sshd(8)
  Net::SSH

=head1 AUTHOR

  Rob Brown <bbb@cpan.org>

  Copyright 2025

  Perl Artistic License

=cut

# Copy a shallow copy of %ENV
our %ORIG_ENV = %ENV;

our $valid_ssh_options = {
    # All possible authorized_keys options, according to "man sshd":
    command => "string",
    environment => "string",
    "expiry-time" => "string",
    from => "string",
    permitlisten => "string",
    permitopen => "string",
    principals => "string",
    tunnel => "string",

    # Empty value means that option is a flag (no arguments).
    "cert-authority" => "",
    "verify-required" => "",
    restrict => "",

    # All "no-FLAG" options mean "FLAG" is also possible:
    "no-touch-required" => "",
    "no-user-rc" => "",
    "no-touch-required" => "",
    "no-port-forwarding" => "",
    "no-agent-forwarding" => "",
    "no-x11-forwarding" => "",
    "no-pty" => "",

    # Fake option to provide pubkey comment
    comment => "special",
};

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

sub register {
    my $self = shift;
    my $feature = shift or die "register: feature title required!\n";;
    if (@_) {
        unshift @{ $self->{r}->{$feature} ||= [] }, @_;
        return $self;
    }
    return $self->{r}->{$feature} || [];
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
    # Detect AuthorizedKeysCommand
    if (1 < @{ $self->{run} } and $self->{run}->[1] =~ /^action=verifypubkey$/) {
        $ENV{PAM_ID} = $self->{pam_id} = getppid();
        $self->{pam_env_needed} = !$ENV{SESSION_FILE};
        exit $self->run_authorizedkeyscommand;
    }
    # Detect pam_exec case
    if (1 < @{ $self->{run} } and $self->{run}->[1] =~ /^pam_exec_step=(.+)/) {
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
    eval { $self->generate_pam_config } if !-f $self->pam_file;
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

# validate_pubkey
# Input: {
#   user    => $user,
#   homedir => $homedir,
#   file    => $authorized_keys_file_name, # (optional)
#   keytype => $keytype,
#   pubkey  => $pubkey,
#   fingerprint => $fingerprint,
# };
# Success Output: {
#   command => $command,
#   environment => ["NAM1=VAL1","NAM2=VAL2"],
#   "no-pty" => [],
# };
# Or die with PAM_* error on failure.
sub validate_pubkey {
    my $self = shift;
    my $args = shift;
    my $file = $args->{file} ||= "$args->{homedir}/.ssh/authorized_keys";
    my $key = "$args->{keytype} $args->{pubkey}";
    my $auth_history = $self->stash->{auth} ||= [];
    push @$auth_history, { pubkey => $key } if !grep { ($_->{pubkey} // "") eq $key} @$auth_history;
    $self->trace("validate_pubkey:[file=$file]SCANFOR[$key]");
    if (open my $fh, "<", $file) {
        while (<$fh>) {
            next if /^\s*\#/;
            if (/^(.*?)\b\Q$key\E(\s.*)/) {
                my $prefix = $1;
                my $comment = $2;
                $comment =~ s/^\s+//;
                my $options = {};
                $options->{comment} = $comment if length $comment;
                while ($prefix =~ s/^([^=]+)=?(?:|"([^\"]*)"|([^\"\ ,]*))[\ ,]//) {
                    my $opt = $1;
                    my $val = defined $2 ? $2 : defined $3 ? $3 : "";
                    next unless exists $valid_ssh_options->{lc $opt} or $valid_ssh_options->{lc "no-$opt"};
                    $options->{$opt} ||= [];
                    push @{ $options->{$opt} }, $val if $valid_ssh_options->{lc $opt} and length $val;
                }
                return $options;
            }
        }
        close $fh;
    }
    die 6; # PAM_PERM_DENIED  /* Permission denied */
}

sub run_authorizedkeyscommand {
    my $self = shift;
    my (undef, $user, $homedir, $keytype, $pubkey, $fingerprint) = $self->cmdline;
    $self->loadstash;
    my $args = {
        user    => $user,
        homedir => $homedir,
        keytype => $keytype,
        pubkey  => $pubkey,
        fingerprint => $fingerprint,
    };
    my $options = undef;
    if (eval { $options = $self->validate_pubkey($args); 1; }) {
        $options ||= [];
        $options = [] if !ref $options;
        if ("HASH" eq ref $options) {
            my $options_list = [];
            foreach my $o (sort keys %$options) {
                my $opt = $o;
                my $val = $options->{$o};
                if (defined $val and !ref $val and length $val) {
                    $val = [ $val ];
                }
                $val = undef if "ARRAY" ne ref $val or !@$val;
                if ($val and @$val) {
                    foreach my $v (@$val) {
                        my $escaped = $v;
                        $escaped =~ s/\"/\\"/g;
                        push @$options_list, qq{$opt="$escaped"};
                    }
                }
                else {
                    push @$options_list, $opt;
                }
            }
            $options = $options_list;
        }
    }
    $self->savestash;
    return 0 if !$options or "ARRAY" ne ref $options;
    my $valid_options = [];
    my $comment = undef;
    foreach my $opt (@$options) {
        if ($opt =~ /^comment=(.*)/) {
            $comment = $1;
            $comment = $1 if $comment =~ /"(.*)"/;
        }
        elsif ($opt =~ /^([\w\-]+)/) {
            push @$valid_options, $opt if exists $valid_ssh_options->{lc $1} or exists $valid_ssh_options->{lc "no-$1"};
        }
    }
    my $line = "$keytype $pubkey";
    $line .= $comment ? " $comment\n" : "\n";
    if (@$valid_options) {
        $line = join(",", @$valid_options)." ".$line;
    }
    print $line;
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
    return $ENV{SESSION_FILE} ||= "/var/run/sshd/session-$service-$id.env";
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
    if (my $file = delete $ENV{BANNER_FILE}) {
        unlink $file;
    }
    return [$code->($self), $self->trace("run_pam_exec:savestash"), $self->savestash]->[0];
}

# Munge commandline arguments based on settings
sub init_commandline_args {
    my $self = shift;
    $self->trace("init_commandline_args:TopOverRide=[".($ENV{NET_SSH_OVERRIDE} // "(undef)")."]");
    if (!$ENV{NET_SSH_OVERRIDE}) {
        my $dir = $self->register("override_config_directory");
        $dir = [ grep { -d } @$dir ];
        my $file = $self->register("override_config_file");
        $file = [ grep { -e and -f _ } @$file ];
        if (@$dir or @$file > 1) {
            $file = [ "/etc/ssh/sshd_config" ] if !@$file;
            $ENV{NET_SSH_OVERRIDE} = "/var/run/sshd/".$self->pam_service().".conf";
            open my $cnf, ">", $ENV{NET_SSH_OVERRIDE};
            print $cnf "# DO NOT EDIT MANUALLY!\n";
            print $cnf "# Auto-generated by $0\n";
            foreach my $d (@$dir) {
                print $cnf "# Override settings using any *.conf file under $d/\n";
                print $cnf "Include $d/*.conf\n";
            }
            foreach my $f (@$file) {
                print $cnf "Include $f\n";
            }
            close $cnf;
        }
        elsif (@$file) {
            $ENV{NET_SSH_OVERRIDE} = $file->[0];
        }
        else {
            $ENV{NET_SSH_OVERRIDE} = "/dev/null";
        }
        $self->cmdline(-f => $ENV{NET_SSH_OVERRIDE}) if @$dir || @$file;
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
    my $failover_user = $self->register( "failover_user" )->[0] || do {
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
                $uid = $self->validate_user($test);
            };
            $pam_error = $@ =~ /^(\d+)/ ? $1 : 0;
            $self->trace("init_connection:[test_user=$test][uid=$uid][pam_error=$pam_error]");
            ($name) = getpwuid $uid if defined $uid and $uid >= 0;
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
        if (open my $fh, ">", $banner_file) {
            print $fh $banner_text;
            close $fh;
            $ENV{BANNER_FILE} = $banner_file;
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
        $self->loadstash;
        $self->init_connection;
        $self->savestash;
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
    $ENV{PAM_PW} = $pw; # Store most recent password into PAM_PW
    push @{ $self->stash->{auth} ||= [] }, { password => $pw };
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
    $self->savestash;
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
    unlink $env_file;
    unlink $lock_file;
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

sub close_session_cleanup {
    my $self = shift;
    $self->trace("close_session_cleanup");
    unlink $self->session_file if -e $self->session_file;
    unlink $self->banner_file  if -e $self->banner_file;
    return 0; # PAM_SUCCESS
}

sub close_session_sniff {
    my $self = shift;
    $self->trace("close_session_sniff");
    return 0; # PAM_SUCCESS
}

sub json {
    my $self = shift;
    return $self->{json} ||= eval { require JSON; JSON->new->utf8->allow_unknown->allow_nonref->convert_blessed->canonical } || die "Could not load JSON: $@";
}

sub loadstash {
    my $self = shift;
    my $json = $ENV{STASH_JSON} = $self->loadenv( "STASH_JSON" ) or return $self->stash;
    $json = $self->json->decode($json);
    foreach my $k (keys %$json) {
        my $v = $self->stash->{$k};
        if ($v and "ARRAY" eq ref $v) {
            push @$v, $json->{$k};
        }
        else {
            $self->stash->{$k} = $json->{$k};
        }
    }
    return $self->stash;
}

sub savestash {
    my $self = shift;
    $self->trace("savestash:top");
    $ENV{STASH_JSON} = $self->json->encode($self->stash);
    $self->saveenv;
    $self->trace("savestash:end");
    return $self->stash;
}

# Load previous ENV settings
sub loadenv {
    my $self = shift;
    my $name = shift || "";
    my $file = $ENV{SESSION_FILE} ||= $self->session_file;
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

# Store any changes to %ENV to be able to restore {stash} or other ENV settings later
sub saveenv {
    my $self = shift;
    my $changes = {};
    $ENV{SESSION_FILE} = $self->session_file;
    foreach my $old (keys %ORIG_ENV) {
        if (defined $ORIG_ENV{$old}) {
            if (defined $ENV{$old}) {
                $changes->{$old} = $ENV{$old} if $ORIG_ENV{$old} ne $ENV{$old};
            }
            else {
                $changes->{$old} = undef;
            }
        }
        else {
            $changes->{$old} = $ENV{$old};
        }
    }
    foreach my $new (keys %ENV) {
        next if exists $ORIG_ENV{$new};
        $changes->{$new} = $ENV{$new};
    }
    my $file = $self->session_file;
    if (!keys %$changes) {
        unlink $file;
        return;
    }
    sysopen my $fh, $file, O_CREAT | O_RDWR, 0600 or die "$file: open failure! $!\n";
    my $contents = "";
    foreach my $n (sort keys %$changes) {
        my $val = $changes->{$n};
        $val =~ s/\n/\\n/g if defined $val;
        $contents .= $n . (defined($val) ? "=$val" : "") . "\n";
    }
    seek $fh, 0, 0; # SEEK_SET
    print $fh $contents;
    truncate($fh, tell $fh);
    close $fh;
    return;
}

sub trace {
    my $self = shift;
    my $tag = shift || "unknown_trace";
    # Nothing to do
}

1;
