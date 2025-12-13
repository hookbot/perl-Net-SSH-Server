package Net::SSH::Server::Plugin;

use strict;
use warnings;
use Carp qw(croak);

=pod

=head1 NAME

Net::SSH::Server::Plugin - Methods related to utilizing plugins.

=head1 SYNOPSYS

  # Example Plugin:
  package Net::SSH::Server::Plugin::MyPlugin;
  use base qw(Net::SSH::Server::Plugin);

  sub load {
    my $plugin_obj = shift;
    $plugin_obj->create_method( munge => \&munge_it );
    my $sshd_obj = shift;
    $sshd_obj->register( trace_debug => \&capture_trace_event );
    return;
  }

  sub capture_trace_event {
    my $sshd_obj = shift;
    $sshd_obj->do_method( munge => { trace_args => \@_ } );
  }

  sub munge_it {
    my $plugin_obj = shift;
    my $sshd_obj = shift;
    my $args = shift;
    my $tag = $args->{trace_args}->[0];
    $tag =~ /validate_/ or return 0;
    open my $log, ">>/tmp/validation_log";
    print localtime().": [$$] munge: $tag\n";
    close $log;
    return 1;
  }

=head1 DESCRIPTION

Base class for plugins.

=head1 METHODS

These methods are intended for the Plugin subclasses:

=head2 new()

This initializer is not intended to be overriden.
Default new method will return an empty hashref
blessed into the subclass. No arguments are given.

=head2 load( $sshd_object )

The "load" method must be defined, but it runs multiple
times at various stages so it should execute quickly.
Do potentially slower operations within your custom
routine method "create_method" and call it "do_method"
later at the time it's needed to run the actual work.
Unlike the "new" method, the main Net::SSH::Server object
is provided, but avoid storing this object within the
self subclass $plugin_obj in order to keep the scope
segregated appropriately and to avoid possible memory
leaks via circular refs.
If you need the main engine object for something,
then use create_method to include that code,
which will always be given it as its first argument.
Use "register" to store and retrieve settings.

=head2 create_method( CUSTOM_NAME => CODEREF )

Define arbitrary custom routines for the engine to use.

  CODEREF->($self_plugin_object, $sshd_object, @args)

When this method is called, the main engine object is
first, followed by possible arguments as inputs.
This "create_method" is intended to be called during
the "load" routine to register custom functionalities,
but it is not required. Choose a unique name that
won't be defined by another plugin, otherwise it will
be ambiguous which plugin's CODEREF will win.

=head2 do_method( CUSTOM_NAME => @args )

Execute the custom Plugin method. This may be invoked
via $sshd_main_obj->do_method
or via $plugin_manager_obj->do_method
or via $plugin_subclass_obj->do_method
and will all execute the same.
The CODEREF will called as a method of the Plugin object.
Expect the first argument to be the Net::SSH::Server
main engine object.
The rest of the @args, if any, will come after that.
Returns the value whatever the method returns.

=head2 register( $feature => $value )

Convenience wrapper for main engine $sshd_obj->register
which just passes through the same arguments.
See Net::SSH::Server for more details.

=head2 manager()

The Net::SSH::Server::Plugin manager object initializer.
This is used internally to compile and load all Plugins.
If called from plugin subclass method, returns the
master plugin manager object. Do not overload it.

=cut

# new()
# Constructor
sub new {
    my $class = shift;
    my $self = shift || {};
    return bless $self, $class;
}

# manager( $sshd_obj )
# Plugin Manager initializer.
# Takes main Server $self object as input.
# Compile and load all Plugins.
# $plugin_subclass_obj->manager() always returns master plugin_manager object.
sub manager {
    my $manager = shift;
    if (@_ and __PACKAGE__ eq $manager) {
        # Initialize master plugin_manager
        $manager = $manager->new;
        (my $sshd = shift)->isa("Net::SSH::Server") or croak 'manager($sshd): Main object required';
        $manager->_sshd_obj($sshd);
        # Register myself in case someone needs me later.
        $manager->register( plugin_manager => $manager );
    }
    elsif (!@_ and my $prev = $manager->register( "plugin_manager" )->[0]) {
        # Too many cooks in the kitchen! Can't have multiple managers. Just return the previous one.
        return $prev;
    }
    else {
        croak "create_method(@_): Unexpected invoker [$manager]";
    }

    # Scan for any plugins in Net::SSH::Server::Plugin::*
    (my $prefix = __PACKAGE__) =~ s{::}{/}g;
    my $p = $manager->{plugins} = [];
    foreach my $inc (@INC) {
        local $_ = $inc;
        !ref && -d or next;
        $_ .= "/$prefix";
        -d or next;
        foreach my $path (glob "$_/*.pm") {
            -f $path or next;
            $path =~ m{^\Q$inc\E/((.+/(\w+))\.pm)$} or next;
            my $req = $1;
            my $plugin = $3;
            (my $mod = $2) =~ s{/+}{::}g;
            next if grep { $mod eq ref $_ } @$p; # Skip if already loaded.
            if (my $obj = eval { require $req; $mod->new; }) {
                push @$p, $obj;
            }
            else {
                warn "$mod: INITIALIZATION FAILED: $@\n";
            }
            # Never try again if failed to compile.
            $INC{$req} //= $path;
        }
    }
    # Run "load" method for each plugin in the order they were compiled
    foreach my $plugin_obj (@$p) {
        eval { $plugin_obj->load(_sshd_obj()); 1} or warn localtime().": ".ref($plugin_obj)."->load crashed: $@\n";
    }
    return $manager;
}

# create_method( $method_name => $CODEREF )
sub create_method {
    my $plugin_obj = shift;
    $plugin_obj && UNIVERSAL::isa($plugin_obj, __PACKAGE__) && __PACKAGE__ ne ref $plugin_obj or croak "create_method: Unexpected object [$plugin_obj]";
    my $method_name = shift;
    $method_name && $method_name =~ /^\w+$/ or croak 'create_method: Invalid method name';
    my $method_code = shift;
    'CODE' eq ref $method_code or croak "create_method( $method_name => sub {...} ): Invalid method registration";
    my $methods = $plugin_obj->manager->{method_name} ||= {};
    $methods->{$method_name} and croak "create_method: Method name $method_name already registered! [ $methods->{$method_name}->{plugin_obj} ]";
    $methods->{$method_name} = {
        plugin_obj  => $plugin_obj,
        method_code => $method_code,
    };
    return;
}

sub register {
    return shift()->_sshd_obj->register(@_);
}

# do_method( $method_name => @args )
sub do_method {
    my $methods = shift()->manager->{method_name} ||= {};
    my $method_name = shift or croak 'do_method: method name is required to execute';
    my $info = $methods->{$method_name} or croak "do_method($method_name => (@_)): undefined method"; # XXX: Should we avoid crashing if method not defined
    my $plugin_obj = $info->{plugin_obj};
    my $code = $info->{method_code};
    return $code->($plugin_obj,$plugin_obj->_sshd_obj,@_);
}

# Singleton to avoid each plugin object having to store
# its own copy and reduce circular refs and to maintain
# segregated scope and encourage use of do_method.
my $singleton_sshd_obj = undef;

# _sshd_obj: Setter/Getter
# For internal use. Don't use directly.
# It's at the very end to avoid cheating.
sub _sshd_obj {
    shift; # Ignore plugin object or class
    $singleton_sshd_obj ||= shift if @_;
    return $singleton_sshd_obj || croak '_sshd_obj: Sequence malfunction!';;
}

1;
