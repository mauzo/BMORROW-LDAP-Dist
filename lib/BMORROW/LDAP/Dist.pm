package BMORROW::LDAP::Dist;

=head1 NAME

BMORROW::LDAP::Dist - Use syncrepl to distribute LDAP changes

=cut

use 5.012;
use Moo;

use BMORROW::LDAP::Entry;
use Net::LDAP;
use Net::LDAPx::Sync;

use Carp;
use Data::Dump      qw/pp/;
use Data::UUID;
use File::Slurp     qw/read_file write_file/;
use IO::KQueue;
use IO::Select;
use JSON::XS        qw/encode_json/;
use Module::Runtime qw/use_module/;
use POSIX;
use Try::Tiny;
use YAML::XS;

our $VERSION = "3";

with "MooX::Role::WeakClosure";

has _conf   => is => "ro";

has KQ      => is => "lazy";

sub _build_KQ { IO::KQueue->new }

has LDAP    => is => "lazy";

sub _build_LDAP {
    my ($self) = @_;
    my $L = Net::LDAP->new($self->conf("host"));
    $self->conf("debug") and $L->debug(12);
    my $tls = $self->conf("tls");
    $tls and $L->start_tls(ref $tls ? %$tls : ());
    my $bind = $self->conf("bind");
    $bind and $L->bind(ref $bind ? @$bind : ());
    $L;
}

has sync_state  => is => "lazy";

sub _build_sync_state {
    my ($self) = @_;
    my $cache = eval { scalar read_file $self->conf("sync") };
    $cache ? JSON::XS->new->decode($cache) : {};
}

has plugins     => is => "lazy";
has searches    => is => "ro", lazy => 1, default => sub { +{} };
has active      => is => "ro", lazy => 1, default => sub { +{} };
has changes     => is => "ro", lazy => 1, default => sub { +{} };

sub BUILDARGS {
    my ($class, @args) = @_;
    my $args = @args == 1 ? $args[0] : { @args };

    if (my $file = delete $$args{conf}) {
        $$args{_conf} = YAML::XS::LoadFile $file;
    }

    $args;
}

sub conf { $_[0]->_conf->{$_[1]} }

sub SIGINFO () { 29 } # grr

sub info {
    my ($fmt, @args) = @_;
    my $msg = @args ? sprintf $fmt, @args : $fmt;
    warn "$msg\n";
}

my $UUID = Data::UUID->new;

sub register_kevent {
    my ($self, $id, $filt, $cb) = @_;
    
    info "REGISTER KEVENT [$id] [$filt] [$cb]";
    $self->KQ->EV_SET($id, $filt, EV_ADD, 0, 0, $cb);
}

sub set_timeout {
    my ($self, $id, $after, $meth) = @_;

    info "SET TIMEOUT [$id] [$meth] [$after]";
    ref $meth or $meth = $self->weak_method($meth);

    try { $self->KQ->EV_SET($id, EVFILT_TIMER, EV_DELETE, 0, 0, 0) };
    $self->KQ->EV_SET($id, EVFILT_TIMER, EV_ADD|EV_ONESHOT, 
        0, $after, $meth);
}

sub invalidate {
    my ($self, $name) = @_;

    say "Got notification [$name]";
    my $chg = $self->changes->{$name}
        or croak "No change information for [$name]";

    if (my $wait = $$chg{wait}) {
        my $first = $$chg{first} //= time;

        $self->set_timeout(int $chg, $wait * 1000, sub {
            delete $$chg{first};
            $$chg{callback}->();
        }) unless $first < time - $$chg{maxwait};
    }
    else {
        $$chg{callback}->();
    }
}

sub add_search {
    my ($self, $name, %params) = @_;

    my $searches    = $self->searches;
    exists $$searches{$name}
        and croak "[$self] already has a search called [$name]";

    $self->changes->{$name} = {
        map +($_, delete $params{$_}), qw/wait maxwait callback/,
    };

    my $active  = $self->active;

    $$searches{$name} = Net::LDAPx::Sync->new(
        LDAP    => $self->LDAP,
        cache   => 1,
        thaw    => $self->sync_state->{$name},
        search  => \%params,
        callbacks   => {
            idle    => sub { delete $$active{$name} },
            refresh => sub { $$active{$name} = 1 },
            change  => $self->weak_method("invalidate", undef, [$name]),
        },
    );
}

sub results {
    my ($self, $srch) = @_;
    map BMORROW::LDAP::Entry->new($_),
    $self->searches->{$srch}->results;
}

sub _show_caches {
    my ($self) = @_;
    my $S = $self->searches;
    
    say join "",
        "Current cache contents:\n",
        map { ("---$_---\n", map $_->ldif, $$S{$_}->results) }
        keys %$S;
}

sub _build_plugins {
    my ($self) = @_;

    my %plg;
    for (keys %{$self->conf("plugins")}) {
        my ($name, $type) = /(.*)=(.*)/ || ($_, $_);
        $plg{$name} and die "Duplicate plugin name: [$name]\n";

        my $mod = use_module(__PACKAGE__ . "::$type");
        my $plg = $plg{$name} = $mod->new(Dist => $self, name => $name);
        $plg->init;

        my %srch = $plg->searches;
        for (keys %srch) {
            my $cbm = $srch{$_}{callback};
            $srch{$_}{callback} = sub { $plg->$cbm };
            $self->add_search("$name.$_", %{$srch{$_}});
        }
    }
    \%plg;
}

sub init {
    my ($self) = @_;

    my $L = $self->LDAP;

    $L->bind;
    $L->async(1);

    $self->plugins;

    $self->register_kevent(fileno $L->socket(sasl_layer => 0),
        EVFILT_READ, sub {
            info "LDAP read";
            $L->process;
        },
    );
    $self->register_kevent(POSIX::SIGINT, EVFILT_SIGNAL,
        $self->weak_method("stop"));
    $SIG{INT} = "IGNORE";
    $self->register_kevent(POSIX::SIGTERM, EVFILT_SIGNAL,
        $self->weak_method("stop"));
    $SIG{TERM} = "IGNORE";
    $self->register_kevent(SIGINFO, EVFILT_SIGNAL,
        $self->weak_method("_show_caches"));
    $self->register_kevent(POSIX::SIGQUIT, EVFILT_SIGNAL, sub {
        info "QUIT!";
        exit 1;
    });
    $SIG{QUIT} = "IGNORE";
}

sub run {
    my ($self) = @_;

    my $KQ      = $self->KQ;
    my $S       = $self->searches;
    my $active  = $self->active;

    say "Starting searches...";
    $_->sync(persist => 1) for values %$S;

    say "Waiting for sync...";
    while (%$active) {
        for ($KQ->kevent) {
            info "KEVENT: " . pp $_;
            $$_[KQ_UDATA]->();
        }
    }

    say "Recording sync state...";
    my $frz = { map +($_ => $$S{$_}->freeze), keys %$S };
    write_file $self->conf("sync"),
        JSON::XS->new->pretty->ascii->encode($frz);

    say "Done.";
}

sub stop {
    my ($self) = @_;

    my $S = $self->searches;
    say "Stopping searches...";
    $_->stop_sync for values %$S;
}

1;

=head1 AUTHOR

Ben Morrow <ben@morrow.me.uk>

=head1 COPYRIGHT

Copyright 2014 Ben Morrow.

Distributed under the 2-clause BSD licence.

