package BMORROW::LDAP::Dist;

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

with "MooX::Role::WeakClosure";

has _conf   => is => "ro";

has KQ      => is => "lazy";

sub _build_KQ { IO::KQueue->new }

has LDAP    => is => "lazy";

sub _build_LDAP {
    my ($self) = @_;
    Net::LDAP->new($self->conf("host"));
}

has first_change => (
    is      => "ro", 
    lazy    => 1, 
    default => sub { time },
    clearer => 1,
);

has sync_state  => is => "lazy";

sub _build_sync_state {
    my ($self) = @_;
    my $cache = eval { scalar read_file $self->conf("sync") };
    $cache ? JSON::XS->new->decode($cache) : {};
}

has plugins     => is => "lazy";
has searches    => is => "ro", lazy => 1, default => sub { +{} };
has active      => is => "ro", lazy => 1, default => sub { +{} };

sub BUILDARGS {
    my ($class, @args) = @_;
    my $args = @args == 1 ? $args[0] : { @args };

    if (my $file = delete $$args{conf}) {
        $$args{_conf} = YAML::XS::LoadFile $file;
    }

    warn "BUILDARGS: " . pp $args;
    $args;
}

sub conf { $_[0]->_conf->{$_[1]} }

sub SIGINFO () { 29 } # grr

my $UUID = Data::UUID->new;

sub register_kevent {
    my ($self, $id, $filt, $cb) = @_;
    
    warn "REGISTER KEVENT [$id] [$filt] [$cb]";
    $self->KQ->EV_SET($id, $filt, EV_ADD, 0, 0, $cb);
}

sub set_timeout {
    my ($self, $id, $after, $meth) = @_;

    warn "SET TIMEOUT [$meth] [$after]";
    ref $meth or $meth = $self->weak_method($meth);

    try { $self->KQ->EV_SET($id, EVFILT_TIMER, EV_DELETE, 0, 0, 0) };
    $self->KQ->EV_SET($id, EVFILT_TIMER, EV_ADD|EV_ONESHOT, 
        0, $after, $meth);
}

sub add_search {
    my ($self, $name, %params) = @_;

    my $callback    = delete $params{callback};
    my $searches    = $self->searches;

    exists $$searches{$name}
        and croak "[$self] already has a search called [$name]";

    # create the entry so we get an address to key the timeout
    my $id      = int \$$searches{$name};
    my $active  = $self->active;

    $$searches{$name} = Net::LDAPx::Sync->new(
        LDAP    => $self->LDAP,
        cache   => 1,
        thaw    => $self->sync_state->{$name},
        search  => \%params,
        callbacks   => {
            idle    => sub { delete $$active{$name} },
            refresh => sub { $$active{$name} = 1 },
            change  => $self->weak_closure(sub {
                my ($self) = @_;
                say "Got notification";
                my $change = $self->first_change;
                $self->set_timeout($id, 
                    $self->conf("wait") * 1000, $callback) 
                    unless $change < time - $self->conf("maxwait");
            }),
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
    for (@{$self->conf("plugins")}) {
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
    my $S = $self->searches;

    $L->bind;
    $L->async(1);

    $self->plugins;
    $self->_show_caches;

    $self->register_kevent(fileno $L->socket(sasl_layer => 0),
        EVFILT_READ, sub {
            warn "LDAP read";
            $L->process;
        },
    );
    $self->register_kevent(POSIX::SIGINT, EVFILT_SIGNAL, sub {
        warn "SIGINT!";
        $_->stop_sync for values %$S;
    });
    $SIG{INT} = "IGNORE";
    $self->register_kevent(SIGINFO, EVFILT_SIGNAL,
        $self->weak_method("_show_caches"));
    $self->register_kevent(POSIX::SIGQUIT, EVFILT_SIGNAL, sub {
        warn "QUIT!";
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
            warn "KEVENT: " . pp $_;
            $$_[KQ_UDATA]->();
        }
    }

    $self->_show_caches;

    say "Recording sync state...";
    my $frz = { map +($_ => $$S{$_}->freeze), keys %$S };
    write_file $self->conf("sync"),
        JSON::XS->new->pretty->ascii->encode($frz);

    say "Done.";
}

1;
