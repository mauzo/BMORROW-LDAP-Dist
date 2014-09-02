package BMORROW::LDAP::Dist;

use 5.012;
use Moo;

use BMORROW::LDAP::Entry;
use BMORROW::LDAP::Util qw/rdn/;
use Net::LDAP;
use Net::LDAPx::Sync;

use Carp;
use Data::Dump      qw/pp/;
use Data::UUID;
use File::Slurp     qw/read_file write_file/;
use IO::KQueue;
use IO::Select;
use JSON::XS        qw/encode_json/;
use List::Util      qw/first/;
use Net::IP;
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

has searches    => is => "ro", lazy => 1, default => sub { +{} };
has active      => is => "ro", lazy => 1, default => sub { +{} };

has zones       => is => "lazy", clearer => 1;

sub _build_zones {
    my ($self) = @_;
    +{  map {
            my $zn = $_;
            map +($_ => $zn), $zn->zoneName;
        }
        $self->results("zones"),
    };
}

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

sub find_zone {
    my ($self, $name) = @_;
    $name = reverse $name;
    my $zn = first { 
        $name =~ /^\.?\Q$_\E(?:\.|$)/
    } sort map scalar reverse, keys %{$self->zones};
    $zn ? reverse $zn : ();
}

sub zones_changed {
    my ($self) = @_;

    $self->clear_zones;
    $self->hosts_changed;
}

sub hosts_changed {
    my ($self) = @_;
    say "Rebuilding zone files...";
    $self->clear_first_change;

    my %recs;
    my $push_rec = sub {
        my ($nm, $typ, $data) = @_;
        my $zone = $self->find_zone($nm) or return;
        push @{$recs{$zone}}, [$nm, $typ, $data];
    };

    my @hosts = $self->results("hosts");
    for my $host (@hosts) {
        my $canon = rdn cn => $host->dn;
        for my $ip (map Net::IP->new($_), $host->ipHostNumber) {
            for my $nm ($host->cn) {
                $push_rec->("$nm.", 
                    $ip->version == 6 ? "AAAA" : "A", $ip->ip);
            }
            $push_rec->($ip->reverse_ip, "PTR", "$canon.");
        }
    }

    my $Zones   = $self->conf("zones");
    my $TTL     = $self->conf("TTL");
    my $Contact = $self->conf("contact");
    my $zones   = $self->zones;

    -d $Zones or mkdir $Zones;
    unlink $_ for glob "$Zones/*";
    my $Time = time;

    for my $zn (keys %$zones) {
        say "  Writing zone file [$Zones/$zn]...";
        open my $ZN, ">", "$Zones/$zn";
        select $ZN;

        my $zrc     = $$zones{$zn};
        my $master  = rdn "nSRecord", $zrc->dn;
        print "$zn. $$TTL{SOA} IN SOA $master. $Contact. ";
        say "$Time 16384 2048 1048576 $$TTL{SOA}";

        for ($zrc->nSRecord) {
            say "$zn. $$TTL{NS} IN NS $_.";
        }

        for my $r (@{$recs{$zn}}) {
            my ($nm, $typ, $dat) = @$r;
            my $ttl = $$TTL{$typ} // $$TTL{default};
            say "$nm $ttl IN $typ $dat";
        }

        select STDOUT;
        close $ZN;
    }

    say "  Writing [$Zones.nsd.conf]...";
    open my $CNF, ">", "$Zones.nsd.conf";
    print $CNF <<CNF for keys %$zones;
zone:
    name: "$_"
    zonefile: "$Zones/$_"

CNF
    close $CNF;

    say "  Writing [$Zones.unbound.conf]...";
    open $CNF, ">", "$Zones.unbound.conf";
    for (keys %$zones) {
        # XXX lookup and generate the addrs
        # We can't use stub-host since the NS records are in-bailiwick
        print $CNF <<CNF;
server:
    private-domain: "$_"
    local-zone: "$_" transparent
    domain-insecure: "$_"

stub-zone:
    name: "$_"
    stub-addr: 192.168.1.2

CNF
    }

    say "  Done.";
}

sub _show_caches {
    my ($self) = @_;
    my $S = $self->searches;
    
    say join "",
        "Current cache contents:\n",
        map { ("---$_---\n", map $_->ldif, $$S{$_}->results) }
        keys %$S;
}

sub init {
    my ($self) = @_;

    my $L = $self->LDAP;
    my $S = $self->searches;

    $L->bind;
    $L->async(1);

    $self->add_search("hosts",
        base        => $self->conf("base"),
        filter      => "objectClass=ipHost",
        callback    => "hosts_changed",
    );
    $self->add_search("zones",
        base        => "ou=zones," . $self->conf("base"),
        filter      => q((nSRecord=*)),
        attrs       => [qw[ zoneName nSRecord ]],
        callback    => "zones_changed",
    );

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
