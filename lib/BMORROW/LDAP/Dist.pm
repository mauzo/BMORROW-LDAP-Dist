package BMORROW::LDAP::Dist;

use 5.012;
use Moo;

use BMORROW::LDAP::Entry;
use BMORROW::LDAP::Util qw/rdn/;
use Net::LDAP;
use Net::LDAPx::Sync;

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

has Sync    => is => "lazy";

my $J = JSON::XS->new->ascii->pretty;
sub _build_Sync {
    my ($self) = @_;

    Net::LDAPx::Sync->new(
        LDAP    => $self->LDAP,
        cache   => 1,
        thaw    => do {
            my $cache = eval { scalar read_file $self->conf("sync") };
            $cache && $J->decode($cache);
        },
        search  => {
            base    => $self->conf("base"),
            filter  => "objectClass=ipHost",
        },
        callbacks   => {
            change => $self->weak_closure(sub {
                my ($self) = @_;
                say "Got notification";
                my $change = $self->first_change;
                $self->set_timeout(0, $self->conf("wait") * 1000, "do_zones")
                    unless $change < time - $self->conf("maxwait");
            }),
        },
    );
}

has zones       => is => "lazy";

sub _build_zones {
    my ($self) = @_;
    +{  map {
            my $zn = $_;
            map +($_ => $zn), $zn->zoneName;
        }
        map BMORROW::LDAP::Entry->new($_),
        map $_->entries,
        $self->LDAP->search(
            base    => "ou=zones," . $self->conf("base"),
            filter  => q((nSRecord=*)),
            attrs   => [qw[ zoneName nSRecord ]],
        ),
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
    try { $self->KQ->EV_SET($id, EVFILT_TIMER, EV_DELETE, 0, 0, 0) };
    $self->KQ->EV_SET($id, EVFILT_TIMER, EV_ADD|EV_ONESHOT, 
        0, $after, $self->weak_method($meth));
}

sub find_zone {
    my ($self, $name) = @_;
    $name = reverse $name;
    my $zn = first { 
        $name =~ /^\.?\Q$_\E(?:\.|$)/
    } sort map scalar reverse, keys %{$self->zones};
    $zn ? reverse $zn : ();
}

sub do_zones {
    my ($self) = @_;
    say "Rebuilding zone files...";
    $self->clear_first_change;

    my %recs;
    my $push_rec = sub {
        my ($nm, $typ, $data) = @_;
        my $zone = $self->find_zone($nm) or return;
        push @{$recs{$zone}}, [$nm, $typ, $data];
    };

    my @hosts = map BMORROW::LDAP::Entry->new($_), $self->Sync->results;
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

sub init {
    my ($self) = @_;

    my $L = $self->LDAP;
    my $S = $self->Sync;

    say "Defrosted sync:";
    print map $_->ldif, $S->results;

    $L->bind;
    $L->async(1);

    $self->register_kevent(fileno $L->socket(sasl_layer => 0),
        EVFILT_READ, sub {
            warn "LDAP read";
            $L->process;
        },
    );
    $self->register_kevent(POSIX::SIGINT, EVFILT_SIGNAL, sub {
        warn "SIGINT!";
        $S->stop_sync;
    });
    $SIG{INT} = "IGNORE";
    $self->register_kevent(SIGINFO, EVFILT_SIGNAL, sub {
        say "Current cache contents: ";
        print map $_->ldif, $S->results;
    });
    $self->register_kevent(POSIX::SIGQUIT, EVFILT_SIGNAL, sub {
        warn "QUIT!";
        exit 1;
    });
    $SIG{QUIT} = "IGNORE";
}

sub run {
    my ($self) = @_;

    my $KQ  = $self->KQ;
    my $S   = $self->Sync;

    say "Starting search...";
    $S->sync(persist => 1);

    say "Waiting for sync...";
    until ($S->state eq "idle") {
        for ($KQ->kevent) {
            warn "KEVENT: " . pp $_;
            $$_[KQ_UDATA]->();
        }
    }

    say "Current cache contents: ";
    print map $_->ldif, $S->results;

    say "Recording sync state...";
    write_file $self->conf("sync"), $J->encode($S->freeze);

    say "Done.";
}

1;
