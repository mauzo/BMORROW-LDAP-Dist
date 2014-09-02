package BMORROW::LDAP::Dist::DNS;

use 5.012;
use Moo;

use BMORROW::LDAP::Util qw/rdn/;
use List::Util          qw/first/;
use Net::IP;

extends "BMORROW::LDAP::Dist::Plugin";

has zones       => is => "lazy", clearer => 1;

sub _build_zones {
    my ($self) = @_;
    say "Refreshing zone list...";
    +{  map {
            my $zn = $_;
            map +($_ => $zn), $zn->zoneName;
        }
        $self->results("zones"),
    };
}

sub searches {
    my ($self) = @_;
    "hosts" => {
        base        => $self->conf("base"),
        filter      => "objectClass=ipHost",
        callback    => "hosts_changed",
        wait        => 10,
        maxwait     => 30,
    },
    "zones" => {
        base        => "ou=zones," . $self->conf("base"),
        filter      => q((nSRecord=*)),
        attrs       => [qw[ zoneName nSRecord ]],
        callback    => "zones_changed",
    },
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
    $self->invalidate("hosts");
}

sub hosts_changed {
    my ($self) = @_;
    say "Rebuilding zone files...";

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

1;
