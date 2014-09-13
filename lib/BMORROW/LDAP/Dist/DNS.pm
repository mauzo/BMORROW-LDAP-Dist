package BMORROW::LDAP::Dist::DNS;

use 5.012;
use Moo;

use BMORROW::LDAP::Util qw/rdn/;
use Data::Dump          qw/pp/;
use List::Util          qw/first/;
use Net::CIDR::Set;
use Net::IP;

extends "BMORROW::LDAP::Dist::Plugin";

has networks    => is => "lazy", clearer => 1;
has zones       => is => "lazy", clearer => 1;

sub _build_zones {
    my ($self) = @_;

    say "Refreshing zone list...";

    my $zns = {
        map {
            my $zn = $_;
            map +($_ => { server => $zn }), $zn->zoneName;
        }
        $self->results("server"),
    };

    for my $rrs ($self->results("zones")) {
        my $znn = $rrs->zoneName;
        my $zn  = $$zns{$znn} or next;
        my $rr  = $$zn{rr} //= [];
        my $nm  = $rrs->relativeDomainName;

        for my $typ (@{$self->conf("rrtypes")}) {
            my $att = "\l\U$typ\ERecord";
            my @rrs = $rrs->$att or next;
            say "RR [$znn] [$nm] [$typ] [$att]: " . pp \@rrs;
            push @$rr, [$nm, $typ, $_] for @rrs;
        }
    }

    $zns;
}

sub _build_networks {
    my ($self) = @_;

    say "Building network list...";

    my %nets    = map +($_->cn, [$_->ipNetworkNumber]),
                    $self->results("networks");
    my @nets    = map $_->mzNetwork, $self->results("server");
    my $v4      = Net::CIDR::Set->new({type => "ipv4"});
    my $v6      = Net::CIDR::Set->new({type => "ipv6"});

    for (map @{$nets{$_} // []}, @nets) {
        say "NETWORK [$_]";
        (/:/ ? $v6 : $v4)->add($_);
    }

    say "GOT V4 NETWORKS: " . $v4->as_string;
    say "GOT V6 NETWORKS: " . $v6->as_string;
    { a => $v4, aaaa => $v6 };
}
        

sub searches {
    my ($self) = @_;
    server  => {
        base        => join(",", $self->conf("dns", "base")),
        filter      => sprintf(
            "(&(objectClass=mzNameserver)(cn=%s))",
            $self->conf("server"),
        ),
        callback    => "server_changed",
    },
    zones   => {
        base        => join(",", $self->conf("dns", "base")),
        filter      => "objectClass=dNSZone",
        callback    => "zones_changed",
    },
    hosts   => {
        base        => join(",", $self->conf("hosts", "base")),
        filter      => "objectClass=ipHost",
        attrs       => [qw[ cn ipHostNumber ]],
        callback    => "hosts_changed",
        wait        => $self->conf("wait")->{min},
        maxwait     => $self->conf("wait")->{max},
    },
    networks => {
        base        => join(",", $self->conf("networks", "base")),
        filter      => "objectClass=ipNetwork",
        callback    => "nets_changed",
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

sub server_changed {
    my ($self) = @_;

    $self->invalidate("zones");
    $self->invalidate("networks");
}

sub nets_changed {
    my ($self) = @_;

    $self->clear_networks;
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

    my @hosts   = $self->results("hosts");
    my $nets    = $self->networks;

    for my $host (@hosts) {
        my $canon = rdn cn => $host->dn;
        for my $ip (map Net::IP->new($_), $host->ipHostNumber) {
            my $ipn = $ip->ip;

            for my $nm ($host->cn) {
                my $type = $ip->version == 6 ? "aaaa" : "a";
                $$nets{$type}->contains($ipn) or next;
                $push_rec->("$nm.", $type, $ipn);
            }
            $push_rec->($ip->reverse_ip, "ptr", "$canon.");
        }
    }

    my $Zones   = $self->conf("output");
    my $TTL     = $self->conf("TTL");
    my $zones   = $self->zones;

    -d $Zones or mkdir $Zones;
    unlink $_ for glob "$Zones/*";
    my $Time = time;

    for my $zn (keys %$zones) {
        say "  Writing zone file [$Zones/$zn]...";
        open my $ZN, ">", "$Zones/$zn";
        select $ZN;
        say "\$origin $zn.";

        my $zrc     = $$zones{$zn}{server};
        my $master  = rdn "cn", $zrc->dn;
        my $contact = $zrc->mail =~ s/@/./r;
        print "$zn. $$TTL{SOA} IN SOA $master. $contact. ";
        say "$Time 16384 2048 1048576 $$TTL{SOA}";

        for ($zrc->cn) {
            say "$zn. $$TTL{NS} IN NS $_.";
        }

        for my $r (
            sort { $$a[0] cmp $$b[0] } 
            @{$recs{$zn}}, @{$$zones{$zn}{rr} // []}
        ) {
            my ($nm, $typ, $dat) = @$r;
            my $ttl = $$TTL{$typ} // $$TTL{default};
            say "$nm $ttl IN $typ $dat";
        }

        select STDOUT;
        close $ZN;
    }

    say "  Writing [$Zones.nsd.conf]...";
    open my $CNF, ">", "$Zones.nsd.conf";
    print $CNF <<CNF for sort keys %$zones;
zone:
    name: "$_"
    zonefile: "$Zones/$_"

CNF
    close $CNF;

    say "  Writing [$Zones.unbound.conf]...";
    open $CNF, ">", "$Zones.unbound.conf";
    for (sort keys %$zones) {
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
