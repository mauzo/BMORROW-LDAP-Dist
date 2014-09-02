package BMORROW::LDAP::Dist::Plugin;

use 5.012;
use Moo;

has Dist    => is => "ro", weak_ref => 1;
has name    => is => "ro";
has _conf   => is => "lazy";

sub _build__conf {
    my ($self) = @_;
    $self->Dist->_conf->{plugins}{$self->name} // {};
}

sub conf {
    my ($self, @keys) = @_;
    my $cnf     = $self->_conf;
    my $dist    = $self->Dist;
    wantarray 
        ? map $$cnf{$_} // $dist->conf($_), @keys
        : $$cnf{$keys[0]} // $dist->conf($keys[0]);
}

sub init { }

# Called by Dist, returns a hash of LDAP searches
sub searches { ... }

# Returns the results of one of our searches
sub results {
    my ($self, $srch) = @_;
    my $name = $self->name;
    $self->Dist->results("$name.$srch");
}

sub invalidate {
    my ($self, $srch) = @_;
    my $name = $self->name;
    $self->Dist->invalidate("$name.$srch");
}

1;
