package BMORROW::LDAP::Dist::HasExec;

use 5.012;
use Moo::Role;

requires qw/ conf /;

sub do_exec {
    my ($self) = @_;
    my $exec = $self->conf("exec");

    for (@$exec) {
        my @cmd = ref() ? @$_ : split;
        say "RUNNING " . join "", map "[$_]", @cmd;
        0 == system { $cmd[0] } @cmd
            or warn "$cmd[0] failed: $?";
    }
}

1;
