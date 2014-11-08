use Module::Build;

Module::Build->new(
    module_name		=> "BMORROW::LDAP::Dist",
    license		=> "bsd",
    configure_requires	=> {
	"Module::Build"	    => "0.38",
    },
    build_requires	=> {
	"Test::More"	    => "0.96",
    },
    requires            => {
        "BMORROW::LDAP"             => "0",
        "Data::Dump"                => "0",
        "Data::UUID"                => "0",
        "File::Slurp"               => "0",
        "IO::KQueue"                => "0",
        "JSON::XS"                  => "0",
        "Module::Runtime"           => "0",
        "Moo"                       => "0",
        "MooX::Role::WeakClosure"   => "0",
        "Net::CIDR::Set"            => "0",
        "Net::IP"                   => "0",
        "Net::LDAPx::Sync"          => "0",
        "Try::Tiny"                 => "0",
        "YAML::XS"                  => "0",
        "strictures::disable"       => "0",
    },
    meta_merge		=> {
	resources   => {
	    repository => "http://github.com/mauzo/BMORROW-LDAP-Dist",
	    bugtracker => "https://rt.cpan.org/Public/Dist/" .
		"Display.html?Name=BMORROW-LDAP-Dist",
	},
    },
)->create_build_script;
