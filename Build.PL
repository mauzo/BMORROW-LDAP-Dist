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
    meta_merge		=> {
	resources   => {
	    repository => "http://github.com/mauzo/BMORROW-LDAP-Dist",
	    bugtracker => "https://rt.cpan.org/Public/Dist/" .
		"Display.html?Name=BMORROW-LDAP-Dist",
	},
    },
)->create_build_script;
