use 5.010000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::SSH::Server',
    VERSION_FROM      => 'lib/Net/SSH/Server.pm',
    PREREQ_PM         => {},
    ABSTRACT_FROM     => 'lib/Net/SSH/Server.pm',
    AUTHOR            => 'Rob Brown <bbb@cpan.org>',
    LICENSE           => 'artistic_2',
);
