# -*- Perl -*-
# test the Net::Ident modem, which is a bitch, because you really
# need an ident daemon to test it, and then you usually get a connection
# from a remote machine, and then ask for the username.
# so what we do is try to make a connection to an ident daemon, on
# some machine, and if that succeeds, see if we can do a successful lookup
# on that.
# This isn't guaranteed to succeed. If you are not (properly) connected
# to the internet, and if your localhost doesn't run an ident daemon,
# then this script won't work. If you do know a machine that you can
# currently reach, which runs an ident daemon, then put it's name or
# IPnumber in the list below.

require 5.002;

use Net::Ident;
use Socket;
use FileHandle;

# add any hosts below that you think might be running an ident daemon
@hosts = qw(
   xs4all.nl
   pc.xs4all.nl
   netcom.com
   127.0.0.1
);

$SIG{ALRM} = sub { 0 };

sub bomb () { die "1..1\nnot ok1\n" };

$tcpproto = (getprotobyname('tcp'))[2] || 6;
$identport = (getservbyname('ident', 'tcp'))[2] || 113;
foreach $host ( @hosts ) {
    if ( $addr = inet_aton($host) ) {
	$fh = new FileHandle;
	socket($fh, PF_INET, SOCK_STREAM, $tcpproto) or bomb;
	alarm(10);
	if ( connect($fh, sockaddr_in($identport, $addr)) ) {
	    alarm(0);
	    push(@conn, $fh);
	}
	alarm(0);
    }
}

print "1.." . scalar @conn . "\n";
$i = 1;
while ( $fh = shift @conn ) {
    $username = $fh->ident_lookup(30);
    print "not " unless $username;
    print "ok $i\n";
    $i++;
}

    

