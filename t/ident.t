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

use Net::Ident 'ident_lookup';
use Socket;
use FileHandle;

# add any hosts below that you think might be running an ident daemon.
# this list also includes hosts that are not running an identd, to test
# "connection refused" messages from the library.
@hosts = qw(
   pc.xs4all.nl
   speed.xs4all.nl
   xs4all.nl
   fddi.mae-east.netcom.net
   lysator.liu.se
   nord-gw.nordu.net
   netcom.com
   127.0.0.1
);

$SIG{ALRM} = sub { 0 };
$| = 1;

sub bomb ($) { die "# Aargh: @_\n1..1\nnot ok1\n" };

$tcpproto = (getprotobyname('tcp'))[2] || 6;
$identport = (getservbyname('ident', 'tcp'))[2] || 113;
foreach $host ( @hosts ) {
    print "# trying to resolve $host...\n";
    if ( $addr = inet_aton($host) ) {
	$fh = new FileHandle;
	socket($fh, PF_INET, SOCK_STREAM, $tcpproto) or bomb("socket: $!");
	print "# connecting to " . inet_ntoa($addr) . ":$identport\n";
	alarm(10);
	if ( connect($fh, sockaddr_in($identport, $addr)) ) {
	    alarm(0);
	    print "# connected\n";
	    $connok ||= $fh;
	}
	else {
	    $e = $!;
	    alarm(0);
	    if ( $e =~ /connection refused/i ) {
		print "# connection refused\n";
		# try to make a connection to the telnet port instead,
		# to give us some connected filehandle to try the
		# ident lookup on.
		print "# connecting to " . inet_ntoa($addr) . ":23\n";
		$fh = new FileHandle;
		socket($fh, PF_INET, SOCK_STREAM, $tcpproto) or
		  bomb("socket: $!");
		alarm(10);
		if ( connect($fh, sockaddr_in(23, $addr)) ) {
		    alarm(0);
		    print "# connected\n";
		    $connrefuse ||= $fh;
		}
		else {
		    print "# connect: $!\n";
		    alarm(0);
		}
	    }
	    else {
		print "# connect: $e\n";
	    }
	}
	last if $connok && $connrefuse;
    }
}

$tests = 1;
$tests += 6 if $connok;
$tests++ if $connrefuse;
print "1..$tests\n";

$i = 1;
if ( $connok ) {
    print "# standard lookup test that will succeed, using FH->ident_lookup\n";
    $username = $connok->ident_lookup(30);
    print "not " unless $username;
    print "ok $i\n"; $i++;

    print "# now using Net::Ident::lookup\n";
    $username2 = Net::Ident::lookup($connok, 30);
    print "not " if !$username2 || $username2 ne $username;
    print "ok $i\n"; $i++;

    print "# now using ident_lookup, and an unqualified FH\n";
    *FH = $connok;
    *FH = \1;
    # prevent warning, sortof
    $username2 = ident_lookup('FH', 30);
    print "not " if !$username2 || $username2 ne $username;
    print "ok $i\n"; $i++;
    
    print "# now make it fail... establish connection to ident\n";
    $lookup = new Net::Ident $connok, 30;
    print "not " unless $lookup;
    print "ok $i\n"; $i++;

    print "not " unless $lookup->getfh && !$lookup->geterror;
    print "ok $i\n"; $i++;

    print "# now close original connection\n";
    shutdown($connok, 2);
    close($connok);
    sleep 1; # give it a little time...

    print "# try the rest of the lookup, which should fail\n";
    ($username, $opsys, $error) = $lookup->username;
    print "# remote identd said: $error\n";
    print "not " unless !defined $username && $opsys eq "ERROR";
    print "ok $i\n"; $i++;

}

if ( $connrefuse ) {
    print "# try to get a connection refused error\n";
    ($username, $opsys, $error) = $connrefuse->ident_lookup(30);

    print "not " unless !defined $username && !defined $opsys &&
      $error =~ /connection refused/i;
    print "ok $i\n"; $i++;
    print "# got: $error\n";
}

print "# try to get ident info on a something that's not a socket\n";
$lookup = new Net::Ident STDERR, 30;

print "not " unless $lookup &&
	  !defined $lookup->getfh &&
	  $lookup->geterror;
print "ok $i\n"; $i++;
print "# got: " . $lookup->geterror . "\n";




    

