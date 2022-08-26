#!/usr/bin/perl
# A script which parses syslogs for start, stop, and failure events for services such as sudo, ssh, and logins.
# Results of parsing are put in the correlation database.
# See also:
# KB #56990
#
use warnings;
use strict;
use Date::Parse qw(str2time);
use Socket;
use DBI;
use DBD::mysql;
use Digest::MD5 qw(md5_hex);
use Geo::IP;
use Data::Dumper;
use Storable;
use POSIX();

---
my $deb_vers = get_host_debian_version();
$deb_vers = 0 unless(defined $deb_vers);

$| = 1;

unless (-f '/etc/syslog-ng/syslogserver' && ! -f '/etc/syslog-ng/syslogserver.backup') {
	die('ERROR: This script should only be run on the main syslogserver.');
}

my %torIPs = %{retrieve('/etc/syslog-ng/TorExitIPs')} or print "Warning! TorExitIPs file!!";

sub catch_HUP
{
	%torIPs = %{retrieve('/etc/syslog-ng/TorExitIPs')} or print "Warning! Recived sig hup but not TorExitIPs hash";
}

$SIG{HUP} = \&catch_HUP;


$ENV{DEBUG}	= 0 unless ( defined( $ENV{DEBUG} ) );
$ENV{DRYRUN}	= 0 unless ( defined( $ENV{DRYRUN} ) );

our @LogTypes;
{
	my $LogTypes = shift;
	@LogTypes = split( /,/, $LogTypes );
}
our @LogParsers;

for my $LogType (@LogTypes) {
	# TODO: Cleanup: We don't run most of these mail services anymore.
	if ( $LogType eq 'all' || $LogType eq 'mail' ) {
		#push @LogParsers, qw(sm_mta dovecot perdition);
		push @LogParsers, qw(sm_mta);
	}
	#if ( $LogType eq 'all' || $LogType eq 'syslog' ) {
	#	push @LogParsers, qw(horde);
	#}
	if ( $LogType eq 'all' || $LogType eq 'auth' ) {
		push @LogParsers, qw(sshd CAEauth gdm login sudo su lightdm);
	}
	# some few gdm failed messages wind up in daemon.
	# FIXME: gdm is planned to go away (to be replaced in wheezy with lightdm) so this too should pass.
	if ( $LogType eq 'daemon' ) {
		push @LogParsers, qw(gdm);
	}
	# FIXME Lightdm sucks even more in this respect. It comes into user, not even daemon.
	if ( $LogType eq 'user' ) {
		push @LogParsers, qw(lightdm);
	}
	# TODO: Cleanup: Is this style of vpn still in use at all?
	if ( $LogType eq 'all' || $LogType eq 'local4' ) {
		push @LogParsers, qw(vpn);
	}
	if ( $LogType eq 'all' || $LogType eq 'daemon' ) {
		push @LogParsers, qw(radius smbd);
	}
	if ( $LogType eq 'all' || $LogType eq 'auth' ) {
		push @LogParsers, qw(shibboleth);
	}
	# For catching reboots, for instance.
	if ( $LogType eq 'all' || $LogType eq 'kern' ) {
		push @LogParsers, qw(kernel);
	}
	if ( $LogType eq 'all' || $LogType eq 'win' ) {
		push @LogParsers, qw(winlogon);
	}
}

die("ERROR: No LogParsers registered!") unless (@LogParsers);

map { $_ = 'parse_' . $_ } @LogParsers;

---

our $geoip = undef;
our $geoip_ts = 0;

sub geoip {
	my $IP = shift;
	my @Stat = stat('/opt/GeoIP.dat');
	warn "Unable to access GeoIP database" unless (@Stat);
	if ( $Stat[9] > $geoip_ts ) {
		$geoip	= undef;
		$geoip_ts = 0;
	}
	unless ( defined $geoip ) {
		unless ( $geoip = Geo::IP->open('/opt/GeoIP.dat') ) {
			warn "Unable to load GeoIP database";
			$geoip = undef;
			$geoip_ts = 0;
		}
		else {
			$geoip_ts = $Stat[9];
		}
	}
	if ( defined $geoip ) {
		return $geoip->country_code_by_addr($IP);
	}
	return undef;
}

our $geoipv6 = undef;
our $geoipv6_ts = 0;

sub geoipv6 {
	my $IP = shift;
	# A glitch with the GeoIP library causes ::1 (ipv6 localhost) to be interpreted
	# as being in Australia (AU).  Skip any references to ::1 for now.
	# RT #467982
	if ($IP =~ /^::1$/) {
		return undef;
	}
	my @Stat = stat('/opt/GeoIPv6.dat');
	warn "Unable to access GeoIPv6 database" unless (@Stat);
	if ( $Stat[9] > $geoipv6_ts ) {
		$geoipv6	= undef;
		$geoipv6_ts = 0;
	}
	unless ( defined $geoipv6 ) {
		unless ( $geoipv6 = Geo::IP->open('/opt/GeoIPv6.dat') ) {
			warn "Unable to load GeoIP database";
			$geoipv6 = undef;
			$geoipv6_ts = 0;
		}
		else {
			$geoipv6_ts = $Stat[9];
		}
	}
	if ( defined $geoipv6 ) {
		return $geoipv6->country_code_by_addr_v6($IP);
	}
	return undef;
}

sub dump_query {
	my $Query = shift;
	for my $Val (@_) {
		my $Value = $Val;
		if ( defined($Value) && $Value !~ /^[0-9]+$/ ) {
			$Value = $conn->quote($Value) unless ( $Value =~ /^[0-9]+$/ );
		}
		elsif ( !defined($Value) ) {
			$Value = 'NULL';
		}
		$Query =~ s/\?/$Value/;
	}
	printf "%s\n", $Query;
}

our %Queries;

sub run_query {
	my $Query	= shift;
	my @Parameters	= @_;

	unless ( exists( $Queries{$Query} ) ) {
		$Queries{$Query} = $conn->prepare($Query);
	}
	dump_query( $Query, @Parameters )
		if ( $ENV{DEBUG} > 0 || $ENV{DRYRUN} > 0 );
	$Queries{$Query}->execute(@Parameters) unless ( $ENV{DRYRUN} > 0 );
}

sub close_session {
	my $Stop	= shift;
	my $Implicit	= shift;
	my %Conditions	= @_;
	my @CONDITION_FIELDS = qw(User Host Service SessionID Start IPv4 IPv6);

	my $Query;
	my @Parameters;
	$Query .= "UPDATE raw_logins SET Stop=?, ImplicitStop=? WHERE ";
	push @Parameters, $Stop, $Implicit;
	$Query .= "ImplicitStop IS NULL AND type='success'";
	$Query .= "AND Start < ? + 3660 ";
	push @Parameters, $Stop;

	foreach my $Field (@CONDITION_FIELDS) {
		next unless ( exists( $Conditions{$Field} ) );
		my $Comparison	= '=';
		my $Value	= $Conditions{$Field};
		if ( ref($Value) eq 'HASH' ) {
			$Comparison	= $Value->{'comparison'};
			$Value		= $Value->{'value'};
		}
		$Query .= sprintf( 'AND %s %s ? ', $Field, $Comparison );
		push @Parameters, $Value;
	}

	run_query( $Query, @Parameters );
}

my $q_start_sql =
"INSERT IGNORE INTO raw_logins (Start, Stop, IPv4, IPv6, User, Host, Service, Privilege, SessionID, CountryCode, tor, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'success')";

# Failure messages have no duration, so their stop is the same as their start and thus can have no implicit stop (ie: due to reboot).
my $q_failure_sql =
"INSERT IGNORE INTO raw_logins (Start, Stop, ImplicitStop, IPv4, IPv6, User, Host, Service, Privilege, SessionID, CountryCode, tor, type) VALUES (?, Start, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'failure')";

# Similarly, some services have no stop messages, so we simply note their stop to be the same as their start with no implicit stop.
my $q_use_sql = "INSERT IGNORE INTO raw_logins (Start, Stop, ImplicitStop, IPv4, IPv6, User, Host, Service, Privilege, SessionID, CountryCode, tor, type) VALUES (?, Start, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'success')";

my $CurHour		= -1;
my $CurMin		= -1;
my $UnsuccessfulLines	= 0;
INPUTLINE: while (<>) {
	chomp;
	my $Reconnects = 3;
	PARSER: for my $LogParser (@LogParsers) {
		my $Row;
		{ no strict 'refs'; $Row = &{$LogParser}; }
		next unless ( defined($Row) );

		warn $_ if ($ENV{DEBUG});

		# DONE: Strip out @domain from usernames.
		$Row->{user} =~ s/^([^@]+)@\S*$/$1/ if (defined($Row->{user}));

		# Perform some cleanup of old records once in a while.
		if ( $CurHour != int( ( $Row->{ts} % 86400 ) / 3600 ) ) {
			$CurHour = int( ( $Row->{ts} % 86400 ) / 3600 );
			$CurMin = int( ( $Row->{ts} % 86400 ) / 60 );
			printf "%2u\n", $CurHour if ( $ENV{DEBUG} > 0 );

			# Only keep 90 days of records (same as normal syslog).
			$conn->do(
				'DELETE FROM raw_logins WHERE GREATEST(Start, Stop) < UNIX_TIMESTAMP()-(90*86400)'
			) if ( $CurHour == 0 && $CurMin <= 10 );
		}

		my $IPv6 = undef;
		my $IPv4 = undef;
		if ( defined( $Row->{ip} ) ) {
			# Sometimes 'ip' contains a trailing colon, e.g. "failure from 1.2.3.4: Bad password"
			# where $ip is parsed as "1.2.3.4:"
			if ($Row->{ip} =~ /:$/ && $Row->{ip} !~ /::$/) {
				$Row->{ip} =~ s/:$//;
			}
			$Row->{ip} =~ s/^::ffff:((?:[0-9]{1,3}\.){3}[0-9]{1,3})$/$1/;
			if ( $Row->{ip} =~ /:/ ) {
				$IPv6 = $Row->{ip};
				$IPv6 = expand6($IPv6);
				$IPv6 =~ s/://g;
				next if ( length($IPv6) != 32 );
				$IPv6 = pack( 'H*', $IPv6 );
			}
			else {
				my $IPv4_packed = inet_aton( $Row->{ip} );
				$IPv4 = unpack( 'N', $IPv4_packed ) if (defined $IPv4_packed);
			}
		}

		if ( !exists( $Row->{countrycode} ) ) {
			$Row->{countrycode} = undef;
			if ($IPv4) {
				$Row->{countrycode} = geoip( $Row->{ip} );
			}
			elsif ($deb_vers >= 7 && $IPv6) {
				$Row->{countrycode} = geoipv6( $Row->{ip} );
			}
		}

		# Check to see if the login IPv4 is a tor exit node
		my $inTor = undef;
		if ($IPv4 && $torIPs{$IPv4})
		{
			$inTor = 1;
		}
		elsif ($IPv4)
		{
			$inTor = 0;
		}
		eval {
			if ( $Row->{type} eq 'start' )
			{
				run_query(
					$q_start_sql,		$Row->{ts},
					$Row->{ts},		$IPv4,
					$IPv6,			$Row->{user},
					$Row->{host},		$Row->{service},
					$Row->{privilege},	$Row->{sessionid},
					$Row->{countrycode},	$inTor
				);
			}
			elsif ( $Row->{type} eq 'stop' ) {
				$Row->{implicit} = 0 unless ( defined( $Row->{implicit} ) );
				my %Parameters;
				my %Fields = (
					user		=> 'User',
					host		=> 'Host',
					service		=> 'Service',
					sessionid 	=> 'SessionID'
				);
				foreach my $Field ( keys(%Fields) ) {
					next unless exists( $Row->{$Field} );
					$Parameters{ $Fields{$Field} } = $Row->{$Field};
				}
				$Parameters{IPv4} = $IPv4 if ( defined($IPv4) );
				$Parameters{IPv6} = $IPv6 if ( defined($IPv6) );
				if ( $Row->{implicit} == 1 ) {
					$Parameters{Start} =
					{ comparison => '<=', value => $Row->{ts} };
				}
				close_session( $Row->{ts}, $Row->{implicit}, %Parameters );
			}
			elsif ( $Row->{type} eq 'use' ) {
				run_query(
					$q_use_sql,
					$Row->{ts},		$IPv4,
					$IPv6,			$Row->{user},
					$Row->{host},		$Row->{service},
					$Row->{privilege},	$Row->{sessionid},
					$Row->{countrycode},	$inTor
				);
			}
			elsif ( $Row->{type} eq 'failure' ) {
				run_query(
					$q_failure_sql,
					$Row->{ts},		$IPv4,
					$IPv6,			$Row->{user},
					$Row->{host},		$Row->{service},
					$Row->{privilege},	$Row->{sessionid},
					$Row->{countrycode},	$inTor
				);
			}
			else {
				die(	$0
					. ' Internal Parser Error: Row type is "'
					. $Row->{type}
					. '"' );
			}
		};
		if ( $@ =~ /^DBD::mysql::st execute failed: / ) {
			print STDERR "$@" if ( $ENV{DEBUG} > 0 );
			RETRY: while ($Reconnects) {
				printf "Consecutive Attempt #%u.  Sleeping %u.\n",
				( 4 - $Reconnects ), 3**( 4 - $Reconnects );
				sleep( 3**( 4 - $Reconnects ) );
				$Reconnects--;
				if (
					$conn = DBI->connect(
						'dbi:mysql:correlationdb:mysql-correlation.cae.wisc.edu:3306',
						'raw_logins',
						'LGh8TKqeLRrnz6Qz',
						{ AutoCommit => 1, RaiseError => 1 }
					)
				)
				{
					%Queries = ();
					redo PARSER;
				}
			}
			unless ($conn) {
				die "Unable to reconnect: $@";
			}
			if ( $UnsuccessfulLines++ < 3 ) {
				printf
				"Consecutive Unsuccessful Input Line #%u.  Sleeping %u.\n",
				$UnsuccessfulLines, 5**$UnsuccessfulLines;
				sleep( 5**$UnsuccessfulLines );
				next INPUTLINE;
			}
			else {
				die $@;
			}
		}
		elsif ($@) {
			die $@;
		}
		last PARSER;
	}
	$UnsuccessfulLines = 0;
}

sub parse_sm_mta {
	return undef
		unless
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) sm-mta\[[0-9]+\]: AUTH=server, relay=(?:[^ ]+ \[|\[IPv6:)([0-9a-fA-F:.]+)\], authid=([^ ,]+), mech=/;
	return {
		type		=> 'use',
		service		=> 'smtp',
		ts		=> str2time($1),
		ip		=> $3,
		user		=> $4,
		host		=> $2,
		privilege	=> undef,
		sessionid	=> undef
	};
}

sub parse_dovecot {
	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (?:dovecot: )?dovecot: (pop|imap)[0-9]?-login: Login: user=<([^>]+)>, method=PLAIN, rip=([0-9a-fA-F:.]+),/
	)
	{
		return {
			type		=> 'start',
			service		=> $3,
			ts		=> str2time($1),
			ip		=> $5,
			user		=> $4,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> undef
		};
	}

	# New format as of 30-Mar-2010:
	# Added another possible (dovecot: ) - 2011-05-31 bpkroth

	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (?:dovecot: )?dovecot: (?:pop|imap)[0-9]?-login: Login : pid=[0-9]+, service=(IMAP|POP)[0-9]?, user=<([^>]+)>, rip=([0-9a-fA-F:.]+), .*, mail_pid=([0-9]+)$/
	)
	{
		return {
			type		=> 'start',
			service		=> lc($3),
			ts		=> str2time($1),
			ip		=> $5,
			user		=> $4,
			host		=> $2,
			privilege 	=> undef,
			sessionid 	=> sprintf( '%s[%u]', lc($3), $6 )
		};
	}

	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (?:dovecot: )?dovecot: pid=([0-9]+), service=(IMAP|POP)[0-9]?, user=<([^>]+)>, rip=([0-9a-fA-F:.]+), .* : (?:Disconnected|Connection closed)/
	)
	{
		return {
			type		=> 'stop',
			service		=> $4,
			ts		=> str2time($1),
			ip		=> $6,
			user		=> $5,
			host		=> $2,
			sessionid	=> sprintf( '%s[%u]', $4, $3 )
		};
	}
	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (?:dovecot: )?dovecot: (?:pop|imap)[0-9]?-login: (?:(?:Disconnected(?:: Inactivity)?)|(?:Aborted login)) \(auth failed, [0-9]+ attempts\) : pid=[0-9]+, service=(IMAP|POP)[0-9]?, user=<([^>]+)>, rip=([0-9a-fA-F:.]+), .*, mail_pid=([0-9]+)$/
	)
	{
	    return {
			type		=> 'failure',
			service		=> lc($3),
			ts		=> str2time($1),
			ip		=> $5,
			user		=> $4,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> sprintf( '%s[%u]', lc($3), $6 ),
		};
	}


	return undef;
}

sub parse_perdition {
	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (perdition\[[0-9]+\]): Auth: ([0-9a-fA-F:.]+)->[^ ]+ user="([^"]+)" server="(imap|pop)\..* status="ok"/
	)
	{
		return {
			type		=> 'start',
			service		=> $6,
			ts		=> str2time($1),
			ip		=> $4,
			user		=> $5,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (perdition\[[0-9]+\]): Close: ([0-9a-fA-F:.]+)->[^ ]+ user="([^"]+)" /
	)
	{
		return {
			type		=> 'stop',
			ts		=> str2time($1),
			ip		=> $4,
			user		=> $5,
			host		=> $2,
			sessionid	=> $3
		};
	}

	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (perdition\[[0-9]+\]): Fatal [Ee]rror .* Exiting child\./
	)
	{
		return {
			type		=> 'stop',
			ts		=> str2time($1),
			host		=> $2,
			sessionid	=> $3
		};
	}

	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (perdition\[[0-9]+\]): Connect: ([0-9a-fA-F:.]+)->/
	)
	{
		return {
			type		=> 'stop',
			implicit	=> 1,
			ts		=> str2time($1),
			ip		=> $4,
			host		=> $2,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (perdition\[[0-9]+\]): Auth: ([0-9a-fA-F:.]+)->[^ ]+ user="([^"]+)" server="\(null\)" port="\(null\)" status="failed: Login Disabled"/
	)
	{
		return {
			service		=> 'perdition',
			type		=> 'failure',
			ts		=> str2time($1),
			ip		=> $4,
			host		=> $2,
			user		=> $5,
			sessionid	=> $3,

		}
	}
	else {
		return undef;
	}
}

sub parse_horde {
	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) HORDE\[[0-9]+\]: \[imp\] Login success for ([^ ]+) \[([0-9a-fA-F:.]+)\]/
	)
	{
		return {
			type		=> 'use',
			service		=> 'horde',
			ts		=> str2time($1),
			ip		=> $4,
			user		=> $3,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> undef
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) HORDE\[[0-9]+\]: \[imp\] FAILED LOGIN for ([^ ]+) \[([0-9a-fA-F:.]+)\]/
   	)
	{
	    return {
			type		=> 'failure',
			service		=> 'horde',
			ts		=> str2time($1),
			ip		=> $4,
			user		=> $3,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> undef,
	    }
	}
	else {
		return undef;
	}
}

sub parse_sshd {
	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (sshd\[[0-9]+\]): Accepted [^ ]+ for ([^ ]+) from ([0-9a-fA-F:.]+) /
	)
	{
		return {
			type		=> 'start',
			service		=> 'sshd',
			ts		=> str2time($1),
			ip		=> $5,
			user		=> $4,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (sshd\[[0-9]+\]): pam_unix\(sshd:session\): session closed for user ([^ ]+)$/
	)
	{
		return {
			type		=> 'stop',
			service		=> 'sshd',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $4,
			host		=> $2,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (sshd\[[0-9]+\]): Failed [^ ]+ for (?:invalid user )?([^ ]+) from ([0-9a-fA-F:.]+) port [0-9]+ ssh(?:[0-9]+)?$/
	)
	{
		return {
			type		=> 'failure',
			service		=> 'sshd',
			ts		=> str2time($1),
			ip		=> $5,
			user		=> $4,
			host		=> $2,
			sessionid	=> $3
		};
	}
# Actually, it turns out there's a message like the one above for these as well.
#	elsif (
#/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (sshd\[[0-9]+\]): Invalid user ([^ ]+) from ([0-9a-fA-F:.]+)$/
#	)
#	{
#		return {
#			type		=> 'failure',
#			service		=> 'sshd',
#			ts		=> str2time($1),
#			ip		=> $5,
#			user		=> $4,
#			host		=> $2,
#			sessionid	=> $3
#		};
#	}
	else {
		return undef;
	}
}

sub parse_CAEauth {

	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) CAEauth: Login successful for ([^ ]+) from ([0-9a-fA-F:.]+)$/
	)
	{
		return {
			type		=> 'use',
			service		=> 'CAEauth',
			ts		=> str2time($1),
			ip		=> $4,
			user		=> $3,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> undef
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) CAEauth: Login failure for (unknown user|[^ ]+) from ([0-9a-fA-F:.]+)/
	)
	{
		return {
			type		=> 'failure',
			service		=> 'CAEauth',
			ts		=> str2time($1),
			ip		=> $4,
			user		=> $3,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> undef,
		}
	}
	else {
		return undef;
	}
}

sub parse_gdm {

	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) systemd: Detected architecture x86-64\./
	)
	{
		return {
			type		=> 'stop',
			implicit	=> 1,
			ts		=> str2time($1),
			host		=> $2
		};
	}
	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (gdm\[[0-9]+\]): pam_unix\(gdm:session\): session opened for user ([^ ]+) by/
	)
	{
		return {
			type		=> 'start',
			service		=> 'gdm',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $4,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (gdm\[[0-9]+\]): pam_unix\(gdm:session\): session closed for user ([^ ]+)$/
	)
	{
		return {
			type		=> 'stop',
			service		=> 'gdm',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $4,
			host		=> $2,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (gdm\[[0-9]+\]): pam_ldap: error trying to bind as user \"uid=([^ ]+),ou=People,o=[^ ]+\" .*$/
	)
	{
		return {
			type		=> 'failure',
			service		=> 'gdm',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $4,
			host		=> $2,
			sessionid	=> $3,
		}
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (gdm\[[0-9]+\]): pam_unix\(gdm:auth\): check pass; user unknown$/
	)
	{
		return {
			type		=> 'failure',
			service		=> 'gdm',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> 'unknown',
			host		=> $2,
			sessionid	=> $3,
		}
	}
	else {
		return undef;
	}
}

sub parse_lightdm {
	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (lightdm(?:\[[0-9]*\])?): pam_unix\(lightdm:session\): session opened for user ([^ ]+) by/
	)
	{
		my $sessionid;
		my $user = $4;
		my $fqdn = $2;
		if ($3 eq "lightdm") {
			my $host = $2;
			$host =~ s/.cae.wisc.edu//;
			$sessionid = $user . "_" . $host;
		} else {
			$sessionid = $3;
		}
		return {
			type		=> 'start',
			service		=> 'lightdm',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $user,
			host		=> $fqdn,
			privilege	=> undef,
			sessionid	=> $sessionid
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (lightdm(?:\[[0-9]*\])?): pam_unix\(lightdm:session\): session closed for user ([^ ]+)$/
	)
	{
		my $sessionid;
		my $user = $4;
		my $fqdn = $2;
		if ($3 eq "lightdm") {
			my $host = $2;
			$host =~ s/.cae.wisc.edu//;
			$sessionid = $user . "_" . $host;
		} else {
			$sessionid = $3;
		}
		return {
			type		=> 'stop',
			service		=> 'lightdm',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $user,
			host		=> $fqdn,
			sessionid	=> $sessionid
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (lightdm(?:\[[0-9]*\])?): pam_ldap: error trying to bind as user \"uid=([^ ]+),ou=People,o=[^ ]+\" .*$/
	)
	{
		my $sessionid;
		my $user = $4;
		my $fqdn = $2;
		if ($3 eq "lightdm") {
			my $host = $2;
			$host =~ s/.cae.wisc.edu//;
			$sessionid = $user . "_" . $host;
		} else {
			$sessionid = $3;
		}
		return {
			type		=> 'failure',
			service		=> 'lightdm',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $user,
			host		=> $fqdn,
			sessionid	=> $sessionid,
		}
	}
	else {
		return undef;
	}
}

sub parse_login {
	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (login\[[0-9]+\]): pam_unix\(login:session\): session opened for user ([^ ]+) by/
	)
	{
		return {
			type		=> 'start',
			service		=> 'login',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $4,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (login\[[0-9]+\]): pam_unix\(login:session\): session closed for user ([^ ]+)$/
	)
	{
		return {
			type		=> 'stop',
			service		=> 'login',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $4,
			host		=> $2,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (login\[[0-9]+\]): FAILED LOGIN \([0-9]+\) on \'[^']+\' FOR \'([^ ]+)\'.*$/
	)
	{
		return {
			type		=> 'failure',
			service		=> 'login',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $4,
			host		=> $2,
			sessionid	=> $3,
		}


	}
	else {
		return undef;
	}
}

sub parse_sudo {

	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) sudo: +([^ ]+) : TTY=[^ ]+ ; .* ; USER=([^ ]+) ;/
	)
	{
		return undef if ( $3 eq 'nagios' );
		return {
			type		=> 'use',
			service		=> 'sudo',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $3,
			host		=> $2,
			privilege	=> $4,
			sessionid	=> undef
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) sudo: +([^ ]+) : [0-9] incorrect password attempts? ; .* ; USER=([^ ]+) ;/
	)
	{
		return {
			type		=> 'failure',
			service		=> 'sudo',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $3,
			host		=> $2,
			privilege	=> $4,
			sessionid	=> undef
		};
	}
	else {
		return undef;
	}
}

sub parse_su {

	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (su\[[0-9]+\]): Successful su for ([^ ]+) by ([^ ]+)$/
	)
	{
		return undef if ( $4 eq 'www-data' && $5 eq 'root' );
		return {
			type		=> 'start',
			service		=> 'su',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $5,
			host		=> $2,
			privilege	=> $4,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (su\[[0-9]+\]): pam_unix\(su:session\): session closed for user /
	)
	{
		return {
			type		=> 'stop',
			service		=> 'su',
			ts		=> str2time($1),
			ip		=> undef,
			host		=> $2,
			sessionid	=> $3
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (su\[[0-9]+\]): FAILED su for ([^ ]+) by ([^ ]+)$/
	)
	{
		return {
			type		=> 'failure',
			service		=> 'su',
			ts		=> str2time($1),
			ip		=> undef,
			user		=> $5,
			host		=> $2,
			privilege	=> $4,
			sessionid	=> $3
		};
	}
	else {
		return undef;
	}
}

sub parse_vpn {

	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) [^ ]+ [^ ]+: Group <[^ >]+> User <([^ >]+)> IP <([^ >]+)> Address <([^ >]+)> assigned to session/
	)
	{
		return {
			type		=> 'start',
			service		=> 'vpn',
			ts		=> str2time($1),
			ip		=> $3,
			user		=> $2,
			host		=> $4,
			privilege	=> undef,
			sessionid	=> sprintf( '%s@%s', $2, $3 )
		};
	}

	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) [^ ]+ [^ ]+: Group <[^ >]+> User <([^ >]+)> IP <([^ >]+)> SVC closing connection:/
	)
	{
		return {
			type		=> 'stop',
			service		=> 'vpn',
			ts		=> str2time($1),
			ip		=> $3,
			user		=> $2,
			sessionid	=> sprintf( '%s@%s', $2, $3 )
		};
	}

	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) [^ ]+ [^ ]+: Group = [^ ,]+, Username = ([^ ,]+), IP = ([^ ,]+), Assigned private IP address ([^ ]+) to remote user/
	)
	{
		return {
			type		=> 'start',
			service		=> 'vpn',
			ts		=> str2time($1),
			ip		=> $3,
			user		=> $2,
			host		=> $4,
			privilege	=> undef,
			sessionid	=> sprintf( '%s:%s', $2, $3 )
		};
	}

	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) [^ ]+ [^ ]+: Group = [^ ,]+, Username = ([^ ,]+), IP = ([^ ,]+), Session disconnected\./
	)
	{
		return {
			type		=> 'stop',
			service		=> 'vpn',
			ts		=> str2time($1),
			ip		=> $3,
			user		=> $2,
			sessionid	=> sprintf( '%s@%s', $2, $3 )
		};
	}
	# TODO: failure event messages?
	else {
		return undef;
	}
}

sub parse_radius {

# RT #323318
# For radius we only get login records, not logout, so we'll have to do something similar to sudo.
# Note: We skip over nagiosl login records, so as to not clutter downstream information sources
# RT #472807 The format of the output line has changed slightly
	if (/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) radiusd\[[0-9]+\]: \([0-9]+\) Login OK: \[([^]]+)\] \(from client ([^ ]+) port [0-9]+\) [ ]*virtual_server:([^ ]+)/) {
		return undef if ( $3 eq 'nagiosl' );
		my $radius_username = lc($3);
		return {
			type		=> 'use',
			service		=> 'radius',
			ts		=> str2time($1),
			ip		=> $2,
			user		=> $radius_username,
			host		=> $4,
			privilege	=> $5,
			sessionid	=> undef,
		};
	}

# RT 472807 - Format changed slightly
	if (/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) radiusd\[[0-9]+\]: \([0-9]+\) Login incorrect \([^)]+\): \[([^\]]+)\] \(from client ([^ ]+) port [0-9]+\)[ ]*virtual_server:([^ ]+)/) {
	    my $radius_username = lc($3);
		return {
			type		=> 'failure',
			service		=> 'radius',
			ts		=> str2time($1),
			ip		=> $2,
			user		=> $radius_username,
			host		=> $4,
			privilege	=> $5,
			sessionid	=> undef,
		}
	}

	else {
		return undef;
	}
}

sub parse_smbd {

	if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) smbd\[([0-9]+)\]:\s+[^ ]+ \(([^ ]+)\) connect to service ([^ ]+) initially as user ([^ ]+) \(uid=[0-9]+, gid=[0-9]+\) \(pid [0-9]+\)/
	)
	{
		return {
			type		=> 'start',
			service		=> 'samba',
			ts		=> str2time($1),
			ip		=> $4,
			user		=> $6,
			host		=> $2,
			sessionid	=> sprintf( '%s@%s', $3, substr( md5_hex($5), 0, 6 ) )
		};
	}

	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) smbd\[([0-9]+)\]:\s+[^ ]+ \(([^ ]+)\) closed connection to service ([^ ]+)/
	)
	{
		return {
			type		=> 'stop',
			service		=> 'samba',
			ts		=> str2time($1),
			ip		=> $4,
			host		=> $2,
			sessionid	=> sprintf( '%s@%s', $3, substr( md5_hex($5), 0, 6 ) )
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) smbd\[([0-9]+)\]:\s+check_ntlm_password:\s+Authentication for user \[[^ ]+\] -> \[([^ ]+)\] FAILED with error ([^ ]{22,24})/
	)
	{
		return {
			type		=> 'failure',
			service		=> 'samba',
			ts		=> str2time($1),
			user		=> $4,
			host		=> $2,
			sessionid	=> "$3\@$5", # sessions shouldn't be important for these failures.
		}
	}
	else {
		return undef;
	}
}

# Enabled as of 8/20/2015
# RT #403984
# jrdallman
# Now logs IP and session id.
sub parse_shibboleth {

if (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) shibboleth\[([^\]]+)\] INFO CAESHIB - LOGIN Success: (\S+) IP(?:[vV]?6)?:\[?([0-9a-fA-F.:]+)\]?(?:\s+([^ ]+))?\s*$/
	)
	{
		return {
			type		=> 'use',
			service		=> 'shibboleth',
			ts		=> str2time($1),
			ip		=> $5,
			user		=> $4,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> $3,
		};
	}
	elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) shibboleth\[([^\]]+)\] WARN CAESHIB - LOGIN (?:Unknown Account|Fail): (\S+) IP(?:[vV]?6)?:\[?([0-9a-fA-F.:]+)\]?(?:\s+([^ ]+))?\s*$/
)
	{
		return {
			type		=> 'failure',
			service		=> 'shibboleth',
			ts		=> str2time($1),
			ip		=> $5,
			user		=> $4,
			host		=> $2,
			privilege	=> undef,
			sessionid	=> $3,
		};
	}
	else {
		return undef;
	}
}



sub parse_kernel {

	return undef;

}

# TODO: TESTME: Does this handle Xen login info as well?
{
	my %RecentSIDs;

	sub parse_winlogon {

# NOTE: These example lines have not been kept up to date as the eventlog-syslog translator and/or windows have continued to change the syslog formats.

# Updates for new Windows machine formats.
# 1) winlogon.exe is no longer the only Process Name that matches (in fact it may not even show up)
# 2) Logon Types 2 (local interactive) and 10 (remote interactive) are used to filter the unhelpful and overly ambiguous svchost.exe Process Name
# -- See Also: http://www.windowsecurity.com/articles-tutorials/misc_network_security/Logon-Types.html
# 3) There may still be more than one of those, so, filter on full-zeros Logon GUIDs since they appear to be the only ones that correlate with Logoff events (below).
# See Also: RT-426798

# NOTE: 2019-09-25 I've removed the optional non-capturing group /(?:[^ ]+[:]? +[0-9]+ +[0-9:]+)?/ since it doesn't seem to be hitting anything. Just use /.*/, and we should be good, right? (bwilt)


# 2019-04-29 The windows log lines are continuing to evolve, so we need to adjust parsing yet again. Here is an example for posterity:

# 2019-09-25 The windows log lines continue to evolve, yet again. Joy. See RT-483777, RT-484008

# Capture groups: 1 (timestamp) 2 (host) 3 (user) 4 (domain) 5 (logon id) 6 (ip address)
		if (
/^([A-Za-z]+ {1,2}[0-9]{1,2} [\d:]{8}) ([\S]+wisc\.edu) .*(?:Microsoft-Windows-)?Security-Auditing: 4624: (?:AUDIT_SUCCESS )?An account was successfully logged on\. .* Logon Type: (?:2|10) .* Account Name: (\S+[^ \$]) Account Domain: (\S+) Logon ID: 0x(\S+) .* Logon GUID: \{[A-Za-z0-9-]+\} .* Process Name: \S+\\(?:svchost|winlogon)\.exe .* Source Network Address: (\S+) /
		)
		{
			my $TS = str2time($1);
			$RecentSIDs{"$2 $4 $5"} = $TS;
			# NOTE: No idea what this does, really. 
			for my $RecentSID ( keys %RecentSIDs ) {
				delete $RecentSIDs{$RecentSID} if ( $RecentSIDs{$RecentSID} < $TS - 10 );
			}
			return {
				type		=> 'start',
				service		=> 'winlogon',
				ts		=> $TS,
				ip		=> ( ( $6 eq '::1' || $6 eq '127.0.0.1' ) ? undef : $6 ),
				user		=> $3,
				host		=> $2,
				privilege	=> undef,
				sessionid	=> "$4 $5"
			};
		}

# NOTE 2019-04-29:
# NOTE 2019-09-25:

# Capture groups: 1 (timestamp) 2 (host) 3 (user) 4 (domain) 5 (logon id)
		elsif (
/^([A-Za-z]+ {1,2}[0-9]{1,2} [0-9:]{8}) ([\S]+wisc\.edu) .*(?:Microsoft-Windows-)?Security-Auditing: 4647: (?:AUDIT_SUCCESS )?User initiated logoff: .* Account Name: (\S+[^ \$]) Account Domain: (\S+) Logon ID: 0x(\S+) /
		)
		{
			return {
				type		=> 'stop',
				service		=> 'winlogon',
				ts		=> str2time($1),
				user		=> $3,
				host		=> $2,
				sessionid	=> "$4 $5"
			};
		}

# FIXME: These messages don't appear any longer.  Not sure how to find out if a machine has rebooted recently via logs alone yet ...

# Here's one possibility, though it only handles a clean shutdown/restart (no crashes):

		elsif (
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) (?:Eventlog )?to Syslog Service Started:/i ||
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) ([^ ]+) Service_Control_Manager: 7036: The Eventlog to Syslog service entered the running state./i ||
/^([A-Za-z]+ [0-9 ]{2} (?:[0-9]{2}:){2}[0-9]{2}) (([^ .]+)[^ ]*) User32: 1074: NT AUTHORITY\\SYSTEM: The process \S+\\shutdown.exe \(\S+\) has initiated the restart of computer \3 /i
		)
		{
			return {
				type		=> 'stop',
				implicit	=> 1,
				ts		=> str2time($1),
				host		=> $2
			};
		}

# NOTE 2019-09-25:

# Capture groups: 1 (timestamp) 2 (host) 3 (user) 4 (domain) 5 (logon id)
		elsif (
/^([A-Za-z]+ [0-9 ]{2} [0-9:]{8}) ([\S]+wisc\.edu) .*(?:Microsoft-Windows-)?Security-Auditing: 4672: (?:AUDIT_SUCCESS )?Special privileges assigned to new logon\. .* Account Name: (\S+[^ \$]) Account Domain: (\S+) Logon ID: 0x(\S+) /
		)
		{
			my $TS = str2time($1);
			# FIXME: What does this do?
			if ( exists $RecentSIDs{"$2 $4 $5"} ) {
				run_query("UPDATE raw_logins SET privilege='Administrator' WHERE Host=? AND User=? AND SessionID=? AND Start>=? AND Start<=? AND type='success'", $2, $3, "$4 $5", $TS - 10, $TS);
				delete $RecentSIDs{"$2 $4 $5"};
			}
			return undef;
		}

# NOTE 2019-09-25:

# Here again, the Process Name may not be winlogon.exe anymore.
# NOTE: In this case, we don't really care what Logon Type was attempted.
# In fact at that point, we don't care where which Process Name generated the log.

# Capture groups: 1 (timestamp) 2 (host) 3 (user) 4 (domain) 5 (process id) 6 (ip address)
		elsif (
/^([A-Za-z]+ [0-9 ]{2} [0-9:]{8}) ([\S]+wisc.edu) .*(?:Microsoft-Windows-)?Security-Auditing: 4625: (?:AUDIT_FAILURE )?An account failed to log on\. .* Logon Type: (?:2|10) .* Account Name: (\S+[^ \$]) Account Domain: (\S+) Failure Information: .* Process ID: 0x(\S+) .* Source Network Address: (\S+) /
		) {
			return {
				type		=> 'failure',
				service		=> 'winlogon',
				ts		=> str2time($1),
				ip		=> ( ( $6 eq '::1' || $6 eq '127.0.0.1' ) ? undef : $6 ),
				user		=> $3,
				host		=> $2,
				privilege	=> undef,
				sessionid	=> "$4 $5"
			};
		}
		else {
			return undef;
		}
	}
}

sub expand6 {
	my $IP6 = lc(shift);
	my @Parts = split /::/, $IP6, 2;

	for my $i ( 0 .. $#Parts ) {
		my @Pieces = split /:/, $Parts[$i];
		@Pieces = map { ( "0" x ( 4 - length($_) ) ) . $_ } @Pieces;
		$Parts[$i] = join ':', @Pieces;
	}

	if ( @Parts > 1 ) {
		$Parts[0] =~ s/://g;
		$Parts[1] =~ s/://g;

		# IPv6 addresses are 32 nibbles.
		my $Pad = 32 - ( length( $Parts[0] ) + length( $Parts[1] ) );
		$IP6 = join( ( "0" x $Pad ), @Parts );
	}
	else {
		$IP6 = join( '', @Parts );
	}

	$IP6 =~ s/[^0-9a-f]+//gi;
	$IP6 =~ s/(.{4})/$1:/g;
	$IP6 =~ s/:$//;
	return $IP6;
}
