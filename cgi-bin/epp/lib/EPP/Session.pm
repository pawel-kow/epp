package EPP::Session;

###############################################################################
#
#	-------------------------
#			XPanel EPP Server
#		-------------------------
#
#	Version: 1.0.0
#	Web Site: http://www.xpanel.com/
#
#	(c) Copyright 2017 XPanel Ltd.
#
# *  XPanel Ltd. licenses this file to You under the Apache License, Version 2.0
# *  (the "License"); you may not use this file except in compliance with
# *  the License.  You may obtain a copy of the License at
# *
# *      http://www.apache.org/licenses/LICENSE-2.0
# *
# *  Unless required by applicable law or agreed to in writing, software
# *  distributed under the License is distributed on an "AS IS" BASIS,
# *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
###############################################################################

################################################################
#
#	The services a client chose at <login>, RFC 5730 section 2.9.3.1.
#
#	mod_epp runs every frame as a new CGI process, so nothing survives
#	from the login in memory. It sends the same "session" cookie with
#	every request of a connection, and sets that header itself, so a
#	client cannot choose it. The choice is kept in the `epp_session`
#	table under that cookie (parent repo migration 002_epp_session.sql).
#
#	A request with no cookie, no row or no table answers undef from
#	session_extensions, and the writer then adds every extension, as
#	before this module existed.
#
################################################################

use strict;
use warnings;

BEGIN {
	use Exporter ();
	our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

	$VERSION = do { my @r = (q$Revision: 1.01 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r};
	@ISA = qw(Exporter);
	@EXPORT = qw(session_start session_end session_extensions);
	@EXPORT_OK = qw(session_cookie);
	%EXPORT_TAGS = (all => \@EXPORT_OK);
}

use constant EPP_NS => 'urn:ietf:params:xml:ns:epp-1.0';

# The value of the cookie mod_epp sends, or undef
sub session_cookie {
	my $cookies = $ENV{HTTP_COOKIE} // '';
	return $cookies =~ /(?:^|;\s*)session=([^;\s]+)/ ? $1 : undef;
}

# Runs $code with errors neither printed nor raised: a database without the epp_session table
# must keep working as before
sub _quietly {
	my ($dbh, $code) = @_;
	local $dbh->{PrintError} = 0;
	local $dbh->{RaiseError} = 0;
	return $code->();
}

# Stores the <svcs> of a successful login. A second login on the same connection carries the
# same cookie, so it replaces the row.
sub session_start {
	my ($dbh, $registrar_id, $xp, $login_node) = @_;
	my $session = session_cookie();
	return unless defined($session);

	$xp->set_namespace('epp', EPP_NS);
	my $objuris = join(' ', map { _trim($_->string_value) } $xp->findnodes('epp:svcs/epp:objURI', $login_node)->get_nodelist);
	my $exturis = join(' ', map { _trim($_->string_value) } $xp->findnodes('epp:svcs/epp:svcExtension/epp:extURI', $login_node)->get_nodelist);

	_quietly($dbh, sub {
		$dbh->do("REPLACE INTO `epp_session` (`session`,`registrar_id`,`objuris`,`exturis`,`logged_in`,`last_used`) VALUES(?,?,?,?,NOW(),NOW())",
			undef, $session, $registrar_id, $objuris, $exturis);
	});
}

sub session_end {
	my ($dbh) = @_;
	my $session = session_cookie();
	return unless defined($session);
	_quietly($dbh, sub { $dbh->do("DELETE FROM `epp_session` WHERE `session` = ?", undef, $session); });
}

# The extURIs chosen at login, as a hash reference, or undef when they are not known. Marks the
# session as used, at most once a minute, so that the cleanup keeps active sessions.
sub session_extensions {
	my ($dbh) = @_;
	my $session = session_cookie();
	return undef unless defined($session);

	return _quietly($dbh, sub {
		my ($exturis, $stale) = $dbh->selectrow_array("SELECT `exturis`, `last_used` < (NOW() - INTERVAL 1 MINUTE) FROM `epp_session` WHERE `session` = ?", undef, $session);
		return undef unless defined($exturis);
		$dbh->do("UPDATE `epp_session` SET `last_used` = NOW() WHERE `session` = ?", undef, $session) if ($stale);
		return { map { $_ => 1 } split(' ', $exturis) };
	});
}

sub _trim {
	my ($s) = @_;
	$s =~ s/^\s+|\s+$//g;
	return $s;
}

1;
