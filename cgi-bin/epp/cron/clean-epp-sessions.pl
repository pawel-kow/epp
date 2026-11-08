#!/usr/bin/perl

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


# Removes the epp_session rows of clients that disconnected without <logout>. mod_epp has no
# hook for a dropped connection, so session-logout.cgi cannot clean them up. A stale row does no
# harm: no new connection carries its cookie. Every command marks its row as used, at most once a
# minute, so an active session is not removed.

use lib '/var/www/cgi-bin/epp/lib';
use strict;
use warnings;
use EPP::Config();
use DBI;
use vars qw(%c $dbh);
*c = \%EPP::Config::c;

# A session with no command for this long is taken to be gone. Removing a row of a session that
# is still open is not an error: its replies then carry every extension, as before epp#27.
use constant MAX_IDLE_MINUTES => 1440;

$dbh = DBI->connect("DBI:mysql:$c{'mysql_database'}:$c{'mysql_host'}:$c{'mysql_port'}","$c{'mysql_username'}","$c{'mysql_password'}") or die "$DBI::errstr";

my $n = $dbh->do("DELETE FROM `epp_session` WHERE `last_used` < (NOW() - INTERVAL ? MINUTE)", undef, MAX_IDLE_MINUTES) or die $dbh->errstr;
print "clean-epp-sessions.pl: removed " . ($n + 0) . " idle session(s)\n" if ($n > 0);
