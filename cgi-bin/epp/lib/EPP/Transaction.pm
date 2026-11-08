package EPP::Transaction;

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

use EPP::EPPWriter;
use EPP::Date qw(date_for_svtrid);
use EPP::Session;
use Digest::SHA qw(sha1_hex);

use strict;
use warnings;

BEGIN {
	use Exporter ();
	our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

	$VERSION = do { my @r = (q$Revision: 1.01 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r};
	@ISA = qw(Exporter);
	@EXPORT = qw(record_cl_transaction);
	@EXPORT_OK = qw();
	%EXPORT_TAGS = (all => \@EXPORT_OK);
}

use constant MYSQL_DUPLICATE_ENTRY => 1062;
use constant CLTRID_COLUMN_LENGTH => 64;

# Runs the prepared INSERT into transaction_identifier. When it fails, typically on a reused
# clTRID, answers 2400 and exits: the header is already out, so a die leaves the client with
# no reply. The refused command has no row of its own, so it is not logged.
sub record_cl_transaction {
	my ($sth, $blob, $registrar_id, $frame, $cldate, $clmicrosecond) = @_;

	# clTRID is optional, and mod_epp passes an absent one as an empty string. Stored as NULL,
	# because the unique key would otherwise let a registrar omit it only once.
	my $cltrid = $blob->{clTRID};
	undef $cltrid if (defined($cltrid) && $cltrid eq '');

	# A clTRID only has to be unique for its registrar, but the unique key spans them all, so
	# the stored value carries the registrar. The column is as wide as the longest clTRID EPP
	# allows: one that no longer fits is hashed, since truncating would merge distinct values.
	# The value as sent stays in clTRIDframe.
	if (defined($cltrid)) {
		my $stored = "$registrar_id:$cltrid";
		$cltrid = length($stored) <= CLTRID_COLUMN_LENGTH ? $stored : "$registrar_id:" . sha1_hex($cltrid);
	}

	if ($sth->execute($registrar_id,$cltrid,$frame,$cldate,$clmicrosecond)) {
		# Every command passes through here, so this is where the reply learns which extensions
		# the client chose at login. EPPWriter leaves out the others.
		$blob->{exturis} = session_extensions($sth->{Database});
		return;
	}

	$blob->{human_readable_message} = 'clTRID already used' if ($sth->err == MYSQL_DUPLICATE_ENTRY);
	$blob->{resultCode} = 2400; # Command failed
	$blob->{command} //= 'unknown';
	$blob->{svTRID} //= date_for_svtrid() . '-clID:' . ($registrar_id // 0) . '-epp:' . ($blob->{cmd} // $blob->{command});
	print epp_writer($blob);
	exit;
}

1;
