package EPP::SecDNS;

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
#	RFC 5910 DS data on domain objects, stored in `secdns`.
#	The server offers the DS data interface only. A keyData
#	child of dsData is kept, keyData on its own is refused.
#
#	The parse functions change nothing. They return the parsed
#	data and an error, which is { code, message } or undef.
#
################################################################

use strict;
use warnings;
use Exporter 'import';

our @EXPORT = qw(secdns_parse_create secdns_parse_update secdns_store secdns_apply_update secdns_info);

use constant NS => 'urn:ietf:params:xml:ns:secDNS-1.1';
use constant MAX_SIG_LIFE => 2147483647;
use constant PUBKEY_COLUMN_LENGTH => 255;

# `secdns`.`digest` is varchar(64), which leaves out SHA-384 (type 4)
my %DIGEST_LENGTH = (1 => 40, 2 => 64, 3 => 64);

sub _error {
	my ($code, $message) = @_;
	return { code => $code, message => $message };
}

sub _trimmed_value {
	my ($xp, $path, $context) = @_;
	my $node = $xp->find($path, $context)->get_node(0);
	return undef unless $node;
	my $value = $node->string_value;
	$value =~ s/^\s+|\s+$//g;
	return $value;
}

# Returns (value, error)
sub _unsigned {
	my ($xp, $name, $context, $min, $max) = @_;
	my $value = _trimmed_value($xp, "secDNS:$name", $context);
	return (undef, _error(2003, "Missing secDNS:$name")) unless defined $value && length($value);
	return (undef, _error(2005, "Invalid secDNS:$name")) unless $value =~ /^\d+$/;
	return (undef, _error(2004, "secDNS:$name must be between $min and $max")) if $value < $min || $value > $max;
	return ($value + 0, undef);
}

sub _parse_key_data {
	my ($xp, $node) = @_;
	my %key;
	my $error;
	($key{flags}, $error) = _unsigned($xp, 'flags', $node, 0, 65535);
	return (undef, $error) if $error;
	($key{protocol}, $error) = _unsigned($xp, 'protocol', $node, 0, 255);
	return (undef, $error) if $error;
	($key{alg}, $error) = _unsigned($xp, 'alg', $node, 0, 255);
	return (undef, $error) if $error;

	my $pubkey = _trimmed_value($xp, 'secDNS:pubKey', $node);
	return (undef, _error(2003, 'Missing secDNS:pubKey')) unless defined $pubkey && length($pubkey);
	$pubkey =~ s/\s+//g;
	return (undef, _error(2005, 'Invalid secDNS:pubKey')) unless $pubkey =~ m{^[A-Za-z0-9+/]+={0,2}$};
	return (undef, _error(2306, 'secDNS:pubKey is longer than this server stores')) if length($pubkey) > PUBKEY_COLUMN_LENGTH;
	$key{pubKey} = $pubkey;
	return (\%key, undef);
}

sub _parse_ds_data {
	my ($xp, $node) = @_;
	my %ds;
	my $error;
	($ds{keyTag}, $error) = _unsigned($xp, 'keyTag', $node, 0, 65535);
	return (undef, $error) if $error;
	($ds{alg}, $error) = _unsigned($xp, 'alg', $node, 1, 255);
	return (undef, $error) if $error;
	($ds{digestType}, $error) = _unsigned($xp, 'digestType', $node, 1, 255);
	return (undef, $error) if $error;

	my $digest = _trimmed_value($xp, 'secDNS:digest', $node);
	return (undef, _error(2003, 'Missing secDNS:digest')) unless defined $digest && length($digest);
	return (undef, _error(2005, 'Invalid secDNS:digest')) unless $digest =~ /^[0-9A-Fa-f]+$/;
	my $length = $DIGEST_LENGTH{$ds{digestType}};
	return (undef, _error(2306, "secDNS:digestType $ds{digestType} is not supported")) unless $length;
	return (undef, _error(2306, "secDNS:digest must have $length hex digits for this digestType")) if length($digest) != $length;
	$ds{digest} = $digest;

	if (my $key_node = $xp->find('secDNS:keyData', $node)->get_node(0)) {
		($ds{keyData}, $error) = _parse_key_data($xp, $key_node);
		return (undef, $error) if $error;
	}
	return (\%ds, undef);
}

# The dsData children of $parent. Returns (arrayref, error).
sub _parse_ds_list {
	my ($xp, $parent) = @_;
	if ($xp->find('secDNS:keyData', $parent)->size > 0) {
		return (undef, _error(2306, 'The key data interface is not supported, use secDNS:dsData'));
	}
	my @list;
	my %seen;
	foreach my $node ($xp->find('secDNS:dsData', $parent)->get_nodelist) {
		my ($ds, $error) = _parse_ds_data($xp, $node);
		return (undef, $error) if $error;
		return (undef, _error(2306, 'The same secDNS:digest is given twice')) if $seen{uc($ds->{digest})}++;
		push @list, $ds;
	}
	return (\@list, undef);
}

# Returns (value or undef, error)
sub _parse_max_sig_life {
	my ($xp, $parent) = @_;
	return (undef, undef) if $xp->find('secDNS:maxSigLife', $parent)->size == 0;
	return _unsigned($xp, 'maxSigLife', $parent, 1, MAX_SIG_LIFE);
}

# Returns (plan, error). The plan is undef when the command has no secDNS:create.
sub secdns_parse_create {
	my ($xp, $extension) = @_;
	return (undef, undef) unless $extension;
	$xp->set_namespace('secDNS', NS);
	my $create = $xp->find('secDNS:create', $extension)->get_node(0);
	return (undef, undef) unless $create;

	my ($max_sig_life, $error) = _parse_max_sig_life($xp, $create);
	return (undef, $error) if $error;
	my $list;
	($list, $error) = _parse_ds_list($xp, $create);
	return (undef, $error) if $error;
	return (undef, _error(2003, 'Missing secDNS:dsData')) unless @$list;
	return ({ maxSigLife => $max_sig_life, dsData => $list }, undef);
}

sub _same_ds {
	my ($x, $y) = @_;
	return $x->{keyTag} == $y->{keyTag} && $x->{alg} == $y->{alg} && $x->{digestType} == $y->{digestType}
		&& uc($x->{digest}) eq uc($y->{digest});
}

sub _stored_ds {
	my ($dbh, $domain_id) = @_;
	my $stored = $dbh->selectall_arrayref("SELECT `keytag` AS `keyTag`,`alg`,`digesttype` AS `digestType`,`digest`,`maxsiglife`,`flags`,`protocol`,`keydata_alg`,`pubkey` FROM `secdns` WHERE `domain_id` = ? ORDER BY `id`", { Slice => {} }, $domain_id)
		or die $dbh->errstr;
	return $stored;
}

# Returns (plan, error). The plan is undef when the command has no secDNS:update.
# Checks the plan against what is stored, with the removals applied before the additions.
sub secdns_parse_update {
	my ($xp, $extension, $dbh, $domain_id) = @_;
	return (undef, undef) unless $extension;
	$xp->set_namespace('secDNS', NS);
	my $update = $xp->find('secDNS:update', $extension)->get_node(0);
	return (undef, undef) unless $update;

	my $urgent = _trimmed_value($xp, '@urgent', $update) // '';
	return (undef, _error(2102, 'The urgent attribute is not supported')) if $urgent =~ /^(true|1)$/;

	my $rem = $xp->find('secDNS:rem', $update)->get_node(0);
	my $add = $xp->find('secDNS:add', $update)->get_node(0);
	my $chg = $xp->find('secDNS:chg', $update)->get_node(0);
	return (undef, _error(2003, 'secDNS:update needs secDNS:rem, secDNS:add or secDNS:chg')) unless $rem || $add || $chg;

	my %plan = (remove_all => 0, remove => [], add => []);
	my $error;
	if ($rem) {
		my $all = _trimmed_value($xp, 'secDNS:all', $rem);
		if (defined $all) {
			return (undef, _error(2005, 'secDNS:all cannot be combined with other elements')) if $xp->find('secDNS:dsData|secDNS:keyData', $rem)->size > 0;
			return (undef, _error(2005, 'Invalid secDNS:all')) unless $all =~ /^(true|false|1|0)$/;
			$plan{remove_all} = $all =~ /^(true|1)$/ ? 1 : 0;
		}
		else {
			($plan{remove}, $error) = _parse_ds_list($xp, $rem);
			return (undef, $error) if $error;
		}
	}
	if ($add) {
		($plan{add}, $error) = _parse_ds_list($xp, $add);
		return (undef, $error) if $error;
	}
	if ($chg) {
		($plan{maxSigLife}, $error) = _parse_max_sig_life($xp, $chg);
		return (undef, $error) if $error;
	}

	my $stored = _stored_ds($dbh, $domain_id);
	$plan{stored_max_sig_life} = @$stored ? $stored->[0]{maxsiglife} : undef;

	my @remaining = $plan{remove_all} ? () : @$stored;
	foreach my $ds (@{ $plan{remove} }) {
		my $before = @remaining;
		@remaining = grep { !_same_ds($_, $ds) } @remaining;
		return (undef, _error(2306, "secDNS:dsData with keyTag $ds->{keyTag} is not on this domain")) if @remaining == $before;
	}
	foreach my $ds (@{ $plan{add} }) {
		if (grep { uc($_->{digest}) eq uc($ds->{digest}) } @remaining) {
			return (undef, _error(2306, "secDNS:dsData with keyTag $ds->{keyTag} is already on this domain"));
		}
	}
	if (defined $plan{maxSigLife} && !@remaining && !@{ $plan{add} }) {
		return (undef, _error(2306, 'secDNS:maxSigLife needs a domain with dsData'));
	}
	return (\%plan, undef);
}

# Stores dsData on a domain
sub secdns_store {
	my ($dbh, $domain_id, $list, $max_sig_life) = @_;
	my $sth = $dbh->prepare("INSERT INTO `secdns` (`domain_id`,`maxsiglife`,`interface`,`keytag`,`alg`,`digesttype`,`digest`,`flags`,`protocol`,`keydata_alg`,`pubkey`) VALUES(?,?,'dsData',?,?,?,?,?,?,?,?)") or die $dbh->errstr;
	foreach my $ds (@$list) {
		my $key = $ds->{keyData} || {};
		$sth->execute($domain_id, $max_sig_life, $ds->{keyTag}, $ds->{alg}, $ds->{digestType}, $ds->{digest},
			$key->{flags}, $key->{protocol}, $key->{alg}, $key->{pubKey}) or die $sth->errstr;
	}
}

sub secdns_apply_update {
	my ($dbh, $domain_id, $plan) = @_;
	if ($plan->{remove_all}) {
		$dbh->do("DELETE FROM `secdns` WHERE `domain_id` = ?", undef, $domain_id) or die $dbh->errstr;
	}
	foreach my $ds (@{ $plan->{remove} }) {
		$dbh->do("DELETE FROM `secdns` WHERE `domain_id` = ? AND `keytag` = ? AND `alg` = ? AND `digesttype` = ? AND `digest` = ?",
			undef, $domain_id, $ds->{keyTag}, $ds->{alg}, $ds->{digestType}, $ds->{digest}) or die $dbh->errstr;
	}

	# maxSigLife belongs to the domain, but the table has it on each row
	my $max_sig_life = $plan->{maxSigLife} // $plan->{stored_max_sig_life};
	secdns_store($dbh, $domain_id, $plan->{add}, $max_sig_life);
	if (defined $plan->{maxSigLife}) {
		$dbh->do("UPDATE `secdns` SET `maxsiglife` = ? WHERE `domain_id` = ?", undef, $plan->{maxSigLife}, $domain_id) or die $dbh->errstr;
	}
}

# What _info_domain needs for secDNS:infData, or undef for a domain without DS data
sub secdns_info {
	my ($dbh, $domain_id) = @_;
	my $stored = _stored_ds($dbh, $domain_id);
	return undef unless @$stored;
	my @list;
	foreach my $row (@$stored) {
		my %ds = map { $_ => $row->{$_} } qw(keyTag alg digestType digest);
		if (defined $row->{pubkey}) {
			$ds{keyData} = { flags => $row->{flags}, protocol => $row->{protocol}, alg => $row->{keydata_alg}, pubKey => $row->{pubkey} };
		}
		push @list, \%ds;
	}
	return { maxSigLife => $stored->[0]{maxsiglife}, dsData => \@list };
}

1;
