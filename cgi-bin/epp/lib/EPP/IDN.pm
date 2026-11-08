package EPP::IDN;

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
#	Internationalized domain names, and the EPP IDN extension
#	urn:ietf:params:xml:ns:idn-1.0 on domain objects.
#
#	A-labels are checked as RFC 5891 section 4.2 asks of a
#	registry: the punycode must decode and encode back to the
#	same label, and the U-label must be NFC, lowercase, free of
#	hyphens in the third and fourth position and of a leading
#	combining mark, and made of letters, marks, digits and the
#	hyphen. The IDN table of the registration then limits the
#	code points further. Tables are rows of `idn_table`.
#
#	The domain stores its table in `domain`.`idn_table` and its
#	Unicode name in `domain`.`idn_uname`.
#
#	The parse functions change nothing. They return the parsed
#	data and an error, which is { code, message } or undef.
#
################################################################

use strict;
use warnings;
use feature qw(unicode_strings);
use Exporter 'import';
use Unicode::Normalize qw(NFC);

our @EXPORT = qw(idn_alabel_error idn_parse_create idn_store idn_info);
our @EXPORT_OK = qw(punycode_encode punycode_decode);

use constant NS => 'urn:ietf:params:xml:ns:idn-1.0';

# RFC 3492 section 5
use constant {
	BASE => 36, TMIN => 1, TMAX => 26, SKEW => 38, DAMP => 700,
	INITIAL_BIAS => 72, INITIAL_N => 128, MAXINT => 0x7FFFFFFF,
};

sub _error {
	my ($code, $message) = @_;
	return { code => $code, message => $message };
}

sub _adapt {
	my ($delta, $numpoints, $first) = @_;
	$delta = $first ? int($delta / DAMP) : int($delta / 2);
	$delta += int($delta / $numpoints);
	my $k = 0;
	while ($delta > int(((BASE - TMIN) * TMAX) / 2)) {
		$delta = int($delta / (BASE - TMIN));
		$k += BASE;
	}
	return $k + int(((BASE - TMIN + 1) * $delta) / ($delta + SKEW));
}

sub _threshold {
	my ($k, $bias) = @_;
	return TMIN if $k <= $bias;
	return TMAX if $k >= $bias + TMAX;
	return $k - $bias;
}

sub _digit_value {
	my $c = ord(shift);
	return $c - 48 + 26 if $c >= 48 && $c <= 57;
	return $c - 97 if $c >= 97 && $c <= 122;
	return $c - 65 if $c >= 65 && $c <= 90;
	return undef;
}

sub _digit_char {
	my $d = shift;
	return chr($d < 26 ? $d + 97 : $d - 26 + 48);
}

# The code points of a punycode string, without the ACE prefix, or undef when it does not decode
sub punycode_decode {
	my ($input) = @_;
	my ($n, $i, $bias) = (INITIAL_N, 0, INITIAL_BIAS);
	my @out;
	my $delimiter = rindex($input, "-");
	if ($delimiter >= 0) {
		my $basic = substr($input, 0, $delimiter);
		return undef if $basic =~ /[^\x00-\x7F]/;
		@out = split(//, $basic);
		$input = substr($input, $delimiter + 1);
	}
	my ($pos, $len) = (0, length($input));
	while ($pos < $len) {
		my ($oldi, $w) = ($i, 1);
		for (my $k = BASE; ; $k += BASE) {
			return undef if $pos >= $len;
			my $digit = _digit_value(substr($input, $pos++, 1));
			return undef unless defined $digit;
			return undef if $digit > int((MAXINT - $i) / $w);
			$i += $digit * $w;
			my $t = _threshold($k, $bias);
			last if $digit < $t;
			return undef if $w > int(MAXINT / (BASE - $t));
			$w *= BASE - $t;
		}
		my $count = @out + 1;
		$bias = _adapt($i - $oldi, $count, $oldi == 0);
		return undef if int($i / $count) > MAXINT - $n;
		$n += int($i / $count);
		$i %= $count;
		return undef if $n > 0x10FFFF || ($n >= 0xD800 && $n <= 0xDFFF);
		splice(@out, $i, 0, chr($n));
		$i++;
	}
	return join('', @out);
}

# The punycode of a string, without the ACE prefix
sub punycode_encode {
	my ($input) = @_;
	my @cp = map { ord } split(//, $input);
	my ($n, $delta, $bias) = (INITIAL_N, 0, INITIAL_BIAS);
	my $output = join('', map { chr } grep { $_ < 0x80 } @cp);
	my $basic = length($output);
	my $h = $basic;
	$output .= "-" if $basic > 0;
	while ($h < @cp) {
		my $m = MAXINT;
		foreach (@cp) { $m = $_ if $_ >= $n && $_ < $m; }
		$delta += ($m - $n) * ($h + 1);
		$n = $m;
		foreach my $c (@cp) {
			$delta++ if $c < $n;
			next unless $c == $n;
			my $q = $delta;
			for (my $k = BASE; ; $k += BASE) {
				my $t = _threshold($k, $bias);
				last if $q < $t;
				$output .= _digit_char($t + ($q - $t) % (BASE - $t));
				$q = int(($q - $t) / (BASE - $t));
			}
			$output .= _digit_char($q);
			$bias = _adapt($delta, $h + 1, $h == $basic);
			$delta = 0;
			$h++;
		}
		$delta++;
		$n++;
	}
	return $output;
}

# Why a string is not a U-label, or undef when it is one
sub _ulabel_error {
	my ($u) = @_;
	return 'decodes to ASCII only' unless $u =~ /[^\x00-\x7F]/;
	return 'is not in Unicode NFC' unless NFC($u) eq $u;
	return 'has an uppercase letter' unless lc($u) eq $u;
	return 'has hyphens in the third and fourth position' if substr($u, 2, 2) eq '--';
	return 'begins or ends with a hyphen' if $u =~ /^-|-$/;
	return 'begins with a combining mark' if $u =~ /^\p{M}/;
	if ($u =~ /([^\p{Ll}\p{Lo}\p{Lm}\p{Mn}\p{Mc}\p{Nd}\-])/) {
		return sprintf('has the code point U+%04X, which IDNA does not allow', ord($1));
	}
	return undef;
}

# Why a label of the form xn--* (any case) is not a valid A-label, or undef when it is one
sub idn_alabel_error {
	my $label = lc(shift // '');
	return 'Invalid A-label: it must begin with xn--' unless $label =~ /^xn--(.*)$/;
	my $puny = $1;
	return 'Invalid A-label: longer than 63 characters' if length($label) > 63;
	return 'Invalid A-label: only letters, digits and hyphens are allowed' if $label =~ /[^a-z0-9\-]/;
	my $u = punycode_decode($puny);
	return 'Invalid A-label: the punycode does not decode' unless defined $u;
	if (my $why = _ulabel_error($u)) {
		return "Invalid A-label: the U-label $why";
	}
	return 'Invalid A-label: the punycode is not in its canonical form' unless punycode_encode($u) eq $puny;
	return undef;
}

# The Unicode form of a domain name. Labels that are not A-labels stay as they are, in lowercase.
sub _uname_of {
	my ($name) = @_;
	my @labels;
	foreach my $label (split(/\./, lc($name), -1)) {
		if ($label =~ /^xn--(.*)$/) {
			my $u = punycode_decode($1);
			$label = $u if defined $u;
		}
		push @labels, $label;
	}
	return join('.', @labels);
}

# Code point ranges of a table, as [from, to] pairs, or undef for an unknown table
sub _table_ranges {
	my ($dbh, $tag) = @_;
	my ($codepoints) = $dbh->selectrow_array('SELECT `codepoints` FROM `idn_table` WHERE `tag` = ? LIMIT 1', undef, $tag);
	return undef unless defined $codepoints;
	my @ranges;
	foreach my $item (split(/[\s,]+/, $codepoints)) {
		next unless length($item);
		my ($from, $to) = $item =~ /^(?:U\+)?([0-9A-Fa-f]+)(?:-(?:U\+)?([0-9A-Fa-f]+))?$/ or next;
		push @ranges, [hex($from), hex($to // $from)];
	}
	return \@ranges;
}

sub _trimmed_value {
	my ($xp, $path, $context) = @_;
	my $node = $xp->find($path, $context)->get_node(0);
	return undef unless $node;
	my $value = $node->string_value;
	$value =~ s/^\s+|\s+$//g;
	return $value;
}

# Returns (plan, error) for a domain:create of $name. The plan is { table, uname } for an IDN
# and undef for an ASCII name. $name has passed validate_label.
sub idn_parse_create {
	my ($xp, $extension, $dbh, $name) = @_;
	my $data;
	if ($extension) {
		$xp->set_namespace('idn', NS);
		$data = $xp->find('idn:data', $extension)->get_node(0);
	}
	my ($first) = split(/\./, lc($name));
	if ($first !~ /^xn--/) {
		return (undef, _error(2306, 'idn:data applies to IDN names only')) if $data;
		return (undef, undef);
	}
	return (undef, _error(2003, 'An IDN needs idn:data with idn:table')) unless $data;

	my $tag = _trimmed_value($xp, 'idn:table', $data);
	return (undef, _error(2003, 'Missing idn:table')) unless defined $tag && length($tag);
	my $ranges = _table_ranges($dbh, $tag);
	return (undef, _error(2306, "Unknown idn:table $tag")) unless $ranges;

	my $ulabel = punycode_decode(substr($first, 4));
	foreach my $char (split(//, $ulabel)) {
		my $cp = ord($char);
		unless (grep { $cp >= $_->[0] && $cp <= $_->[1] } @$ranges) {
			return (undef, _error(2306, sprintf('The code point U+%04X is not in the IDN table %s', $cp, $tag)));
		}
	}

	my $derived = _uname_of($name);
	my $uname = _trimmed_value($xp, 'idn:uname', $data);
	if (defined $uname && length($uname)) {
		return (undef, _error(2306, 'idn:uname is not in Unicode NFC')) unless NFC($uname) eq $uname;
		my @given = split(/\./, $uname, -1);
		my @want = split(/\./, $derived, -1);
		my $same = @given == @want;
		for (my $i = 0; $same && $i < @want; $i++) {
			# An ASCII label may differ in case, a U-label may not
			$same = $want[$i] =~ /[^\x00-\x7F]/ ? $given[$i] eq $want[$i] : lc($given[$i]) eq $want[$i];
		}
		return (undef, _error(2306, 'idn:uname does not map to domain:name')) unless $same;
	}
	else {
		$uname = $derived;
	}
	return ({ table => $tag, uname => $uname }, undef);
}

sub idn_store {
	my ($dbh, $domain_id, $plan) = @_;
	$dbh->do('UPDATE `domain` SET `idn_table` = ?, `idn_uname` = ? WHERE `id` = ?', undef, $plan->{table}, $plan->{uname}, $domain_id)
		or die $dbh->errstr;
}

# What _info_domain needs for idn:data, or undef for a domain that is not an IDN
sub idn_info {
	my ($dbh, $domain_id) = @_;
	my ($table, $uname) = $dbh->selectrow_array('SELECT `idn_table`,`idn_uname` FROM `domain` WHERE `id` = ?', undef, $domain_id);
	return undef unless defined $table;
	return { table => $table, uname => $uname };
}

1;
