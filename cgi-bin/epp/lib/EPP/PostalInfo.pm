package EPP::PostalInfo;

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

use strict;
use warnings;

BEGIN {
	use Exporter ();
	our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

	$VERSION = do { my @r = (q$Revision: 1.01 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r};
	@ISA = qw(Exporter);
	@EXPORT = qw($LOC_TEXT $LOC_CITY $LOC_SP);
	@EXPORT_OK = qw();
	%EXPORT_TAGS = (all => \@EXPORT_OK);
}

# Patterns for <contact:postalInfo type="loc">, which RFC 5733 allows to hold UTF-8. They apply to
# the character strings XML::XPath returns, not to bytes. type="int" is limited to ASCII by the
# same RFC, so it keeps its own patterns in the scripts.
#
# There are no minimum lengths: a three letter name is complete in Chinese. The first letter of
# a state is upper case only in the scripts that have one. The columns are utf8, three bytes at
# most, so a character beyond the BMP would be cut off or fail in the INSERT.
my $bmp_only = qr/(?!.*[\x{10000}-\x{10FFFF}])/s;

our $LOC_TEXT = qr/^${bmp_only}[\p{L}\p{M}\p{N}\-\&\,\.\/\s]+$/;
our $LOC_CITY = qr/^${bmp_only}\p{L}[\p{L}\p{M}\-\.\s]*$/;
our $LOC_SP = qr/^${bmp_only}[\p{Lu}\p{Lo}][\p{L}\p{M}\-\.\s]+$/;

1;
