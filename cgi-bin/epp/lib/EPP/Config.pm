package EPP::Config;

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

use vars qw(%c);

my $file = '/etc/registry/registry.conf';
open(CONFIG, $file) or die "can't open $file: $!";
	my @conf = <CONFIG>;
close CONFIG;

%c = map {
	s/#.*//;
	s/^\s+//;
	s/\s+$//;
	m/(.*?)\s*=\s*(.*)/;
} @conf;

# RFC 3915 grace periods in minutes, read by command-delete.cgi and change-domain-status.pl.
# Upstream's fixed values apply when registry.conf has none or a value that is not a number.
my %rgp_defaults = (
	rgp_add_period_minutes => 7200,         # 5 days
	rgp_renew_period_minutes => 7200,       # 5 days
	rgp_transfer_period_minutes => 7200,    # 5 days
	rgp_auto_renew_period_minutes => 64800, # 45 days
	rgp_expiry_grace_minutes => 43200,      # 30 days after expiry before an unrenewed domain goes to redemptionPeriod
	rgp_redemption_period_minutes => 43200, # 30 days
	rgp_pending_restore_minutes => 10080,   # 7 days
	rgp_pending_delete_minutes => 7200,     # 5 days
);
foreach my $key (keys %rgp_defaults) {
	$c{$key} = $rgp_defaults{$key} unless defined $c{$key} && $c{$key} =~ /^\d+$/;
}

1;


# End.