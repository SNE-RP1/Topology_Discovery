#!/usr/bin/perl

# Copyright (C) 2013 Dennis Pellikaan <dennis.pellikaan@os3.nl> & Diederik Vandevenne <diederik.vandevenne@os3.nl>
# (Written by Dennis Pellikaan <dennis.pellikaan@os3.nl> for University of Amsterdam, the Netherlands)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

use strict;
use warnings;
use DBI;

use constant true => 1;
use constant false => 0;

my @devices;                    # List of detected devices
my @interfaces;			# STP port states referenced by interface index
my @states;			# STP port states referenced by stp (mib) index
my $sql;                        # SQL handle

# 1.3.6.1.2.1.17.2.15.1.3 	stp link state
# 1.3.6.1.2.1.31.1.1.1.1 	map portid to iface index

my $stpPortState 		= ".1.3.6.1.2.1.17.2.15.1.3";	# Port state related to stpId
my $stpDesignatedRoot		= ".1.3.6.1.2.1.17.2.5.0";	# Designated Root
my $ifIdx			= ".1.3.6.1.2.1.17.1.4.1.2";	# Interface index related to stpId
my $ifName			= ".1.3.6.1.2.1.31.1.1.1.1";	# Global Port Id related to Interface index
my $ifDesc			= ".1.3.6.1.2.1.2.2.1.2";	# Local interface description

sub sql_error_handle {

}

sub stp_state {
	my $device = shift;
 
        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $stpPortState 2>/dev/null`;

	if ($? != 0) {
		printf ("Error\n");
		return;
	}

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($stpPortState).*\.([0-9]+)\ \=\ INTEGER\: ([0-9])/;
		
		if ($1 && $2 && $3) {
			# Skip disabled ports
			if ($3 == 1) {
				next;
			}

			my $state = {'ChassisId' => $device->{'ChassisId'}, 'StpId' => $2, 'State' => $3};
			push @states, $state;
		}
	}
}

sub stp_designated_root {
	my $device = shift;

        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $stpDesignatedRoot 2>/dev/null`;

	if ($? != 0) {
		printf ("Error\n");
		return;
	}

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($stpDesignatedRoot)\ \=\ Hex-STRING\:\ [0-9A-Z]{2}\ [0-9A-Z]{2}\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})/;
		
		if ($1 && $2 && $3 && $4 && $5 && $6 && $7) {
			my $root = sprintf ("%s-%s-%s-%s-%s-%s", $2, $3, $4, $5, $6, $7);

			foreach my $interface (@interfaces) {
				# TODO: check
				if ($interface->{'ChassisId'} eq $root) {
					$interface->{'DesignatedRoot'} = true;
				}
			}
		}
	}

}

sub get_ifidx {
	my $device = shift;

        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ifIdx 2>/dev/null`;

	if ($? != 0) {
		printf ("Error\n");
		return;
	}

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ifIdx)\.([0-9]+)\ \=\ INTEGER\: ([0-9]+)/;

		if ($1 && $2 && $3) {
			foreach my $state (@states) {
				if ($device->{'ChassisId'} eq $state->{'ChassisId'} && $2 eq $state->{'StpId'}) {
					$state->{'ifIdx'} = $3;

					last;
				}
			}
		}
	}
}

sub map_stpidx_to_ifidx {
	foreach my $state (@states) {
		foreach my $interface (@interfaces) {
			if ($state->{'ChassisId'} eq $interface->{'ChassisId'} && $state->{'ifIdx'} eq $interface->{'ifIdx'}) {
				$interface->{'State'} = $state->{'State'};

				last;
			}
		}
	}
}

sub loop_devices {
	my $query;
	my $sql_sth;

	# Select all devices that have one or more local ports
	$query = sprintf ("SELECT lldpDevice.ChassisId, lldpDevice.Address, lldpDevice.SNMPVersion, lldpDevice.Community, Interface.IfId, Interface.Index FROM lldpDevice INNER JOIN Interface ON lldpDevice.ChassisId = Interface.LocChassisId WHERE lldpDevice.Scanned = 1 AND lldpDevice.Error = 0 AND lldpDevice.HasLLDP = 1");
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();

	while ((my $ChassisId, my $Address, my $SNMPVersion, my $Community, my $ifId, my $IfIdx) = $sql_sth->fetchrow_array()) {
		my $interface = {'ChassisId' => $ChassisId, 'ifId' => $ifId, 'ifIdx' => $IfIdx};
		push @interfaces, $interface;

		my $dev_exists = false;
		foreach my $device (@devices) {
			if ($device->{'ChassisId'} eq $ChassisId) {
				$dev_exists = true;
			}
		}

		if (!$dev_exists) {
			my $device = {'ChassisId' => $ChassisId, 'Address' => $Address, 'Community' => $Community, 'SNMPVersion' => $SNMPVersion, 'Error' => false};

			push @devices, $device;
		}
	}

	foreach my $device (@devices) {
		printf ("Scanning STP: %s\n", $device->{'Address'});

		stp_state ($device);
		get_ifidx ($device);
		stp_designated_root ($device);
	}

	map_stpidx_to_ifidx ();
}

sub main {
	# Connect to the database
	$sql = DBI->connect ('dbi:mysql:dbname=topo;host=127.0.0.1','username','password', {'RaiseError' => 0, 'PrintError' => 1, 'HandleError' => \&sql_error_handle}) || die ("ERROR: Couldn't connect to the database");

	# TRUNCATE STP tables
	$sql->do ('TRUNCATE TABLE stpState');

	# Scan all devices
	loop_devices ();

	# Insert the port states into the database
	foreach my $interface (@interfaces) {
		if (defined ($interface->{'State'})) {
			my $DesignatedRoot = false;

			if (defined ($interface->{'DesignatedRoot'})) {
				$DesignatedRoot = $interface->{'DesignatedRoot'};
			}

			my $query = sprintf ("INSERT INTO stpState (IfId, State, DesignatedRoot) VALUES ('%s', '%s', '%s')",
				$interface->{'ifId'},
				$interface->{'State'},
				$DesignatedRoot);
			$sql->do ($query);
		}
	}
}

main ();
