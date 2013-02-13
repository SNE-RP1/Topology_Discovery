#!/usr/bin/perl

# Copyright (C) 2013 Diederik Vandevenne <diederik.vandevenne@os3.nl> & Dennis Pellikaan <dennis.pellikaan@os3.nl>
# (Written by Diederik Vandevenne <diederik.vandevenne@os3.nl> & Dennis Pellikaan <dennis.pellikaan@os3.nl> for University of Amsterdam, the Netherlands)
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

my @devices;			# List of devices
my @interfaces;			# List of interfaces
my @neighbours;			# List of neighbouring relations
my @next_hops;			# List of Next Hops
my $sql;			# SQL handle

my $ipAdEntAddr 		= ".1.3.6.1.2.1.4.20.1.1";	# (RFC1213-MIB (v1)
my $ipAdEntIfIndex		= ".1.3.6.1.2.1.4.20.1.2";	# (RFC1213-MIB (v1)
my $ipAdEntNetmask		= ".1.3.6.1.2.1.4.20.1.3";	# (RFC1213-MIB (v1)
my $ipCidrRouteNextHop		= ".1.3.6.1.2.1.4.24.4.1.4";	# (IP-FORWARD-MIB (v1))
my $ipCidrRouteIfIndex		= ".1.3.6.1.2.1.4.24.4.1.5";	# (IP-FORWARD-MIB (v1))
my $ipCidrRouterType		= ".1.3.6.1.2.1.4.24.4.1.6";	# (IP-FORWARD-MIB (v1))

sub sql_error_handle {
}

# The MIB IP identifier
sub ip_id {
	my $device = shift;

        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ipAdEntIfIndex 2>/dev/null`;

	if ($? != 0) {
		$device->{'Error'} = true;

		return;
	}	

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ipAdEntIfIndex).([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ \=\ INTEGER\: (.*)/;

		if ($1 && $2 && $3) {
			my $IpId = $2;
			my $IfIdx = $3;

			foreach my $interface (@interfaces) {
				if ($device->{'ChassisId'} eq $interface->{'ChassisId'} && $interface->{'IfIdx'} eq $IfIdx) {
					$interface->{'IpId'} = $IpId;

					last;
				}
			}
		}
	}
}

sub ip_address {
	my $device = shift;

        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ipAdEntAddr 2>/dev/null`;

	if ($? != 0) {
		$device->{'Error'} = true;

		return;
	}	

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ipAdEntAddr).([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ \=\ IpAddress\: (.*)/;

		if ($1 && $2 && $3) {
			my $IpId = $2;
			my $Address = $3;

			foreach my $interface (@interfaces) {
				if (!defined ($interface->{'IpId'})) {
					next;
				}

				if ($device->{'ChassisId'} eq $interface->{'ChassisId'} && $interface->{'IpId'} eq $IpId) {
					$interface->{'Address'} = $Address;

					last;
				}
			}
		}	
	}
}

sub ip_netmask {
	my $device = shift;

        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ipAdEntNetmask 2>/dev/null`;

	if ($? != 0) {
		$device->{'Error'} = true;

		return;
	}	

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ipAdEntNetmask).([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ \=\ IpAddress\: (.*)/;

		if ($1 && $2 && $3) {
			my $IpId = $2;
			my $Netmask = $3;

			foreach my $interface (@interfaces) {
				if (!defined ($interface->{'IpId'})) {
					next;
				}

				if ($device->{'ChassisId'} eq $interface->{'ChassisId'} && $interface->{'IpId'} eq $IpId) {
					$interface->{'Netmask'} = $Netmask;

					last;
				}
			}
		}	
	}
}

sub ip_route_if_index {
	my $device = shift;

        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ipCidrRouteIfIndex 2>/dev/null`;

	if ($? != 0) {
		$device->{'Error'} = true;

		return;
	}

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ipCidrRouteIfIndex).([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ \=\ INTEGER\: (.*)/;

		if ($1 && $2 && $3 && $4 && $5) {
			my $IpId = $2;
			my $Netmask = $3;
			my $IfIdx = $5;
			
			foreach my $interface (@interfaces) {
				if ($interface->{'ChassisId'} eq $device->{'ChassisId'} && $interface->{'IfIdx'} eq $IfIdx) {
					my $next_hop = {'ChassisId' => $device->{'ChassisId'}, 'IpId' => $IpId, 'Netmask' => $Netmask, 'IfIdx' => $IfIdx};
					push @next_hops, $next_hop;
					
					last;
				}	
			}

		}
	}
}

sub ip_next_hop {
	my $device = shift;

        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ipCidrRouteNextHop 2>/dev/null`;

	if ($? != 0) {
		$device->{'Error'} = true;

		return;
	}

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ipCidrRouteNextHop).([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ \=\ IpAddress\: (.*)/;

		if ($1 && $2 && $3 && $4 && $5) {
			my $IpId = $2;
			my $NextHop = $5;
			my $IfId;

			# Find IfId based on IP address
			foreach my $interface (@interfaces) {
				if (!defined ($interface->{'IpId'})) {
					next;
				}
	
				if ($interface->{'Address'} eq $NextHop) {
					$IfId = $interface->{'IfId'};

					last;
				}
			}

			if (!$IfId) {
				next;
			}
		
			# Find corresponding mib id of next_hop
			foreach my $next_hop (@next_hops) {
				# Filter for Remote route types only
				if ($next_hop->{'RouteType'} != 4) {
					next;
				}

				if ($next_hop->{'ChassisId'} eq $device->{'ChassisId'} && $next_hop->{'IpId'} eq $IpId) {
					$next_hop->{'IfId'} = $IfId;
					$next_hop->{'Address'} = $NextHop;
				}
			}

		}
	}
}

sub ip_route_type {
	my $device = shift;

        if ($device->{'Error'} == true) {
                return;
        }

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ipCidrRouterType 2>/dev/null`;

	if ($? != 0) {
		$device->{'Error'} = true;

		return;
	}

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ipCidrRouterType).([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\ \=\ INTEGER: (.*)/;

		if ($1 && $2 && $3 && $4 && $5) {
			my $IpId = $2;
			my $RouteType = $5;

			foreach my $next_hop (@next_hops) {
				if ($next_hop->{'ChassisId'} eq $device->{'ChassisId'} && $next_hop->{'IpId'} eq $IpId) {
					$next_hop->{'RouteType'} = $RouteType;

					last;
				}
			}
		}
	}
}

sub loop_devices {
	my $query;
	my $sql_sth;
	
	# Select all LLDP devices and the corresponding SNMP information
	$query = sprintf ("SELECT lldpDevice.ChassisId, lldpDevice.Address, lldpDevice.SNMPVersion, lldpDevice.Community, lldpLocPort.LocPortId, Interface.IfId, Interface.Index FROM Interface INNER JOIN lldpLocPort ON lldpLocPort.LocChassisId=Interface.LocChassisId AND lldpLocPort.LocPortId=Interface.LocPortId INNER JOIN lldpDevice ON lldpDevice.ChassisId=lldpLocPort.LocChassisId WHERE lldpDevice.Scanned=1 AND lldpDevice.Error=0 AND lldpDevice.HasLLDP=1 AND lldpDevice.IPForwarding=1");
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $ChassisId, my $Address, my $SNMPVersion, my $Community, my $LocPortId, my $IfId, my $IfIdx) = $sql_sth->fetchrow_array()) {
		my $device = {'ChassisId' => $ChassisId, 'Address' => $Address, 'LocPortId' => $LocPortId, 'IfId' => $IfId, 'IfIdx' => $IfIdx, 'Community' => $Community, 'SNMPVersion' => $SNMPVersion};
	
		# Create a new device if it doesn't exists yet
		my $device_exists = false;
		foreach my $device (@devices) {
			if ($device->{'ChassisId'} eq $ChassisId) {
				$device_exists = true;

				last;
			}
		}
		if (!$device_exists) {
			my $device = {'ChassisId' => $ChassisId, 'Address' => $Address, 'Community' => $Community, 'SNMPVersion' => $SNMPVersion, 'Error' => false};
			push @devices, $device;
		}

		# Add the interface
		my $interface = {'ChassisId' => $ChassisId, 'LocPortId' => $LocPortId, 'IfId' => $IfId, 'IfIdx' => $IfIdx};
		push @interfaces, $interface;
	}

	# Loop through device to get local information
	foreach my $device (@devices) {
		printf ("Scanning IP: %s\n", $device->{'Address'});
		ip_id ($device);
		ip_address ($device);
		ip_netmask ($device);
	}

	# Loop through devices to get next hop information
	foreach my $device (@devices) {
		printf ("Scanning IP: %s\n", $device->{'Address'});
		ip_route_if_index ($device);
		ip_route_type ($device);
		ip_next_hop ($device);
	}
}

sub main {
	# Connect to the database
	$sql = DBI->connect ('dbi:mysql:dbname=topo;host=127.0.0.1','username','password', {'RaiseError' => 0, 'PrintError' => 1, 'HandleError' => \&sql_error_handle}) || die ("ERROR: Couldn't connect to the database");

	# Truncate ipAddress and ipNextHop tables
	$sql->do ('SET FOREIGN_KEY_CHECKS = 0');
	$sql->do ('TRUNCATE TABLE ipNeighbour');
	$sql->do ('TRUNCATE TABLE ipAddress');
	$sql->do ('TRUNCATE TABLE ipNextHop');
	$sql->do ('SET FOREIGN_KEY_CHECKS = 1');
	
	# Scan all layer three devices for IP and IP next hop information
	loop_devices ();

	# Insert local interface
	foreach my $interface (@interfaces) {
		my $query;

		if (!defined ($interface->{'IpId'})) {
			next;
		}

		$query = sprintf ("INSERT INTO ipAddress (IfId, Address, Netmask) VALUES ('%s', '%s', '%s')",
			$interface->{'IfId'},
			$interface->{'Address'},
			$interface->{'Netmask'});
		$sql->do ($query);
	}
		
	foreach my $next_hop (@next_hops) {
		my $query;

		# Filter out only Remote types	
		if ($next_hop->{'RouteType'} != 4) {
			next;
		}

		$query = sprintf ("INSERT INTO ipNextHop VALUES ('%s', '%s')",
			$next_hop->{'IfId'},
			$next_hop->{'Address'});
		$sql->do ($query);

		foreach my $interface (@interfaces) {
			if ($next_hop->{'ChassisId'} eq $interface->{'ChassisId'} && $next_hop->{'IfIdx'} eq $interface->{'IfIdx'}) {
				my $LocIfId = $interface->{'IfId'};
				my $LocIfAddress = $interface->{'Address'};
				my $RemIfId = $next_hop->{'IfId'};
				my $RemIfAddress = $next_hop->{'Address'};

				$query = sprintf ("INSERT INTO ipNeighbour VALUES ('%s', '%s', '%s', '%s')",
					$LocIfId,
					$LocIfAddress,
					$RemIfId,
					$RemIfAddress);
				$sql->do ($query);
			}
		}	

	}
}

main ();

