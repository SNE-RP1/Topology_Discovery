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

# LLDP OIDs
my $ifIdx			= ".1.3.6.1.2.1.2.2.1.1";
my $ifName                      = ".1.3.6.1.2.1.31.1.1.1.1";
my $ipForwarding		= ".1.3.6.1.2.1.4.1.0";
my $ifPhysAddress		= ".1.3.6.1.2.1.2.2.1.6";
my $lldpLocChassisId		= ".1.0.8802.1.1.2.1.3.2.0";
my $lldpLocSysName		= ".1.0.8802.1.1.2.1.3.3.0";
my $lldpLocSysDesc		= ".1.0.8802.1.1.2.1.3.4.0";
my $lldpLocPortId		= ".1.0.8802.1.1.2.1.3.7.1.3";
my $lldpLocPortDesc		= ".1.0.8802.1.1.2.1.3.7.1.4";
my $lldpLocSysCapEnabled	= ".1.0.8802.1.1.2.1.3.6.0";
my $lldpRemPortId		= ".1.0.8802.1.1.2.1.4.1.1.7";
my $lldpRemPortDesc		= ".1.0.8802.1.1.2.1.4.1.1.8";
my $lldpRemChassisId		= ".1.0.8802.1.1.2.1.4.1.1.5";
my $lldpRemManAddr		= ".1.0.8802.1.1.2.1.4.2.1.4";

my @devices;			# List of detected devices
my @ports;			# List of connected local ports to remote ports
my @neighbours;			# List of connected local ports to remote chassis is (devices)
my @mgmts;			# List of management ips
my @ips;			# List of ips, which are allowed to scan
my $sql;			# SQL handle 
my $check_ips = true;		# true = check list of allowed ips
my $DefaultSNMPVersion=1;
my $DefaultCommunity='public';

sub sql_error_handle {
	
}

sub trim {
	my $str = shift;

	$str =~ s/^\s+//;
	$str =~ s/\s+$//;

	return $str;
}

# Get IPForwarding information. This is part of the RFC1213
sub ip_forwarding {
	my $device = shift;

	if ($device->{'Error'} == true) {
		return;
	}

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ipForwarding 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
	 	$line =~ m/^($ipForwarding)\ \=\ INTEGER\: ([0-9]+)/;

		if ($1 && $2) {
			$device->{'ipForwarding'} = $2;
		}
	}
}

# Get local port information
sub local_port_information {
	my $device = shift;

	if ($device->{'Error'} == true) {
		return;
	}

	# Local port id
	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpLocPortId 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
	 	$line =~ m/^($lldpLocPortId)\.([0-9]+).*(STRING\:\ \"(.*)\"|Hex-STRING\:\ (.*))/;

		if ($1 && $2 && $3) {
			my $LocPortId;
			my $LocPortIdx = $2;

			$LocPortId = trim($4) if $4;
			$LocPortId = trim($5) if $5;

			foreach my $port (@ports) {
				if ($port->{'LocChassisId'} eq $device->{'ChassisId'} && $port->{'LocPortIdx'} eq $LocPortIdx) {
					$port->{'LocPortId'} = $LocPortId;

					last;
				}
			}
		}
	}


	# Local port description
	@output = `snmpwalk -On -Oe -Ih -PR -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpLocPortDesc 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($lldpLocPortDesc)\.([0-9]+).*(STRING\:\ \"(.*)\"|Hex-STRING\:\ (.*))/;

		if ($1) {
			my $desc;
			my $LocPortIdx = $2;

			$desc = trim($3) if $3;
			$desc = trim($4) if $4;

			foreach my $port (@ports) {
				if ($port->{'LocChassisId'} eq $device->{'ChassisId'} && $port->{'LocPortIdx'} eq $LocPortIdx) {
					$port->{'LocPortDesc'} = $desc;

					last;
				}
			}
		}
	}
}

# Get interface index based on local port id
sub local_iface_index {
	my $device = shift;
	my $match = false;

	if ($device->{'Error'} == true) {
		return
	}

	# First check if LocPortId matches with the physical address of the interface
	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ifPhysAddress 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}	
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ifPhysAddress)\.([0-9]+)\ \=\ Hex-STRING\:\ (.*)/;
		if ($1 && $2 && $3) {
			my $ifIdx = $2;
			my $ifPhysAddress = trim($3);

			foreach my $port (@ports) {
				if ($device->{'ChassisId'} eq $port->{'LocChassisId'} && $port->{'LocPortId'} eq $ifPhysAddress) {
					$port->{'ifIdx'} = $ifIdx;
					$match = true;
					last;
				}
			}
		}
	}

	if ($match) {
		return;
	}

	# Secondly, check if the LocPortId matches with the interface name
	@output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ifName 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ifName)\.([0-9]+)\ \=\ STRING\: \"(.*)\"/;
		if ($1 && $2 && $3) {
			my $ifIdx = $2;
			my $ifName = trim($3);

			foreach my $port (@ports) {
				if ($device->{'ChassisId'} eq $port->{'LocChassisId'} && $port->{'LocPortId'} eq $ifName) {
					$port->{'ifIdx'} = $ifIdx;
					$match = true;
					last;
				}
			}
		}
	}

	if ($match) {
		return;
	}

	# Thirdly, check if the LocPortId matches with the interface index
	@output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $ifIdx 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($ifIdx)\.([0-9]+)\ \=\ INTEGER\: (.*)/;
		if ($1 && $2 && $3) {
			my $ifIdx = $2;
			my $ifIdxInt = $3;

			foreach my $port (@ports) {
				if ($device->{'ChassisId'} eq $port->{'LocChassisId'} && $port->{'LocPortId'} eq $ifIdxInt) {
					$port->{'ifIdx'} = $ifIdxInt;
					last;
				}
			}
		}
	}
}

# Get remote management addressess
sub remote_mgmt_addresses {
	my $device = shift;

	if ($device->{'Error'} == true) {
		return;
	}

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpRemManAddr 2>/dev/null`;

	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^$lldpRemManAddr\.[0-9]+\.([0-9]+)\.(.*)\.([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\ \=/;
		if ($1 && $3) {
			my $LocPortIdx = $1;
			my $address = trim($3);

			foreach my $neighbour (@neighbours) {
				if (($neighbour->{'LocChassisId'} eq $device->{'ChassisId'}) && ($neighbour->{'LocPortIdx'} eq $LocPortIdx)) {
					my $mgmt = {'LocChassisId' => $device->{'ChassisId'}, 'LocPortIdx' => $LocPortIdx, 'RemChassisId' => $neighbour->{'RemChassisId'}, 'Address' => $address};
					push @mgmts, $mgmt;

					last;
				}
			}
		}
	}
}

# Get remote chassis ids
sub remote_chassis_ids {
	my $device = shift;

	if ($device->{'Error'} == true) {
		return;
	}

	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpRemChassisId 2>/dev/null`;

	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}

	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($lldpRemChassisId)\.[0-9]+\.([0-9]+).*Hex-STRING\:\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})/;

		if ($2) {
			my $LocPortId;
			my $LocPortIdx = $2;
			my $RemChassisId = sprintf ("%s-%s-%s-%s-%s-%s", $3, $4, $5, $6, $7, $8);
		
			# Lookup LocPortId
			foreach my $port (@ports) {
				if ($port->{'LocChassisId'} eq $device->{'ChassisId'} && $port->{'LocPortIdx'} eq $LocPortIdx) {
					$LocPortId = $port->{'LocPortId'};
					last;
				}
			}

			my $neighbour = {'LocChassisId' => $device->{'ChassisId'}, 'LocPortIdx' => $LocPortIdx, 'RemChassisId' => $RemChassisId, 'LocPortId' => $LocPortId};
			push @neighbours, $neighbour;
		}
	}	
}

# Get remote port ids
sub remote_ports {
	my $device = shift;

	if ($device->{'Error'} == true) {
		return;
	}

	# Get PortIDs
	my @output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpRemPortId 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^$lldpRemPortId(.*)/;
		
		# TODO: No Such Instance currently exists at this OID
		if ($1) {
			my $t = $1;

			$t =~ m/^\.[0-9]+\.([0-9]+).*(STRING\:\ \"(.*)\"|Hex-STRING\:\ (.*))/;
			my $LocPortIdx = $1;
			my $RemPortId;

			$RemPortId = trim($3) if $3;
			$RemPortId = trim($4) if $4;

			if ($LocPortIdx && $RemPortId) {
				my $new_port = {'LocChassisId' => $device->{'ChassisId'}, 'LocPortIdx' => $LocPortIdx, 'RemPortId' => $RemPortId};

				# Check if LocPort exists
				my $port_exists = false;
				foreach my $port (@ports) {
					if ($port->{'LocChassisId'} eq  $new_port->{'LocChassisId'} && $port->{'LocPortIdx'} eq $new_port->{'LocPortIdx'}) {
						$port_exists = true;
					}
				}

				if (!$port_exists) {
					push @ports, $new_port;
				}
			}
		}
	}

	# Get PortDesc
	@output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpRemPortDesc 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($lldpRemPortDesc)\.[0-9]+\.([0-9]+)\..*(STRING\:\ \"(.*)\"|Hex-STRING\:\ (.*))/;
		if ($1) {
			my $LocPortIdx = $2;
			my $desc;

			$desc = trim($4) if $4;
			$desc = trim($5) if $5;

			if ($LocPortIdx && $desc) {
				foreach my $port (@ports) {
					if ($port->{'LocChassisId'} eq $device->{'ChassisId'} && $port->{'LocPortIdx'} eq $LocPortIdx) {
						$port->{'RemPortDesc'} =  trim($desc);

						last;
					}
				}
			}	
		}
	}
}

# Get local system data
sub system_data {
	my $device = shift;
	my @output;

	if ($device->{'Error'} == true) {
		return;
	}

	# Get Chassis ID
	@output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpLocChassisId 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($lldpLocChassisId).*Hex-STRING:\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})/;
		if ($1 && $2 && $3 && $4 && $5 && $6 && $7) {
			$device->{'HasLLDP'} = true;

			if ($2 && $3 && $4 && $5 && $6) {
				$device->{'ChassisId'} = sprintf ("%s-%s-%s-%s-%s-%s", $2, $3, $4, $5, $6, $7);
			} else {
				$device->{'Error'} = true;
				return;
			}
		} else {
			$device->{'HasLLDP'} = false;
		}
	}

	# Get system name
	@output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpLocSysName 2>/dev/null`;	
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($lldpLocSysName)\ \=\ STRING\:\ \"(.*)\"/;

		if ($1) {
			$device->{'SysName'} = trim($2);
		}
	}

	# Get system description
	@output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpLocSysDesc 2>/dev/null`;	

	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($lldpLocSysDesc)\ \=\ STRING\:\ \"(.*)\"/;

		if ($1 && $2) {
			$device->{'SysDesc'} = trim($2);
		}
	}

	# Get system capabilities
	@output = `snmpwalk -On -Oe -PR -Ih -v $device->{'SNMPVersion'} -c $device->{'Community'} $device->{'Address'} $lldpLocSysCapEnabled 2>/dev/null`;
	if ($? != 0) {
		$device->{'Error'} = true;
		return;
	}
	chomp (@output);
	foreach my $line (@output) {
		$line =~ m/^($lldpLocSysCapEnabled)\ \=\ STRING\:\ \"(.*)\"/;

		if ($1 && $2) {
			$device->{'SysCapEnabled'} = trim($2);
		}
	}
}

# Recursively loop through devices and its neighbouring devices
sub loop_devices {
	my $device = shift;

	# if check for ip 
	if ($check_ips) {
		my $found = false;

		foreach my $ip (@ips) {
			if ($device->{'Address'} eq $ip->{'Address'}) {
				if ($ip->{'Community'}) {
					$device->{'Community'} = $ip->{'Community'};
				}

				if ($ip->{'SNMPVersion'}) {
					$device->{'SNMPVersion'} = $ip->{'SNMPVersion'};
				}

				$found = true;

				last;
			}
		}

		if ($found == false) {
			$device->{'Error'} = true;

			return;
		}
	}

	printf ("Scanning LLDP: %s\n", $device->{'Address'});

	$device->{'Scanned'} = true;

	# Get SNMP data
	system_data ($device);
	ip_forwarding ($device);
	remote_ports ($device);
	local_port_information ($device);
	local_iface_index ($device);
	remote_chassis_ids ($device);
	remote_mgmt_addresses ($device);
	
	if ($device->{'Error'} == true) {
		return;
	}

	foreach my $neighbour (@neighbours) {
		my $found = false;

		# Check if the neighbour device already exists
		foreach my $dev (@devices) {
			if (!defined ($dev->{'ChassisId'}) || !defined ($neighbour->{'RemChassisId'})) {
				next;
			}

			if ($dev->{'ChassisId'} eq $neighbour->{'RemChassisId'}) {
				$found = true;

				last;
			}
		}
		
		if ($found == false) {
			my $mgmt_address = '';

			# Lookup management address
			foreach my $mgmt (@mgmts) {
				if ($neighbour->{'RemChassisId'} eq $mgmt->{'RemChassisId'}) {
					$mgmt_address = $mgmt->{'Address'};					

					last;
				}
			}

			my $new_device = {'ChassisId' => $neighbour->{'RemChassisId'}, 'Address' => $mgmt_address, 'SNMPVersion' => $DefaultSNMPVersion, 'Community' => $DefaultCommunity, 'Scanned' => false, 'Error' => false};

			# Check if new device already exists
			my $found2 = false;
			foreach my $dev (@devices) {
				if (!defined ($dev->{'ChassisId'})) {
					next;
				}

				if ($dev->{'ChassisId'} eq $new_device->{'ChassisId'}) {
					$found2 = true;
				}
			}

			if ($found2 == false) {
				push @devices, $new_device;
			}
	
			# Do a recursive lookup of neighbours
			loop_devices ($new_device);		
		}
	}
}

sub create_root {
	my $ChassisId;
	my $address;
	my $community;
	my $version;

	$address = "192.168.1.1";
	$community = "public";
	$version = "2c";

	my $root = {'Address' => $address, 'SNMPVersion' => $version, 'Community' => $community, 'Scanned' => false, 'Error' => false};
	push @devices, $root;

	# Loop through all devices
	loop_devices ($root);
}

# If listed ips is used, then scan all ips which are scanned.
sub loop_unscanned_ips {
	# Loop through list of unscanned ips
	if ($check_ips) {
		# Loop through all ips in the list
		foreach my $ip (@ips) {
			my $ip_exists = false;

			# Check if listed ip has been detected
			foreach my $device (@devices) {
				if ($device->{'Address'} eq $ip->{'Address'}) {
					$ip_exists = true;

					last;
				}
			}

			if (!$ip_exists) {
				my $new_device = {'Address' => $ip->{'Address'}, 'SNMPVersion' => $ip->{'SNMPVersion'}, 'Community' => $ip->{'Community'}, 'Scanned' => false, 'Error' => false};

				# Get ChassisId to see if it already exists
				my @output = `snmpwalk -On -Oe -PR -Ih -v $new_device->{'SNMPVersion'} -c $new_device->{'Community'} $new_device->{'Address'} $lldpLocChassisId 2>/dev/null`;

				if ($? != 0) {
					$new_device->{'Error'} = true;
				} else {
					chomp (@output);
					foreach my $line (@output) {
						$line =~ m/^($lldpLocChassisId).*Hex-STRING:\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})\ ([0-9A-Z]{2})/;
						if ($1 && $2 && $3 && $4 && $5 && $6 && $7) {
							$new_device->{'HasLLDP'} = true;
	
							$new_device->{'ChassisId'} = sprintf ("%s-%s-%s-%s-%s-%s", $2, $3, $4, $5, $6, $7);
						} else {
							$new_device->{'HasLLDP'} = false;
						}
					}
				}

				if ($new_device->{'Error'} == true || $new_device->{'HasLLDP'} == false) {
					$new_device->{'Scanned'} = true;

					push @devices, $new_device;

					next;
				}					

				my $dev_exists = false;
				foreach my $dev (@devices) {
					if (!defined ($dev->{'ChassisId'})) {
						next;
					}

					if ("$dev->{'ChassisId'}" eq "") {
						next;
					}

					if ($dev->{'ChassisId'} eq $new_device->{'ChassisId'}) {
						$dev_exists = true;
						$dev->{'Address'} = $ip->{'Address'};
						$dev->{'Community'} = $ip->{'Community'};
						$dev->{'SNMPVersion'} = $ip->{'SNMPVersion'};
						$dev->{'Scanned'} = false;
						$dev->{'Error'} = false;

						loop_devices ($dev);		

						last;
					}
				}	

				if ($dev_exists == false) {
					push @devices, $new_device;

					loop_devices ($new_device);
				}
			}
		}
	}
}

sub padding {
	my $string = "";
	my $len;
	my $direction;

	if (defined ($_[0])) {
		$string = $_[0];
		$len = $_[1];
		$direction = $_[2];
	} else {
		$len = $_[1];
		$direction = $_[2];
	}

        if (length($string) > $len) {
                return substr($string, 0, ($len - 2)) . "...";
        }

        my $filling = "";
        for (my $i = length($string); $i<=$len; $i++) {
                $filling = $filling . ' ';
        }
        if ($direction eq 'l') {
                return $string . $filling;
        } else {
                return $filling . $string;
        }
}

sub print_neighbours {
	my $query = sprintf ("select LocDevice.SysName, lldpNeighbour.LocChassisId, LocDevice.Address, lldpLocPort.LocPortDesc, RemDevice.SysName, lldpNeighbour.RemChassisId, RemDevice.Address, lldpRemPort.RemPortDesc FROM lldpNeighbour INNER JOIN lldpDevice AS LocDevice ON LocDevice.ChassisId = LocChassisId INNER JOIN lldpDevice AS RemDevice ON RemDevice.ChassisId = lldpNeighbour.RemChassisId INNER JOIN lldpRemPort ON lldpNeighbour.RemChassisId = lldpRemPort.RemChassisId AND lldpNeighbour.RemPortId = lldpRemPort.RemPortId INNER JOIN lldpLocPort ON lldpNeighbour.LocChassisId = lldpLocPort.LocChassisId AND lldpNeighbour.LocPortId = lldpLocPort.LocPortId");
	my $sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();

	print (padding ("Nr", 3, 'r'));
	print (" ");
	print (padding ("Local system name", 35, 'l'));
	print (padding ("Local chassis id", 20, 'l'));
	print (padding ("Local address", 18, 'l'));
	print (padding ("Local port", 12, 'l'));
	print ("      ");
	print (padding ("Remote system name", 35, 'l'));
	print (padding ("Remote chassis id", 20, 'l'));
	print (padding ("Remote address", 18, 'l'));
	print (padding ("Remote port", 12, 'l'));
	print ("\n");

	my $i=1;
	while ((my $LocSysName, my $LocChassisId, my $LocAddress, my $LocPortId, my $RemSysName, my $RemChassisId, my $RemAddress, my $RemPortDesc) = $sql_sth->fetchrow_array()) {
		print (padding ($i, 3, 'r'));
		print (" ");
		print (padding ($LocSysName, 35, 'l'));
		print (padding ($LocChassisId, 20, 'l'));
		print (padding ($LocAddress, 18, 'l'));
		print (padding ($LocPortId, 12, 'l'));
		print ("  ->  ");
		print (padding ($RemSysName, 35, 'l'));
		print (padding ($RemChassisId, 20, 'l'));
		print (padding ($RemAddress, 18, 'l'));
		print (padding ($RemPortDesc, 12, 'l'));
		print ("\n");

		$i++;
	}
	print ("\n");
}

sub print_problems {
	print (padding ("Nr", 3, 'r'));
	print (" ");
	print (padding ("System name", 35, 'l'));
	print (padding ("Address", 20, 'l'));
	print (padding ("Community", 20, 'l'));
	print (padding ("Chassis id", 20, 'l'));
	print (padding ("Scanned", 10, 'r'));
	print (padding ("Error", 10, 'r'));
	print (padding ("HasLLDP", 10, 'r'));
	print ("\n");

	my $i=1;
	foreach my $device (@devices) {
		if ($device->{'Error'} == true || $device->{'HasLLDP'} == false) {
			print (padding ($i, 3, 'r'));
			print (" ");
			print (padding ($device->{'SysName'}, 35, 'l'));
			print (padding ($device->{'Address'}, 20, 'l'));
			print (padding ($device->{'Community'}, 20, 'l'));
			print (padding ($device->{'ChassisId'}, 20, 'l'));
			print (padding ($device->{'Scanned'}, 10, 'r'));
			print (padding ($device->{'Error'}, 10, 'r'));
			print (padding ($device->{'HasLLDP'}, 10, 'r'));
			print ("\n");
		
			$i++;
		}
	}
	print ("\n");
}

sub read_snmp_ips {
	my $infile = shift;

	open INPUT, "<", "$infile" or die $!;
	while (<INPUT>) {
		my @line = split(',', $_);

		chomp ($line[2]);
		my $ip = {'Address' => $line[0], 'SNMPVersion' => $line[1], 'Community' => $line[2]};
		push @ips, $ip;
	}
	close INPUT;
}

sub main {
	read_snmp_ips ("ips.csv");

	# Connect to the database
	$sql = DBI->connect ('dbi:mysql:dbname=topo;host=127.0.0.1','username','password', {'RaiseError' => 0, 'PrintError' => 1, 'HandleError' => \&sql_error_handle}) || die ("ERROR: Couldn't connect to the database");

	# Truncate the ndp tables
	$sql->do ('SET FOREIGN_KEY_CHECKS = 0');
	$sql->do ('TRUNCATE TABLE lldpNeighbour');
	$sql->do ('TRUNCATE TABLE lldpRemPort');
	$sql->do ('TRUNCATE TABLE lldpLocPort');
	$sql->do ('TRUNCATE TABLE lldpDevice');
	$sql->do ('TRUNCATE TABLE Interface');
	$sql->do ('SET FOREIGN_KEY_CHECKS = 1');

	# Initiate root device
	create_root ();

	# Loop unscanned ips
	loop_unscanned_ips ();

	# Insert devices into the database
	my $i = 0;
	foreach my $device (@devices) {
		my $ChassisId = "";
		my $Address = "";
		my $SysName = "";
		my $SysDesc = "";
		my $Community = "";
		my $SNMPVersion = "";
		my $SysCapEnabled = "";
		my $HasLLDP = "";
		my $ipForwarding = "";

		if (!defined ($device->{'ChassisId'})) {
			$i++;
			$ChassisId = sprintf ("UNKNOWN (SEQ: %s)", $i);
		} else {
			$ChassisId = $device->{'ChassisId'};
		}

		if (defined ($device->{'Address'})) {
			$Address = $device->{'Address'};
		}

		if (defined ($device->{'SysName'})) {
			$SysName = $device->{'SysName'};
		}

		if (defined ($device->{'Community'})) {
			$Community = $device->{'Community'};
		}

		if (defined ($device->{'SNMPVersion'})) {
			$SNMPVersion = $device->{'SNMPVersion'};
		}

		if (defined ($device->{'SysCapEnabled'})) {
			$SysCapEnabled = $device->{'SysCapEnabled'};
		}

		if (defined ($device->{'HasLLDP'})) {
			$HasLLDP = $device->{'HasLLDP'};
		}

		if (defined ($device->{'ipForwarding'})) {
			$ipForwarding = $device->{'ipForwarding'};
		}

		my $query = sprintf ("INSERT INTO lldpDevice VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')", 
			$ChassisId,
			$Address,
			$Community,
			$SNMPVersion,
			$SysName,
			$SysDesc,
			$device->{'Scanned'},
			$device->{'Error'},
			$SysCapEnabled,
			$HasLLDP,
			$ipForwarding);
		$sql->do ($query);
	}

	# insert local ports, remote ports and neighbour connections into the database
	foreach my $port (@ports) {
		my $query;
		my $LocPortIdx = "";
		my $LocChassisId = "";
		my $LocPortId = "";
		my $LocPortDesc = "";
		my $RemPortId = "";
		my $RemPortDesc = "";
		my $RemChassisId = "";

		if (defined ($port->{'LocChassisId'})) {
			$LocChassisId = $port->{'LocChassisId'};
		}

		if (defined ($port->{'LocPortIdx'})) {
			$LocPortIdx = $port->{'LocPortIdx'};
		}

		if (defined ($port->{'LocPortId'})) {
			$LocPortId = $port->{'LocPortId'};
		}

		if (defined ($port->{'LocPortDesc'})) {
			$LocPortDesc = $port->{'LocPortDesc'};
		}

		if (defined ($port->{'RemPortId'})) {
			$RemPortId = $port->{'RemPortId'};
		}

		if (defined ($port->{'RemPortDesc'})) {
			$RemPortDesc = $port->{'RemPortDesc'};
		}

		# Fill lldpLocPort table
		$query = sprintf ("INSERT INTO lldpLocPort VALUES ('%s', '%s', '%s')",
			$LocPortId,
			$LocChassisId,
			$LocPortDesc);
		$sql->do ($query);			

		# Fill Interface table
		if (defined ($port->{'ifIdx'})) {
			$query = sprintf ("INSERT INTO Interface VALUES (NULL, '%s', '%s', '%s')",
				$port->{'ifIdx'},
				$LocPortId,
				$LocChassisId);
			$sql->do ($query);
		}

		# Match neighbours
		foreach my $neighbour (@neighbours) {
			if ($LocChassisId eq $neighbour->{'LocChassisId'} && $LocPortIdx eq $neighbour->{'LocPortIdx'}) {
				# Fill lldpRemPort table
				$query = sprintf ("INSERT INTO lldpRemPort VALUES ('%s', '%s', '%s')",
					$RemPortId,
					$neighbour->{'RemChassisId'},
					$RemPortDesc);
				$sql->do ($query);

				# Fill lldpNeighbour table
				$query = sprintf ("INSERT INTO lldpNeighbour VALUES ('%s', '%s', '%s', '%s')",
					$LocPortId,
					$LocChassisId,
					$RemPortId,
					$neighbour->{'RemChassisId'});
				$sql->do ($query);
			}
		}
	}

	# Print results
	print ("\n");
	print_problems ();
	print_neighbours ();
}

main();
