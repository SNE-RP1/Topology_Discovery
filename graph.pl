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
use GraphViz;
use DBI;

use constant true => 1;
use constant false => 0;

my $sql;
my $g;
my $exclude_single_nodes = false;
my $minlen = 5;				# minimum edge length

sub sql_error_handle () {
}

# Add nodes without ports
sub graph_devices_with_links {
	my $query;
	my $sql_sth;

	$g = GraphViz->new(directed => true, concentrate => true);

	if ($exclude_single_nodes) {
		$query = sprintf ("SELECT lldpDevice.Address, lldpDevice.ChassisId, lldpDevice.SysName, lldpDevice.HasLLDP, lldpDevice.Scanned, lldpDevice.Error FROM lldpDevice, lldpNeighbour WHERE lldpDevice.ChassisId = lldpNeighbour.LocChassisId OR lldpDevice.ChassisId = lldpNeighbour.RemChassisId");	
	} else {
		$query = sprintf ("SELECT lldpDevice.Address, lldpDevice.ChassisId, lldpDevice.SysName, lldpDevice.HasLLDP, lldpDevice.Scanned, lldpDevice.Error FROM lldpDevice");
	}

	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();

	while ((my $Address, my $ChassisId, my $SysName, my $HasLLDP, my $Scanned, my $Error) = $sql_sth->fetchrow_array()) {
		my $fillcolor;
		my $style = "";
		my $label;

		# Check if node was NOT allowed snmp access (listed in ips)
		if ($Scanned == false && $Error == false) {
			# Should never happen 
			$fillcolor = "brown";
		} elsif ($Scanned == false && $Error == true) {
			$fillcolor = "yellow";
		} elsif ($Scanned == true && $Error == true) {
			$fillcolor = "red";
		} elsif ($Scanned == true && $HasLLDP == true) {
			$fillcolor = "white";
		} elsif ($Scanned == true && $HasLLDP == false) {
			$fillcolor = "purple";
		}

		if ($SysName eq "") {
			if ($Address eq "") {
				$label = $ChassisId;
			} else {
				$label = sprintf ("%s - %s", $ChassisId, $Address);
			}
		} else {
			if ($Address eq "") {
				$label = sprintf ("%s - %s", $SysName, $ChassisId);
			} else {
				$label = sprintf ("%s - %s", $SysName, $Address);
			}
		}

		if ($Address eq "") {
			$g->add_node ($ChassisId, label => $label, color => "black", fillcolor => $fillcolor, style => "filled");
		} else {
			$g->add_node ($ChassisId, label => $label, color => "black", fillcolor => $fillcolor, style => "filled");
		}
	}

	$query = sprintf ("select LocDevice.SysName, lldpNeighbour.LocChassisId, LocDevice.Address, lldpLocPort.LocPortDesc, RemDevice.SysName, lldpNeighbour.RemChassisId, RemDevice.Address, lldpRemPort.RemPortDesc FROM lldpNeighbour INNER JOIN lldpDevice AS LocDevice ON LocDevice.ChassisId = LocChassisId INNER JOIN lldpDevice AS RemDevice ON RemDevice.ChassisId = lldpNeighbour.RemChassisId INNER JOIN lldpRemPort ON lldpNeighbour.RemChassisId = lldpRemPort.RemChassisId AND lldpNeighbour.RemPortId = lldpRemPort.RemPortId INNER JOIN lldpLocPort ON lldpNeighbour.LocChassisId = lldpLocPort.LocChassisId AND lldpNeighbour.LocPortId = lldpLocPort.LocPortId");
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();

	while ((my $LocSysName, my $LocChassisId, my $LocAddress, my $LportDesc, my $RemSysName, my $RemChassisId, my $RemAddress, my $RportDesc) = $sql_sth->fetchrow_array()) {
		$g->add_edge ("$LocChassisId" => "$RemChassisId", minlen => $minlen);
	}

}

# Add nodes with port
sub graph_devices_with_ports {
	my $query;
	my $sql_sth;

	# Create a new graph object
	$g = GraphViz->new(directed => false, concentrate => true, layout => 'fdp', overlap => false);
	#$g = GraphViz->new(directed => false, concentrate => false);

	# Add nodes
	if ($exclude_single_nodes) {
		$query = sprintf ("SELECT lldpDevice.ChassisId, lldpDevice.Address, lldpDevice.SysName, lldpDevice.HasLLDP, lldpDevice.IPForwarding, lldpDevice.Scanned, lldpDevice.Error FROM lldpDevice, lldpNeighbour WHERE lldpDevice.ChassisId = lldpNeighbour.LocChassisId OR lldpDevice.ChassisId = lldpNeighbour.RemChassisId");
	} else {
		$query = sprintf ("SELECT lldpDevice.ChassisId, lldpDevice.Address, lldpDevice.SysName, lldpDevice.HasLLDP, lldpDevice.IPForwarding, lldpDevice.Scanned, lldpDevice.Error FROM lldpDevice, lldpNeighbour");
	}
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $ChassisId, my $Address, my $SysName, my $HasLLDP, my $ipForwarding, my $Scanned, my $Error) = $sql_sth->fetchrow_array()) {
		my $fillcolor;
		my $label;
		my $cluster;

		# Check if node was NOT allowed snmp access (listed in ips)
		if ($Scanned == false && $Error == false) {
			# Should never happen 
			$fillcolor = "brown";
		} elsif ($Scanned == false && $Error == true) {
			$fillcolor = "yellow";
		} elsif ($Scanned == true && $Error == true) {
			$fillcolor = "red";
		} elsif ($Scanned == true && $HasLLDP == true) {
			if ($ipForwarding == 1) {
				$fillcolor = "powderblue";
			} else {
				$fillcolor = "lightgray";
			}
		} elsif ($Scanned == true && $HasLLDP == false) {
			$fillcolor = "purple";
		}

		if ($SysName eq "") {
			if ($Address eq "") {
				$label = $ChassisId;
			} else {
				$label = sprintf ("%s - %s", $ChassisId, $Address);
			}
		} else {
			if ($Address eq "") {
				$label = sprintf ("%s - %s", $SysName, $ChassisId);
			} else {
				$label = sprintf ("%s - %s", $SysName, $Address);
			}
		}

		$cluster = {name => $ChassisId, label => $label, color => $fillcolor, style => 'filled'};

		# Create (slightly) invisible node
		$g->add_node ($ChassisId, cluster => $cluster, shape => 'point', color => $fillcolor, style => 'filled');
	}

	# Add remote ports
	$query = sprintf ("SELECT lldpDevice.ChassisId, lldpDevice.Address, lldpDevice.SysName, lldpRemPort.RemPortId FROM lldpDevice, lldpRemPort WHERE lldpDevice.ChassisId = lldpRemPort.RemChassisId");	
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $ChassisId, my $Address, my $SysName, my $RemPortId) = $sql_sth->fetchrow_array()) {
		my $id = sprintf ("%s:%s", $ChassisId, $RemPortId);
		my $fillcolor = 'lightgray';
		my $cluster;
		my $label;

		if ($SysName eq "") {
			if ($Address eq "") {
				$label = $ChassisId;
			} else {
				$label = sprintf ("%s - %s", $ChassisId, $Address);
			}
		} else {
			if ($Address eq "") {
				$label = sprintf ("%s - %s", $SysName, $ChassisId);
			} else {
				$label = sprintf ("%s - %s", $SysName, $Address);
			}
		}

		$cluster = {name => $ChassisId, label => $label};

		$g->add_node ($id, cluster => $cluster, color => 'black', fillcolor => $fillcolor, shape => 'box', label => $RemPortId, style => 'filled');
	}

	# Add local ports
	$query = sprintf ("SELECT lldpDevice.ChassisId, lldpDevice.Address, lldpDevice.SysName, lldpLocPort.LocPortId, stpState.State, stpState.DesignatedRoot FROM lldpDevice INNER JOIN lldpLocPort ON lldpDevice.ChassisId = lldpLocPort.LocChassisId LEFT JOIN Interface ON lldpLocPort.LocChassisId = Interface.LocChassisId AND lldpLocPort.LocPortId = Interface.LocPortId LEFT JOIN stpState ON Interface.IfId = stpState.IfId");
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $ChassisId, my $Address, my $SysName, my $LocPortId, my $StpState, my $DesignatedRoot) = $sql_sth->fetchrow_array()) {
		my $id = sprintf ("%s:%s", $ChassisId, $LocPortId);
		my $cluster;
		my $fillcolor = "lightgray";
		my $label;
		my $Addresses = "";

		# Retrieve interface address to place under the LocPortId label
		my $query2 = sprintf ("SELECT Address FROM ipAddress INNER JOIN Interface ON Interface.IfId=ipAddress.IfId INNER JOIN lldpLocPort ON lldpLocPort.LocChassisId=Interface.LocChassisId AND lldpLocPort.LocPortId=Interface.LocPortId WHERE lldpLocPort.LocChassisId='%s' AND lldpLocPort.LocPortId='%s'",
			$ChassisId,
			$LocPortId);
		my $sql_sth2 = $sql->prepare ($query2);
		$sql_sth2->execute ();
		while ((my $Address) = $sql_sth2->fetchrow_array()) {
			$Addresses .= sprintf ("\n%s", $Address);
		}

		if ($StpState) {
			if ($StpState == 0) {		# Unknown
				$fillcolor = "white";
			} elsif ($StpState == 1) {	# Disabled
				$fillcolor = "black";
			} elsif ($StpState == 2) {	# Blocking
				$fillcolor = "ivory4";
			} elsif ($StpState == 3) {	# Listening
				$fillcolor = "gold";
			} elsif ($StpState == 4) {	# Learning
				$fillcolor = " deeppink";
			} elsif ($StpState == 5) {	# Forwarding
				$fillcolor = "green";
			} elsif ($StpState == 6) {	# Broken
				$fillcolor = "brown";
			}
		}

		if ($SysName eq "") {
			if ($Address eq "") {
				$label = $ChassisId;
			} else {
				$label = sprintf ("%s - %s", $ChassisId, $Address);
			}
		} else {
			if ($Address eq "") {
				$label = sprintf ("%s - %s", $SysName, $ChassisId);
			} else {
				$label = sprintf ("%s - %s", $SysName, $Address);
			}
		}
		$cluster = {name => $ChassisId, label => $label};

		# Add DesignatedRoot symbol
		if ($DesignatedRoot) {
			$g->add_node ("$ChassisId - DR", cluster => $cluster, color => 'black', fillcolor => 'orange', shape => 'oval', style => 'filled', label => "DR");
		}

		# Add local port
		$g->add_node ($id, cluster => $cluster, color => 'black', fillcolor => $fillcolor, shape => 'box', label => "$LocPortId$Addresses", style => 'filled');
	}
}

sub graph_stp {
	my $query;
	my $sql_sth;

	# Add unknown links
	$query = sprintf ("SELECT lldpNeighbour.LocChassisId, lldpNeighbour.LocPortId, lldpNeighbour.RemChassisId, lldpNeighbour.RemPortId FROM lldpNeighbour WHERE NOT EXISTS (SELECT * FROM Interface INNER JOIN stpState ON Interface.IfId=stpState.IfId WHERE lldpNeighbour.RemChassisId=Interface.LocChassisId AND lldpNeighbour.RemPortId=Interface.LocPortId) AND NOT EXISTS (SELECT * FROM Interface INNER JOIN stpState ON Interface.IfId=stpState.IfId WHERE lldpNeighbour.LocChassisId=Interface.LocChassisId AND lldpNeighbour.LocPortId=Interface.LocPortId)");
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $LocChassisId, my $LocPortId, my $RemChassisId, my $RemPortId) = $sql_sth->fetchrow_array()) {
		my $LocId = sprintf ("%s:%s", $LocChassisId, $LocPortId);
		my $RemId = sprintf ("%s:%s", $RemChassisId, $RemPortId);

		$g->add_edge ($LocId => $RemId, color => 'brown', minlen => $minlen);
	}

	# Add disables links
	$query = sprintf ("SELECT lldpNeighbour.LocChassisId, lldpNeighbour.LocPortId, lldpNeighbour.RemChassisId, lldpNeighbour.RemPortId FROM lldpNeighbour LEFT JOIN Interface AS LocIf ON lldpNeighbour.LocChassisId=LocIf.LocChassisId AND lldpNeighbour.LocPortId=LocIf.LocPortId LEFT JOIN Interface AS RemIf ON lldpNeighbour.RemChassisId=RemIf.LocChassisId AND lldpNeighbour.RemPortId=RemIf.LocPortId LEFT JOIN stpState AS LocStpState ON LocIf.IfId = LocStpState.IfId LEFT JOIN stpState AS RemStpState ON RemIf.IfId=RemStpState.IfId WHERE LocStpState.State<>5 OR RemStpState.State<>5");
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $LocChassisId, my $LocPortId, my $RemChassisId, my $RemPortId) = $sql_sth->fetchrow_array()) {
		my $LocId = sprintf ("%s:%s", $LocChassisId, $LocPortId);
		my $RemId = sprintf ("%s:%s", $RemChassisId, $RemPortId);

		$g->add_edge ($LocId => $RemId, color => 'black', minlen => $minlen);
	}

	# Add active links
	$query = sprintf ("SELECT lldpNeighbour.LocChassisId, lldpNeighbour.LocPortId, lldpNeighbour.RemChassisId, lldpNeighbour.RemPortId FROM lldpNeighbour INNER JOIN Interface AS LocIf ON lldpNeighbour.LocChassisId=LocIf.LocChassisId AND lldpNeighbour.LocPortId=LocIf.LocPortId INNER JOIN Interface AS RemIf ON lldpNeighbour.RemChassisId=RemIf.LocChassisId AND lldpNeighbour.RemPortId=RemIf.LocPortId INNER JOIN stpState AS LocStpState ON LocIf.IfId = LocStpState.IfId INNER JOIN stpState AS RemStpState ON RemIf.IfId=RemStpState.IfId WHERE LocStpState.State=5 AND RemStpState.State=5");
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $LocChassisId, my $LocPortId, my $RemChassisId, my $RemPortId) = $sql_sth->fetchrow_array()) {
		my $LocId = sprintf ("%s:%s", $LocChassisId, $LocPortId);
		my $RemId = sprintf ("%s:%s", $RemChassisId, $RemPortId);

		$g->add_edge ($LocId => $RemId, color => 'green3', minlen => $minlen);
	}

	# Add active links with remote layer 3 interfaces
	$query = sprintf ("SELECT lldpNeighbour.LocChassisId, lldpNeighbour.LocPortId, lldpNeighbour.RemChassisId, lldpNeighbour.RemPortId FROM lldpNeighbour INNER JOIN Interface AS LocIf ON lldpNeighbour.LocChassisId=LocIf.LocChassisId AND lldpNeighbour.LocPortId=LocIf.LocPortId INNER JOIN Interface AS RemIf ON lldpNeighbour.RemChassisId=RemIf.LocChassisId AND lldpNeighbour.RemPortId=RemIf.LocPortId INNER JOIN stpState AS LocStpState ON LocIf.IfId = LocStpState.IfId WHERE LocStpState.State=5 AND EXISTS (SELECT * FROM ipAddress WHERE RemIf.IfId=ipAddress.IfId)");
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $LocChassisId, my $LocPortId, my $RemChassisId, my $RemPortId) = $sql_sth->fetchrow_array()) {
		my $LocId = sprintf ("%s:%s", $LocChassisId, $LocPortId);
		my $RemId = sprintf ("%s:%s", $RemChassisId, $RemPortId);

		$g->add_edge ($LocId => $RemId, color => 'green3', minlen => $minlen);
	}
}

# Adds the ip layer on top of the 'devices with ports' layer
sub graph_ip {
	my $query;
	my $sql_sth;

	$query = sprintf ("SELECT LocPort.LocChassisId, LocPort.LocPortId, ipNeighbour.LocAddress, RemPort.LocChassisId, RemPort.LocPortId, ipNeighbour.RemAddress FROM ipNeighbour INNER JOIN Interface AS LocIf ON LocIf.IfId=ipNeighbour.LocIfId INNER JOIN Interface AS RemIf ON RemIf.IfId=ipNeighbour.RemIfId INNER JOIN lldpLocPort AS LocPort ON LocPort.LocChassisId=LocIf.LocChassisId AND LocPort.LocPortId=LocIf.LocPortId INNER JOIN lldpLocPort AS RemPort ON RemPort.LocChassisId=RemIf.LocChassisId AND RemPort.LocPortId=RemIf.LocPortId");	
	$sql_sth = $sql->prepare ($query);
	$sql_sth->execute ();
	while ((my $LocChassisId, my $LocPortId, my $LocAddress, my $RemChassisId, my $RemPortId, my $RemAddress) = $sql_sth->fetchrow_array()) {
		my $LocId = sprintf ("%s:%s", $LocChassisId, $LocPortId);	
		my $RemId = sprintf ("%s:%s", $RemChassisId, $RemPortId);

		$g->add_edge ($LocId => $RemId, color => 'blue', dir => 'forward', fontcolor => 'purple', minlen => $minlen);
	}
}

sub main {
	$sql = DBI->connect ('dbi:mysql:dbname=topo;host=127.0.0.1','username','password', {'RaiseError' => 0, 'PrintError' => 1, 'HandleError' => \&sql_error_handle}) || die ("ERROR: Couldn't connect to the database");

	# Only display devices and their connections
	#graph_devices_with_links ();

	# Display more details
	graph_devices_with_ports ();
	graph_stp ();
	graph_ip ();

	print $g->as_png('/var/tmp/overview.png');
}

main ();
