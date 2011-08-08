#!/usr/bin/perl

# $Id: ip_relay.pl,v 1.13 2000/05/27 07:37:19 gavin Exp $
# 
# ip_relay.pl
#
# Copyright (C) 1999,2000 Gavin Stewart
#

# ip_relay
#
# Utility to act as intermediate relay, currently for tcp packets only.
# All relayed streams may be shaped to a total allowable bandwidth,
# i.e. traffic shaping.
#
# This utility is designed to be used in user-space, and has no
# security measures to authenticate user access.
#
# See README for mre information.

use strict;
use POSIX;
use Socket;
use FileHandle;
use Getopt::Std;

# ** Default settings for variables setable within shell.

# ip_relay host.
$main::local_addrs = "0.0.0.0";		# - used for multihomed / aliased hosts.
$main::force_from = "0.0.0.0";		# - used for multihomed / aliased hosts.

# others.
$main::debug = 1;		#Do we dump messages?
$main::dump_traff = 0;		#Dump traff we pass.
$main::idle_out = 3000;		#Client AND server.
$main::dead_count = 10; 	#Client OR server.
$main::data_size = 500;	#how much data to read and write each loop.
$main::bandwidth = 0;	#in bytes / sec.

# remember which vars are "shell setable".
my (@all_vars);
@all_vars = ("local_addrs", "force_from", "debug", "dump_traff",
		"idle_out", "dead_count", "data_size", "bandwidth");

# ** Default settings for non-setable variables.
my $app_name = "ip_relay.pl";	#Application name.
my $version = "0.71";		#Application version number.
my $max_listen_bind_attempts = 20; #Max no. attempts to bind to local_addrs
				     #and local_port.
my $forward_select_time = 0.01;    #At least some delay needed.
my $qlen = 5;		#how long to let the connect queue grow.
my $daemonise = 0;	#gets set from command line, no console, no output.

# ** Other global vars.
my $time_now;		#Variable containing the "currentish" time.
my $skew_percent;	#To adjust actual bandwidth rate more accuratly.
my $last_skew;
my %forwarders;		#List of forwarding rules.
my @forwarders_queue;	#Forwarders queued for "local binding".
my $conn_key = "CONN000000";	#unique connection identifier.
my %connections;	#List of all current connections.
my $CURR_CONN;		#Holds the current $conn_key

$SIG{PIPE} = \&_pipe_handler;
$SIG{INT} = \&cleanup_handler;
$SIG{KILL} = \&cleanup_handler;
$SIG{QUIT} = \&cleanup_handler;

if ($#ARGV >= 0) {  #someone used command line "fast setup".
    if (! &parse_param) {
        print "Usage: $0 [ [-d] [-b n] local_port:remote_host:remote_port]\n";
	print "    -d        Daemon mode, go straight into background.\n";
	print "              (you loose all logging and console access.)\n";
	print "    -b n      Bandwidth, where n is max bytes/sec.\n";
	exit (1);
    } 
}

&print_version;

if ($daemonise) {
    my $child_id = fork();
    if (! defined ($child_id)) {
        die ("Fork failed...die-ing: $!\n");
    } else {
    	if (! $child_id) {
	    #child
	    close (STDIN);
	    close (STDOUT);	#should we open this to /dev/null ?
	    close (STDERR);
	    #POSIX::setsid();
	} else {
	    #parent
	    exit (0);	#Succesful fork of child, parent work is completed.
	}
    }
}

fcntl(STDIN, F_SETFL, O_NONBLOCK); #dont make our STDIN "block"
print "> ";
$last_skew=time;		#I have to init this someplace.
while (1) {
    $time_now = time;		#For functions that use time a lot.
    &check_new_forwarders;
    &check_connect;
    &forward_data;
    &check_dead;
    &check_user_input;
    &set_skew;
    
    select(undef, undef, undef, $forward_select_time);
}

exit (0);

sub print_version {
    print STDERR "\n$app_name Version: $version\n";
    print STDERR "Copyright (C) 1999,2000 Gavin Stewart\n\n";
}

sub parse_param {
   use vars qw/ $opt_d $opt_b $opt_s /;	#For getopts.
   #print "Args: ".join(",", @ARGV)."\n";
   getopts('db:s:');
   #print "opt_d: $opt_d\n";
   #print "opt_b: $opt_b\n";
   $daemonise = 1 if ($opt_d);
   $main::bandwidth = $opt_b if ($opt_b);
   $main::kill_string = $opt_s if ($opt_s);
   #print "Args: ".join(",", @ARGV)."\n";

   #After getopts, we expect to just have our "quick" command line.
   if ($ARGV[0] =~ /(\d+):([^:]+):(\d+)/) {
	my ($local_port, $remote_addrs, $remote_port)=($1,$2,$3);
 	      
	my ($res_addrs) = resolve($remote_addrs);
	if (! $res_addrs) {
	    $remote_addrs = "0.0.0.0";
	    return (0);
	}
	$remote_addrs = $res_addrs;
	$forwarders{99}{LOCAL_PORT} = $local_port;
	$forwarders{99}{REMOTE_ADDRS} = $remote_addrs;
	$forwarders{99}{REMOTE_PORT} = $remote_port;
	push(@forwarders_queue, 99);

        print STDERR "Useing command line parameters:\n";
        print STDERR "  local_port\t$local_port\n";
        print STDERR "  remote_addrs\t$remote_addrs\n";
        print STDERR "  remote_port\t$remote_port\n";
	print STDERR "  bandwidth\t$main::bandwidth\n";
	print STDERR "  kill_string\t$main::kill_string\n";
	print STDERR "  forwarder 99 set.\n\n";
	return (1);
   } else {
        if ($daemonise || $main::bandwidth) {
	    print "\nIt only makes sense to use -d and -b with local_port:remote_host:remote_port !\n\n";
	}
	return (0);
   }
}

sub check_user_input {
    #We want to see if the user types anything, and effect any variable
    #changes also.

    return if ($daemonise);	#We are not connected to the console.

    my ($input, $cmd, $variable, @value, $var_name);

    $input = <STDIN>;
    if (defined($input)) {
        chomp($input);
        ($cmd, $variable, @value) = split(/\s+/, $input);
	#print "cmd: $cmd, var: $variable, val: $value[0]\n";
	if ($cmd =~ /\?/ || $cmd =~ /he/) {		#help
	    print "Commands are:\n".<<EO_COMMANDS;
    ?                 - Show these commands.
    show              - Display variable(s).
    set               - Set a variable.
    kill              - Kill a connection.
EO_COMMANDS
	} elsif ($cmd =~ /^ex/ || $cmd =~ /^qu/) {  	#exit || quit
	    print "Use: <ctrl>-C to kill program.\n";
	} elsif ($cmd =~ /^ki/) {
	    if ($variable eq "?" || $variable eq "") {
	        print "  all\t\tKill all connections.\n";
		print "  <conn>\tKill specified connection.\n";
	    } elsif(defined($connections{$variable})) {
	        &close_connect($variable);
	    } elsif($variable eq "all") {
	        &close_connect(undef);
	    } else {
	        print "  No such connection: $variable\n";
	    }
	} elsif ($cmd =~ /^sh/) {  			#show
	    if ($variable eq "?") {
	        print "  all\tShow all variables.\n";
		print "  stats\tShow stats on connections.\n";
		print "  ver\tShow current version.\n";
		print "  <var>\tShow specific variable.\n";
	    } elsif ($variable eq "all") {
	        no strict 'refs';	#Only in this block!
		foreach $var_name (@all_vars) {
		    print "$var_name\t".${$var_name}."\n";
		}
		print "forwarders:\n";
		my ($forwarder);
		foreach $forwarder (sort {$a <=> $b} (keys %forwarders)) {
		    print "  forwarder $forwarder ";
		    print "$forwarders{$forwarder}{LOCAL_PORT}:";
		    print "$forwarders{$forwarder}{REMOTE_ADDRS}:";
		    print "$forwarders{$forwarder}{REMOTE_PORT}\n";
		}
	    } elsif ($variable =~ /^st/) {		#stats
	        #my ($conn);
		my (@conns) = (keys %connections);
		print "  Total connections: ".($#conns + 1)."\n";
		if ($main::bandwidth) {
		    print "  Bandwidth set to: $main::bandwidth bytes / sec.\n";
		} else {
		    print "  Bandwidth is not set.\n";
		}
		print "  Forwarding connections for:\n";
		&show_conns;
	    } elsif ($variable =~ /^ver/) {		#version
	        &print_version;
	    } elsif (&is_var($variable)) {
	        no strict 'refs';	#Only in this block!
	        print "$variable\t".${$variable}."\n";
	    } else {
	        print "  Incomplete or incorrect command, try: show ?\n";
	    }
	} elsif ($cmd =~ /^se/) {			#set
	    if ($variable eq "?") {
	    	print "  <var> <val>\tSet specific variable to a value.\n";
		print "  forwarder\tSet up forwarders.\n";
	    } elsif ($value[0] ne "" && &is_var($variable)) {
	    	no strict 'refs';       #Only in this block!
		${$variable} = $value[0];
		print "$variable\t".${$variable}."\n";
	    } elsif ($variable =~ /^for/) {		#forwarder
	        if ($value[0] =~ /^\d+$/) {
	       	    if ($value[1] ne "") {	    #set forwarder
			my ($lp,$ra,$rp);
			($lp,$ra,$rp) = split (/:/,$value[1]);
			if ($lp !~ /\d+/ || $rp !~ /\d+/) {
			    print "  Bad port values, forwarder not set.\n";
			} else {
			    my ($res_addrs) = &resolve($ra);
			    if (! $res_addrs) {
			        print "  forwarder $value[0] not set.\n";
			    } else {
				$forwarders{$value[0]}{LOCAL_PORT} = $lp;
				$forwarders{$value[0]}{REMOTE_ADDRS} = $res_addrs;
				$forwarders{$value[0]}{REMOTE_PORT} = $rp;
				push(@forwarders_queue, $value[0]);
			        print "  forwarder $value[0] set.\n";
			   }
			}
	            } else {			    #unset forwarder
		    	delete ($forwarders{$value[0]});
			print "  forwarder $value[0] deleted.\n";
	            }
		} elsif ($value[0] eq "?") {
		    print "  set forwarder <n> <local_port>:<remote_addrs>:<remote_port>\n";
		} else {
		    print "  Bad forwarder: $value[0], try: set forwarder ?\n";
		}
	    } else {
	        print "  Incomplete or incorrect command, try: set ?\n";
	    }
	}
	
        print "> ";
    }
}

#Resolve the parameter, undef returned if unresolved.
sub resolve {
    my ($address) = $_[0];

    my ($name,$aliases,$addrtype,$length,@addrs);
    my (@bytes, $asc_addrs);

    print "  Resolving address ($address)..... \n";
    ($name,$aliases,$addrtype,$length,@addrs) = gethostbyname($address);

    if (! defined($addrs[0])) {
    	print "** Unable to determine ip address for $address\n";
	return(undef);
    } else {
        @bytes = unpack("C4",$addrs[0]);
	$asc_addrs = "$bytes[0]\.$bytes[1]\.$bytes[2]\.$bytes[3]";
	print "  .... determined as: $asc_addrs\n";
	return($asc_addrs);
    }
}

#Check that the passed parameter is a real variable.
sub is_var {
    my ($var) = $_[0];
    my ($real_var);

    foreach $real_var (@all_vars) {
        return (1) if ($var eq $real_var);
    }

    return (0);		#not real!
}

sub show_conns {
    my ($conn);
    my (@conns) = (keys %connections);
    foreach $conn (@conns) {
        &show_conn($conn);
    }
}

sub show_conn {
    my ($conn) = $_[0];
    my ($smallest_idle) = 0; 
    my $time_so_far = $time_now-$connections{$conn}{ESTABLISHED};

    #If both connections are idle, we want the largest time (smallest idle).
    if ( $connections{$conn}{CLNT_IDLE} && $connections{$conn}{SERV_IDLE}) {
        $smallest_idle = ($connections{$conn}{CLNT_IDLE} > $connections{$conn}{SERV_IDLE} ) ? $connections{$conn}{CLNT_IDLE} : $connections{$conn}{SERV_IDLE};
        $smallest_idle = $time_now - $smallest_idle;
    }

    print "    $connections{$conn}{CLNT_ADDRS}:$connections{$conn}{CLNT_PORT} -> $connections{$conn}{SERV_ADDRS}:$connections{$conn}{SERV_PORT} ($conn)\n";
    print "        Connection Up: ".&nice_time($time_so_far)." Idle: ".&nice_time($smallest_idle)."\n";
    print "        Bytes transfered: $connections{$conn}{IN_OCTETS} in, $connections{$conn}{OUT_OCTETS} out.\n";
    print "        Data rate       : ";
    printf "%0.2f kB/s in, %0.2f kB/s out.\n", 
    	($connections{$conn}{IN_OCTETS}/1024/$time_so_far),
	($connections{$conn}{OUT_OCTETS}/1024/$time_so_far);
    print "            (5 sec avg.): ";
    printf "%0.2f kB/s in, %0.2f kB/s out.\n",
    	$connections{$conn}{RATE_IN_5}, $connections{$conn}{RATE_OUT_5};
    print "            (1 min avg.): ";
    printf "%0.2f kB/s in, %0.2f kB/s out.\n",
    	$connections{$conn}{RATE_IN_60}, $connections{$conn}{RATE_OUT_60};
}

#Instead of just seconds, convert to days, hours, minutes, secs as neccesary.
sub nice_time {
    my ($data) = $_[0];
    my ($days, $hours, $mins, $secs);
    my ($res);

    $days = int($data/(60*60*24));
    $data = $data-($days*60*60*24);

    $hours = int($data/(60*60));
    $data = $data-($hours*60*60);

    $mins = int($data/(60));
    $data = $data-($mins*60);

    $secs = $data;

    $res="${days} days, " if ($days);
    $res.="${hours} hours, " if ($days || $hours);	#YES hours if days are shown!
    $res.="${mins} mins, " if ($days || $hours || $mins);
    $res.="${secs} secs.";

    return ($res);
}

sub check_dead {
    my ($ckey);

    foreach $ckey (keys %connections) {

        #Check if this connection is idle: (Both sides!)
	if ( $connections{$ckey}{CLNT_IDLE} < ($time_now-$main::idle_out)  &&
	     $connections{$ckey}{SERV_IDLE} < ($time_now-$main::idle_out) ) {
	    print STDERR "$ckey: Detected idle connection.\n" if $main::debug;
	    &close_connect($ckey);
	    next;
	}

        #Check if this connection is dead: (Any side!)
	if ($connections{$ckey}{CLNT_DEAD} >= $main::dead_count || 
		$connections{$ckey}{SERV_DEAD} >= $main::dead_count) {
	    print STDERR "$ckey: Detected closed connection.\n" if $main::debug;
	    &close_connect($ckey);
	    next;
	}
    }
}

sub forward_data {
    my ($buff, $buff_size, $amount_writen, $tmp_in_amount, $tmp_out_amount);
    my ($cd_size, $sd_size, $d_size, $d_wait);	#Used for main::bandwidth shapeing.

    foreach $CURR_CONN (keys %connections) {

        #Read from server.
        $buff = undef;
      if (length($connections{$CURR_CONN}{CLNT_BUFF}) <= 0) {
        #Only get more data if we are sending it fast enough.
	if( ! sysread($connections{$CURR_CONN}{SERV_HANDLE},$buff,$main::data_size)) {
	    #Probably just no data flow
	    #$connections{$CURR_CONN}{SERV_IDLE}= $time_now if ($connections{$CURR_CONN}{SERV_IDLE} == 0);
	    if ($! == 0) {      #possibly dead connection.
	        $connections{$CURR_CONN}{SERV_DEAD}++;
	    }
	} else {
	    $connections{$CURR_CONN}{SERV_IDLE}=$time_now;
	    $connections{$CURR_CONN}{SERV_DEAD}=0;
	    $connections{$CURR_CONN}{CLNT_BUFF} .= $buff;
	}
      }

	#Send to client.
	$amount_writen = undef;
	$tmp_in_amount = 0;
	$buff_size = length($connections{$CURR_CONN}{CLNT_BUFF});
	if ($buff_size > 0) {
	    $main::KEY_SIGPIPE = $CURR_CONN;
	    $amount_writen = syswrite($connections{$CURR_CONN}{CLNT_HANDLE}, 
	    	$connections{$CURR_CONN}{CLNT_BUFF}, $main::data_size);
	    return if (!defined($connections{$CURR_CONN})); #Must have SIGPIPE'd
	    $cd_size = $amount_writen;
	    if ($amount_writen == $buff_size) {
	        #Happens to be same ammount ... makes it easy
		if ($main::dump_traff) {
		    print "$connections{$CURR_CONN}{SERV_ADDRS}:$connections{$CURR_CONN}{SERV_PORT} -> $connections{$CURR_CONN}{CLNT_ADDRS}:$connections{$CURR_CONN}{CLNT_PORT} : ".$connections{$CURR_CONN}{CLNT_BUFF}."\n";
		    #print "$connections{$CURR_CONN}{SERV_ADDRS}:$connections{$CURR_CONN}{SERV_PORT} -> $connections{$CURR_CONN}{CLNT_ADDRS}:$connections{$CURR_CONN}{CLNT_PORT} : ".quotemeta($connections{$CURR_CONN}{CLNT_BUFF})."\n";
		}
		$connections{$CURR_CONN}{CLNT_BUFF} = "";
	    } elsif ($amount_writen > 0 && $amount_writen < $buff_size){
	        if ($main::dump_traff) {
		    print "$connections{$CURR_CONN}{SERV_ADDRS}:$connections{$CURR_CONN}{SERV_PORT} -> $connections{$CURR_CONN}{CLNT_ADDRS}:$connections{$CURR_CONN}{CLNT_PORT} : ".substr($connections{$CURR_CONN}{CLNT_BUFF},0,$amount_writen)."\n";
		    #print "$connections{$CURR_CONN}{SERV_ADDRS}:$connections{$CURR_CONN}{SERV_PORT} -> $connections{$CURR_CONN}{CLNT_ADDRS}:$connections{$CURR_CONN}{CLNT_PORT} : ".quotemeta(substr($connections{$CURR_CONN}{CLNT_BUFF},0,$amount_writen))."\n";
		}
	    	#Have to calculate remaining data.
		$connections{$CURR_CONN}{CLNT_BUFF} =
		    substr($connections{$CURR_CONN}{CLNT_BUFF}, 
		    $amount_writen, ($buff_size-$amount_writen));
		    print STDERR "*** Done client buffer offset...\n" if $main::debug;
	    } elsif ($amount_writen < 0){
	        #dunno what happened?
	        print STDERR "** Unknown syswrite return value: $amount_writen\n" if $main::debug;
	    }
	    $connections{$CURR_CONN}{IN_OCTETS} += $amount_writen;
	    $tmp_in_amount = $amount_writen;
	}

	#Read from client.
        $buff = undef;
      if (length($connections{$CURR_CONN}{SERV_BUFF}) <= 0) {
        #Only get more data if we are sending it fast enough.
	if( ! sysread($connections{$CURR_CONN}{CLNT_HANDLE},$buff,$main::data_size)) {
	    #Probably just no data flow
	    #$connections{$CURR_CONN}{CLNT_IDLE} = $time_now if ($connections{$CURR_CONN}{CLNT_IDLE} == 0);
	    if ($! == 0) {      #possibly dead connection.
	        $connections{$CURR_CONN}{CLNT_DEAD}++;
	    }
	} else {
	    $connections{$CURR_CONN}{CLNT_IDLE}=$time_now;
	    $connections{$CURR_CONN}{CLNT_DEAD}=0;
	    $connections{$CURR_CONN}{SERV_BUFF} .= $buff;
	}
      }
      
      # check the kill string to see if we should bail now
      if ($main::kill_string && index($connections{$CURR_CONN}{SERV_BUFF}, $main::kill_string) >= 0) {
          print STDERR "KILLING connection because of match in string from client to server...\n" if $main::debug;
          &close_connect($CURR_CONN);
	  next;
      }

	#Send to server.
	$amount_writen = undef;
	$tmp_out_amount = 0;
	$buff_size = length($connections{$CURR_CONN}{SERV_BUFF});
	if ($buff_size > 0) {
	    $main::KEY_SIGPIPE = $CURR_CONN;
	    $amount_writen = syswrite($connections{$CURR_CONN}{SERV_HANDLE}, 
	    	$connections{$CURR_CONN}{SERV_BUFF}, $main::data_size);
	    return if (!defined($connections{$CURR_CONN})); #Must have SIGPIPE'd
	    $sd_size = $amount_writen;
	    if ($amount_writen == $buff_size) {
	        #Happens to be same ammount ... makes it easy
		if ($main::dump_traff) {
		    print "$connections{$CURR_CONN}{CLNT_ADDRS}:$connections{$CURR_CONN}{CLNT_PORT} -> $connections{$CURR_CONN}{SERV_ADDRS}:$connections{$CURR_CONN}{SERV_PORT} : ".$connections{$CURR_CONN}{SERV_BUFF}."\n";
		    #print "$connections{$CURR_CONN}{CLNT_ADDRS}:$connections{$CURR_CONN}{CLNT_PORT} -> $connections{$CURR_CONN}{SERV_ADDRS}:$connections{$CURR_CONN}{SERV_PORT} : ".quotemeta($connections{$CURR_CONN}{SERV_BUFF})."\n";
		}
		$connections{$CURR_CONN}{SERV_BUFF} = "";
	    } elsif ($amount_writen > 0 && $amount_writen < $buff_size){
	    	#Have to calculate remaining data.
	        if ($main::dump_traff) {
		    print "$connections{$CURR_CONN}{CLNT_ADDRS}:$connections{$CURR_CONN}{CLNT_PORT} -> $connections{$CURR_CONN}{SERV_ADDRS}:$connections{$CURR_CONN}{SERV_PORT} : ".substr($connections{$CURR_CONN}{SERV_BUFF},0,$amount_writen)."\n";
		    #print "$connections{$CURR_CONN}{CLNT_ADDRS}:$connections{$CURR_CONN}{CLNT_PORT} -> $connections{$CURR_CONN}{SERV_ADDRS}:$connections{$CURR_CONN}{SERV_PORT} : ".quotemeta(substr($connections{$CURR_CONN}{SERV_BUFF},0,$amount_writen))."\n";
		}
		$connections{$CURR_CONN}{SERV_BUFF} =
		    substr($connections{$CURR_CONN}{SERV_BUFF}, 
		    $amount_writen, ($buff_size-$amount_writen));
		    print STDERR "*** Done server buffer offset: $buff_size $amount_writen\n" if $main::debug;
	    } elsif ($amount_writen < 0) {
	        #dunno what happened?
	        print STDERR "** Unknown syswrite return value: $amount_writen\n" if $main::debug;
	    }
	    $connections{$CURR_CONN}{OUT_OCTETS} += $amount_writen;
	    $tmp_out_amount = $amount_writen;
	}

	#I want to shape all bandwith on all connections, so we pause here
	#dependant on how much data we want to push.

	if ($main::bandwidth) {
	    #We shape on the larger: upstream or downstream ... effect is the
	    # same.
	    $d_size = ($sd_size >= $cd_size) ? $sd_size : $cd_size;
	    if ($d_size > 0) {

	    	#If we want 5Kb / sec, and we sent 500b, we wait (1/(5K/500))
	    	# ... or 1/10th of a second.
	    	#if we want 1Kb / sec, and we sent 2Kb, we wait 2 secs!
	    	$d_wait = (1/($main::bandwidth/$d_size));

		#Skew the wait time by some percentage:
		if ($skew_percent != 0) {
		    #print "Was $d_wait -- ";
		    $d_wait = $d_wait + ($d_wait*$skew_percent/100);
		    #print "Now $d_wait\n";
		}

    	    	select(undef, undef, undef, $d_wait);
	    }
	}

	&calculate_rate($CURR_CONN, $tmp_in_amount, $tmp_out_amount);
    }
}

#This routine is used to calculate the current
#transfer rate.
sub calculate_rate {
    my ($conn, $amount_in, $amount_out) = @_;

    $connections{$conn}{RATE_IN_SUM}+=$amount_in;
    $connections{$conn}{RATE_OUT_SUM}+=$amount_out;

    #Skip calculation if less than 1 second since last one.
    return if ($connections{$conn}{LAST_RATE} > $time_now - 1);
    #Ok we must have enough data for a 1 second period.
    $connections{$conn}{RATE_IN} = $connections{$conn}{RATE_IN_SUM} / 1024 / ($time_now - $connections{$conn}{LAST_RATE});
    $connections{$conn}{RATE_OUT} = $connections{$conn}{RATE_OUT_SUM} / 1024 / ($time_now - $connections{$conn}{LAST_RATE});

    #lets do a 5 second average.
    $connections{$conn}{RATE_IN_5} = ($connections{$conn}{RATE_IN_5} * 4 + $connections{$conn}{RATE_IN}) / 5;
    $connections{$conn}{RATE_OUT_5} = ($connections{$conn}{RATE_OUT_5} * 4 + $connections{$conn}{RATE_OUT}) / 5;

    #lets do a 1 minute average
    $connections{$conn}{RATE_IN_60} = ($connections{$conn}{RATE_IN_60} * 59 + $connections{$conn}{RATE_IN}) / 60;
    $connections{$conn}{RATE_OUT_60} = ($connections{$conn}{RATE_OUT_60} * 59 + $connections{$conn}{RATE_OUT}) / 60;

    $connections{$conn}{RATE_IN_SUM}=0;
    $connections{$conn}{RATE_OUT_SUM}=0;
    $connections{$conn}{LAST_RATE} = $time_now;
}

#Calculate the percentage to skew the forwarding
#select by. Range: -25% to +25%, in 5% increments.
#Window of acceptable rate +-100 bytes/sec.
sub set_skew {

    #Not relevant if no bandwidth is set.
    if (! $main::bandwidth) {
        $skew_percent = 0;
	return;
    }

    #Skip if we did this less than 1 second ago.
    return if ($last_skew > $time_now - 1);
    $last_skew = $time_now;

    my ($conn, $rate_in, $rate_out, $rate, $no_conn);

    $no_conn=0;
    foreach $conn (keys %connections) {
    	$rate_in += $connections{$conn}{RATE_IN};
    	$rate_out += $connections{$conn}{RATE_OUT};
	$no_conn++;
    }

    if ($no_conn==0) {	#no actual connections anyway!
        $skew_percent = 0;
	return;
    }

    $rate = ($rate_in > $rate_out) ? $rate_in : $rate_out;
    if ($rate < (($main::bandwidth-100)/1024)) {
        $skew_percent -= 5 if ($skew_percent > -25);
    } elsif ($rate > (($main::bandwidth+200)/1024)) {
        $skew_percent += 5 if ($skew_percent < 25);
    }
    #print "Skew: $skew_percent\n";
}

sub close_connect {
    my ($ckey) = $_[0];

    if (defined($ckey)) {
        #Just disconnect this key.
	if (defined ($connections{$ckey})) {
	    shutdown ($connections{$ckey}{CLNT_HANDLE}, 2);
	    shutdown ($connections{$ckey}{SERV_HANDLE}, 2);
	    delete $connections{$ckey};
	    print STDERR "$ckey: Connection closed.\n" if $main::debug;
	} else {
	    #connection does not exist.
	}
    } else {
        #Do all keys.
	my ($key);
	foreach $key (keys %connections) {
	    shutdown ($connections{$key}{CLNT_HANDLE}, 2);
	    shutdown ($connections{$key}{SERV_HANDLE}, 2);
	    delete $connections{$key};
	    print STDERR "$key: Connection closed.\n" if $main::debug;
	}
    }
}

sub check_connect {
    my ($forwarder, $client_address);

  #We check for a connection on all forwarders that have a listen socket.
  foreach $forwarder (keys (%forwarders)) {
    next if (! defined($forwarders{$forwarder}{PAS_SOCK}));

    my ($ip_addr, $paddr, $loc_paddr);
    my ($pas_sock) = $forwarders{$forwarder}{PAS_SOCK};
    my ($remote_addrs) = $forwarders{$forwarder}{REMOTE_ADDRS};
    my ($remote_port) = $forwarders{$forwarder}{REMOTE_PORT};
    my ($fail_msg) = "Failed to connect to: $remote_addrs:$remote_port\n";
    my ($clnt_ref) = new FileHandle;     #keep scope local, if not "accepted";
    my ($serv_ref) = new FileHandle;     #keep scope local, if not "accepted";

    #NB, we are non-blocking.
    if (($client_address = accept($clnt_ref, $pas_sock)) ) {
    	# if we get here, we have a new connection from a client.

	fcntl($clnt_ref , F_SETFL, O_NONBLOCK); #dont make our socket "block"
    	autoflush $clnt_ref 1;          #make unbuffered

	my($clnt_port,$clnt_iaddr) = sockaddr_in($client_address);
	print STDERR "- Received connect from ".inet_ntoa($clnt_iaddr)."\n" if $main::debug;
	
	$ip_addr = inet_aton($remote_addrs);
	$paddr = sockaddr_in($remote_port, $ip_addr);
	if (! socket ($serv_ref, PF_INET, SOCK_STREAM, getprotobyname('tcp'))) {
	    syswrite($clnt_ref, $fail_msg, length($fail_msg));
	    print STDERR "* Failed to get socket to server for ".inet_ntoa($clnt_iaddr).", closeing client socket - out of sockets?: $!\n" if $main::debug;
	    shutdown($clnt_ref, 2);
	    return;
	}
	if ($main::force_from) {
		$loc_paddr = sockaddr_in(0, inet_aton($main::force_from));
	} else {
		$loc_paddr = sockaddr_in(0, inet_aton(INADDR_ANY));
	}
	bind($serv_ref, $loc_paddr);	#So we originate on any address!
					#Handy for multihomed/aliases server.
	if (connect ($serv_ref, $paddr)) {
	    fcntl($serv_ref, F_SETFL, O_NONBLOCK); #dont "block"
            autoflush $serv_ref;          #make unbuffered
    	    setsockopt($serv_ref, SOL_SOCKET, SO_SNDBUF, 4096); #max send buffer
    	    #setsockopt($serv_ref, SOL_SOCKET, SO_SNDBUF, 0); #max send buffer
    	    setsockopt($serv_ref, SOL_SOCKET, SO_RCVBUF, 4096); #max recv buffer
	    print STDERR "- Connected to server on: $remote_addrs:$remote_port\n" if $main::debug;
	} else {
	    syswrite($clnt_ref, $fail_msg, length($fail_msg));
	    print STDERR "* Failed to connect to server on: $remote_addrs:$remote_port for ".inet_ntoa($clnt_iaddr).", closeing client socket: $!\n" if $main::debug;
	    shutdown($clnt_ref, 2);
	    return;
	}

	$conn_key++;	#New key for new connection:
	$connections{$conn_key}{CLNT_HANDLE} = $clnt_ref;
	$connections{$conn_key}{CLNT_ADDRS} = inet_ntoa($clnt_iaddr);
	$connections{$conn_key}{CLNT_PORT} = $clnt_port;
	$connections{$conn_key}{CLNT_IDLE} = $time_now;
	$connections{$conn_key}{CLNT_DEAD} = 0;
	$connections{$conn_key}{SERV_HANDLE} = $serv_ref;
	$connections{$conn_key}{SERV_ADDRS} = $remote_addrs;
	$connections{$conn_key}{SERV_PORT} = $remote_port;
	$connections{$conn_key}{SERV_IDLE} = $time_now;
	$connections{$conn_key}{SERV_DEAD} = 0;
	$connections{$conn_key}{ESTABLISHED} = $time_now;
	$connections{$conn_key}{LAST_RATE} = $time_now;
	$connections{$conn_key}{RATE_IN} = 0;
	$connections{$conn_key}{RATE_OUT} = 0;
	$connections{$conn_key}{IN_OCTETS} = 0;
	$connections{$conn_key}{OUT_OCTETS} = 0;

	print STDERR "$conn_key: Connection established between ".inet_ntoa($clnt_iaddr)." and $remote_addrs:$remote_port\n";
    }
  }
}

#Ok see if any "forwaders" are queued for a passive "listen" socket.
sub check_new_forwarders {

    return if ($#forwarders_queue < 0);		#None in queue.

    my ($forwarder, %delete_from_queue);

    foreach $forwarder (@forwarders_queue) {

	#skip this forwarder if attempted a short time ago.
	next if ($forwarders{$forwarder}{NEXT_ATTEMPT} > $time_now);

	#These scoped variables defined here for effeciency.
        my ($ip_addr, $listen_socket);
        my ($local_port, $bind_attempt);

        $local_port=$forwarders{$forwarder}{LOCAL_PORT};
	$bind_attempt=$forwarders{$forwarder}{ATTEMPT};
        my ($listen_ref) = new FileHandle;     #keep scope local, if not "accepted";

    	if ($main::local_addrs) {	#Check for specific listen address.
            $ip_addr = inet_aton($main::local_addrs);
    	    $listen_socket = sockaddr_in($local_port, $ip_addr);
    	} else {
    	    $listen_socket = sockaddr_in($local_port, INADDR_ANY);
        }

    	#Setup our passive socket.
        socket($listen_ref, PF_INET, SOCK_STREAM, getprotobyname('tcp')) ||
                        die ("No more sockets? : $!\n");

    	if (! bind ($listen_ref, $listen_socket) ) {
	    $bind_attempt++;
	    print STDERR "** forwarder $forwarder failed bind to local port: $main::local_addrs:$local_port, waiting .... ($bind_attempt/$max_listen_bind_attempts)\n";
	    if ($bind_attempt >= $max_listen_bind_attempts) {
		print STDERR "** forwarder $forwarder failed bind: $main::local_addrs:$local_port exceeded max bind attempts ($max_listen_bind_attempts), deleting.\n";    	
	    	delete($forwarders{$forwarder});
		$delete_from_queue{$forwarder}++;
		next;
	    }
	    $forwarders{$forwarder}{NEXT_ATTEMPT} = $time_now + 5;	#Wait 5 secs.
	    $forwarders{$forwarder}{ATTEMPT} = $bind_attempt;
	    next;
        }

    	listen($listen_ref, $qlen);

    	fcntl($listen_ref, F_SETFL, O_NONBLOCK); #dont make our socket "block"
    	autoflush $listen_ref 1;          #make unbuffered

    	setsockopt($listen_ref, SOL_SOCKET, SO_RCVBUF, 4096); #max receive buffer.
    	#setsockopt($listen_ref, SOL_SOCKET, SO_RCVBUF, 0); #max receive buffer.
    	setsockopt($listen_ref, SOL_SOCKET, SO_SNDBUF, 4096); #max send buffer.

    	print STDERR "Passive socket setup on $main::local_addrs:$local_port\n" if $main::debug;

	$delete_from_queue{$forwarder}++;
	$forwarders{$forwarder}{PAS_SOCK} = $listen_ref;
    }

    #Remove forwarders to be deleted.
    my $old_queue = [ @forwarders_queue ];
    @forwarders_queue=();
    foreach $forwarder (@{$old_queue}) {
        next if ($forwarder eq "");	#Sheesh!
        if (! defined($delete_from_queue{$forwarder})) {
            push (@forwarders_queue, $forwarder);
	}
    }
}

sub _pipe_handler {
   #We were called 'cause a pipe has died, and we wrote to it.
   #Shutdown Client and Server ends, and reset $connected.

   print STDERR "${main::KEY_SIGPIPE}: Caught SIGPIPE, shutting down client and server connections.\n" if $main::debug;

   shutdown ($connections{$main::KEY_SIGPIPE}{CLNT_HANDLE}, 2);
   shutdown ($connections{$main::KEY_SIGPIPE}{SERV_HANDLE}, 2);
   delete $connections{$main::KEY_SIGPIPE};
}

sub cleanup_handler {
    my($signal) = @_;
    $SIG{$signal} = 'IGNORE';      #prevent re-SIGing

    print STDERR "Caught sig ($signal), closeing all connections.\n";
    &close_connect(undef);       #Close all connections

    sleep 1;
    sleep 1;
    exit 0;
}
