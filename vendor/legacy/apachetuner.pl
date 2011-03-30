#!/usr/bin/perl
my %process_name;
my %process_owner;
my %process_ram_usage;
my %meminfo;
my %apache_setting;
my %php_setting;
my @output_split;
my $server_daemon="httpd";
my $server_mpm="prefork";
my %server_mpm_settings={};
my $child_counter=0;
my @ps_output;
my $total_real_ram_usage=0;
my @df_data;
my $fs_warn_txt="";
my $percent_used_warning=66;
my $php_not_found=0;
my $httpd_not_found=0;
my %color = (
          green  => "\e[32;1m",
          yellow => "\e[33;1m",
          red    => "\e[31;1m",
          gray   => "\e[30;1m",
          white  => "\e[37;1m",
          red    => "\e[31;1m",
          blue   => "\e[34;1m",
          reset  => "\e[0m",
);
sub title {
    my $text = shift;
    print "$color{'white'}\[$color{'yellow'} $text $color{'white'}\]$color{'reset'}\n";
}

sub result {
    my $result = shift;
    my $newline = shift;
    print "$color{'white'}${result}$color{'reset'}";
    print "\n" unless $newline;
}

### Check for RedHat
if (! -f "/etc/redhat-release"){
    print "\n** NO REDHAT LINUX FOUND **\n\n";
    exit;
}

### Check for root
print "\n** NOT RUNNING AS ROOT!! Proceeding with unpredictable results **\n\n" if ($> ne 0); 

@ps_output=`/bin/ps -eo pid= -o ruser= -o comm=`;
#@ps_output=`/bin/ps -eo pid= -o ruser= -o comm= -o rss=`;
foreach $line (@ps_output){
    chomp $line;
    $line =~ s/^\s*//;
    @output_split = split /\s+/, $line;
    $process_owner{$output_split[0]} = $output_split[1];
    $process_name{$output_split[0]} = $output_split[2];
#    if ($output_split[3] !~ /\d+/) { die "Initial information gathering failed.\n"; }
#    $process_ram_usage{$output_split[0]} = get_MB($output_split[3]);
}


sub apache_real_ram_usage {
    foreach $pid (keys %process_name){
        if ($process_name{$pid} eq "$server_daemon"){
            chomp($pid);
            $child_counter+=1;
            my $pid_ram=`pmap -d $pid | grep "mapped:"`;
            $pid_ram=~/^mapped:\s+\d+K\s+writeable\/private:\s+(\d+)K\s+shared:\s+\d+K$/;
            my $total_real_ram_usageMB = $1;
            $total_real_ram_usage+=get_MB($total_real_ram_usageMB);
        }
    }
}

### Find out the Apache MPM being used
sub apache_mpm {
    if (-f "/etc/sysconfig/httpd" and -r "/etc/sysconfig/httpd"){
        open(APACHEMPM,"</etc/sysconfig/httpd");
        while (defined($line=<APACHEMPM>)){
            chomp($line);
            if ($line=~/HTTPD=/){
                if ($line=~/^\s*HTTPD=\/usr\/sbin\/httpd.worker\s*/){
                    $server_daemon="httpd.worker";
                    $server_mpm="worker";
                }
            break;
            }
        }
        close(APACHEMPM);
    } else {
        print "Couldn't find or read the Apache MPM configuration file /etc/sysconfig/httpd, assuming forker MPM";
    }
}

### Get MB value from kB
sub get_MB {
    my $bytes = shift;
    my $mbytes = sprintf("%.2f",$bytes/1024);
}

sub apache_read_config{
    if (-f "/etc/httpd/conf/httpd.conf" and -r "/etc/httpd/conf/httpd.conf"){
        open(APACHECFG,"</etc/httpd/conf/httpd.conf");
        while (defined($line=<APACHECFG>)){
            chomp($line);
            next if $line=~/^\s*#/;
            next if $line=~/^$/;
            if ($line=~/^<IfModule $server_mpm/ .. $line=~/<\/IfModule/){
                next if $line=~/^\s*</;
                $line=~/^\s*(\w*)\s+?([\s|\S]*)$/;
                my $directive=lc($1);
                my $value=lc($2);
                $server_mpm_settings{$server_mpm}{$directive} = $value;
                next;
            }
            next if $line=~/^\s*</;
            $line=~/^\s*(\w*)\s+?([\s|\S]*)$/;
            my $directive=lc($1);
            my $value=lc($2);
            $apache_setting{$directive} = $value;
        }
        close(APACHECFG);
        } else {
            $httpd_not_found=1;
        }
}


sub php_read_config{
    if (-f "/etc/php.ini" and -r "/etc/php.ini"){
        open(PHPCFG,"</etc/php.ini");
        while (defined($line=<PHPCFG>)){
            chomp($line);
            next if $line=~/^\s*;/;
            next if $line=~/^$/;
            $line=~/^\s*(\w*)\s+?=\s+?(\S*);?.*$/;
            my $directive=lc($1);
            my $value=lc($2);
            $php_setting{$directive} = $value;
        }
        close(PHPCFG);
        } else {
            $php_not_found=1;
        }
}

### Print results !
sub print_results {
    title("Apache overview");
    if(!$httpd_not_found){
        print "Found Apache configured with the $server_mpm MPM\n";
        if ($apache_setting{'keepalive'}){
            print "KeepAlives: "; result(uc($apache_setting{'keepalive'}));
        }
        if ($apache_setting{'keepalive'} eq 'on'){
            print "KeepAliveTimeout: "; result(uc($apache_setting{'keepalivetimeout'}));
        }
        if($server_mpm_settings{$server_mpm}{'maxrequestsperchild'}){
            print "MaxRequestsPerChild: "; result($server_mpm_settings{$server_mpm}{'maxrequestsperchild'});
        } elsif($apache_setting{'maxrequestsperchild'}){
            print "MaxRequestsPerChild: "; result($apache_setting{'maxrequestsperchild'}) ;
        } else {
            print "MaxRequestsPerChild:"; result("Not found in configuration file");
        }
        if($server_mpm_settings{$server_mpm}{'maxclients'}){
            print "MaxClients setting: "; result(sprintf("%6d", $server_mpm_settings{$server_mpm}{'maxclients'}));
            print "Currently running:  "; result(sprintf("%6d", $child_counter));
        } elsif($apache_setting{'maxclients'}){
            print "MaxClients setting: " . sprintf("%6d", $apache_setting{'maxclients'}) . "\nCurrently running:  ". sprintf("%6d", $child_counter)."\n";
        } else {
            print "MaxClients: Not found in configuration file\n";
        }
        print "Total Apache RAM usage (excluding shared libraries): "; result("${total_real_ram_usage} MB");
### Suggest a MaxClients value considering 70% of RAM available for Apache
        if(($total_real_ram_usage>0)
                &&($child_counter>0)
                &&($meminfo{memtotal}>0)){
            my $average_real_ram_usage = $total_real_ram_usage/$child_counter;
            $average_real_ram_usage = sprintf("%.2f",$average_real_ram_usage);
            my $recommended_maxclients = $meminfo{memtotal}*.7 / $average_real_ram_usage;
            $recommended_maxclients = sprintf("%d",$recommended_maxclients);
            print "Average child size: "; result("$average_real_ram_usage MB");
            print "Suggested MaxClients setting: "; result("$recommended_maxclients -- Considers 70% of RAM to be used by Apache"); print "\n";
#            result ("* Suggested MaxClients setting considers 70% of RAM to be used by Apache");
        } else {
            print "Suggested MaxClients setting: "; result("No suggestion can be made. Are you running as root?"); print "\n";
        }
    } else {
        result("The httpd.conf configuration file was not found!\n\n");
    }
    title("PHP overview");
    if(!$php_not_found){
        if ($php_setting{'memory_limit'}){
            print "Memory Limit: "; result($php_setting{'memory_limit'});
        }
        if ($php_setting{'safe_mode'}){
            print "Safe Mode: "; result(uc($php_setting{'safe_mode'}));
        }
        if($php_setting{'allow_url_fopen'}){
            print "URL fopen: "; result(uc($php_setting{'allow_url_fopen'}));
        }
        if($php_setting{'disable_functions'}){
            print "Disabled functions: "; result($php_setting{'disable_functions'});
        }
        print "\n";
    } else {
        result("The php.ini configuration file was not found!\n");
    }

    title("System overview");
    my $free_ram = $meminfo{buffers} + $meminfo{cached} + $meminfo{memfree};
    result("$fs_warn_txt");
    print "Total System RAM: "; result("$meminfo{memtotal}MB");
    print "Free System RAM: "; result("${free_ram}MB");
    print "\n";


    print "\n";
#    foreach my $key (sort keys %{ $server_mpm_settings{$server_mpm} }){
#        print "$key, $server_mpm_settings{$server_mpm}{$key}\n";
#    }

}

sub average {
    my ($total, $count) = @_[0,1];
    my $average=$total/$count;
    my $average=sprintf("%.2f",$average);
    return $average;
}

sub disk_free {
        
    eval {
        local $SIG{ALRM} = sub { die(); };
        alarm 10;
        @df_data = `/bin/df -mP 2>/dev/null`;
        alarm 0;
    };
        
    if($@){
        # The DF Timed out uhoh!
        $fs_warn_txt = "Timed out waiting for the system df utility. This is generally indicative of an unreachable network file system, or other serious error.";
    } else {
        # The DF worked successfully
        # parse through the resulting data
        while(my $line=shift(@df_data)){
            if($line =~ /^([\/\d]+[\:\.\d\w\/\-]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\%\s+(.*)$/){
                if($5 >= $percent_used_warning){ 
                    my $device = $1;  # The device from df check 
                    my $total = $2;         # total space on the device 
                    my $used = $3;          # used space on the device 
                    my $available = $4;     # available space on the device
                    my $percent = $5;       # percentage of spaced used
                    my $mounted = $6;       # where the device is mounted as, what skip list checks.
                    # Set the warning flag so the email can be sent.
                    # Update the warning text
                    $fs_warn_txt .= "Filesystem $mounted on device $device is $percent% used.";
                }
            }
        }
    } 
    if ($fs_warn_txt eq ""){
        $fs_warn_txt = "All filesystems mounted have less than $percent_used_warning% of space utilized."; 

    }
}

sub memory_info {
    if (-f "/proc/meminfo" and -r "/proc/meminfo"){
        open(MEMINFO,"</proc/meminfo");
        while (defined($line=<MEMINFO>)){
            chomp($line);
            $line=~/^\s*(\w*):\s+?([\d]*)( kB)?$/;
            my $item=lc($1);
            my $value=get_MB(lc($2));
            $meminfo{$item} = $value;
        }
    } else { 
        print "Can't get system memory information from /proc/meminfo!\n";
        exit 1;
    }

}    

apache_mpm();
apache_read_config();
php_read_config();
apache_real_ram_usage();
disk_free();
memory_info();
print_results();
