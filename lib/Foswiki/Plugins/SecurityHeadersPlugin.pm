# Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# SecurityHeadersPlugin is Copyright (C) 2015-2016 Michael Daum http://michaeldaumconsulting.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details, published at
# http://www.gnu.org/copyleft/gpl.html

package Foswiki::Plugins::SecurityHeadersPlugin;

use strict;
use warnings;

use Foswiki::Func ();

our $VERSION = '1.01';
our $RELEASE = '09 Sep 2016';
our $SHORTDESCRIPTION = 'Add HTTP security headers to protect against XSS attacks';
our $NO_PREFS_IN_TOPIC = 1;
our $core;

sub initPlugin {

  Foswiki::Func::registerRESTHandler(
    'report',
    sub {
      return getCore()->restReport(@_);
    },
    authenticate => 0,
    validate => 0,
    http_allow => 'POST',
  );


  return 1;
}

sub getCore {
  unless (defined $core) {
    require Foswiki::Plugins::SecurityHeadersPlugin::Core;
    $core = new Foswiki::Plugins::SecurityHeadersPlugin::Core();
  }
  return $core;
}


sub finishPlugin {
  undef $core;
}


sub modifyHeaderHandler {
  my ($headers, $query) = @_;

  my @csp = ();
  my $csp; 
  if ($Foswiki::cfg{Http}{ContentSecurityPolicy}) {
    if (ref($Foswiki::cfg{Http}{ContentSecurityPolicy})) {
      while (my ($key, $val) = each %{$Foswiki::cfg{Http}{ContentSecurityPolicy}}) {
        push @csp, "$key $val" if defined $val && $val ne '';
      }
      $csp = join("; ", sort @csp);
    } else {
      $csp = $Foswiki::cfg{Http}{ContentSecurityPolicy};
    }
  }

  #print STDERR "csp=$csp\n";

  $headers->{"X-Frame-Options"} = "DENY" if $Foswiki::cfg{Http}{DenyFrameOptions};
  $headers->{"Strict-Transport-Security"} = $Foswiki::cfg{Http}{StrictTransportSecurity} if $Foswiki::cfg{Http}{StrictTransportSecurity};
  $headers->{"X-Content-Type-Options"} = $Foswiki::cfg{Http}{ContentTypeOptions} if $Foswiki::cfg{Http}{ContentTypeOptions};
  $headers->{"Content-Security-Policy"} = $csp if $csp;

  # IE only
  $headers->{"X-Download-Options"} = $Foswiki::cfg{Http}{DownloadOptions} if $Foswiki::cfg{Http}{DownloadOptions};
  $headers->{"X-XSS-Protection"} = $Foswiki::cfg{Http}{XSSProtection} if $Foswiki::cfg{Http}{XSSProtection};

  # deprecated header
  if ($Foswiki::cfg{Http}{EnableDeprecatedCSPHeaders}) {
    $headers->{"X-Content-Security-Policy"} = $csp if $csp;
    $headers->{"X-Webkit-CSP"} = $csp if $csp;
  }

}

1;
