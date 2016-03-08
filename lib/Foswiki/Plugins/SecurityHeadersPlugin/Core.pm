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

package Foswiki::Plugins::SecurityHeadersPlugin::Core;

use strict;
use warnings;

use Foswiki::Func ();
use JSON ();
use Data::Dump qw(dump);

use constant TRACE => 0; # toggle me

sub writeDebug {
  return unless TRACE;
  #Foswiki::Func::writeDebug("SecurityHeadersPlugin::Core - $_[0]");
  print STDERR $_[0]."\n";
}

sub new {
  my $class = shift;

  my $this = bless({
    @_
  }, $class);

  return $this;
}

sub restReport {
  my ($this, $session, $params, $topic, $web) = @_;

  #writeDebug("called restReport()");

  my $request = $session->{request};
  my $data = $request->param("POSTDATA");
  return unless defined $data;
  
  my $report = JSON::decode_json($data);

  unless (defined $report->{"csp-report"}) {
    writeDebug("woops, invalid csp-report");
    return;
  }

  my @result = ();
  while (my ($key,$val) = each %{$report->{"csp-report"}}) {
      next if !defined($val) || $val eq "" || $key =~ /^(?:original\-policy|status\-code)$/;
      push @result , "$key=$val";
  }

  return unless @result;
  my $msg = "CSP-Report: ".join(", ", @result); 

  writeDebug($msg);
  Foswiki::Func::writeWarning($msg);
}

1;
