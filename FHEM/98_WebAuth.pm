##############################################
# $Id$
#
# WebAuth
# authenticate FHEMWEB requests based on HTTP headers
#
# Author: Sidey
# Version: 0.2.0
#
package main;

use strict;
use warnings;

use FHEM::Core::Authentication::HeaderPolicy qw(
  evaluate_header_auth_policy
  parse_header_auth_policy
  validate_header_auth_policy
);

our $VERSION = '0.2.0';

#####################################
sub WebAuth_Initialize {
  my ($hash) = @_;

  $hash->{DefFn} = \&FHEM::WebAuth::Define;
  $hash->{AuthenticateFn} = \&FHEM::WebAuth::Authenticate;
  $hash->{AttrFn} = \&FHEM::WebAuth::Attr;
  $hash->{RenameFn} = \&FHEM::WebAuth::Rename;
  $hash->{UndefFn} = \&FHEM::WebAuth::Undef;

  no warnings 'qw';
  my @attrList = qw(
    disable:1,0
    disabledForIntervals
    headerAuthPolicy:textField-long
    noCheckFor
    trustedProxy:textField-long
    reportAuthAttempts
    strict:1,0
    validFor:
  );
  $attrList[-1] .= join(",", devspec2array("TYPE=FHEMWEB"));
  use warnings 'qw';
  $hash->{AttrList} = join(" ", @attrList)." ".$readingFnAttributes;
}


package FHEM::WebAuth;

#####################################
sub Define {
  my ($hash, $def) = @_;
  my @l = split(" ", $def);

  return "Wrong syntax: use define <name> WebAuth" if(int(@l) != 2);

  $main::auth_refresh = 1;
  $hash->{".validFor"} = () if(!$hash->{OLDDEF});
  main::readingsSingleUpdate($hash, "state", "validFor:", 0);
  main::SecurityCheck() if($main::init_done);
  return;
}

sub Undef {
  $main::auth_refresh = 1;
  return;
}

sub Rename {
  $main::auth_refresh = 1;
  return;
}

#####################################
# Return
# - 0 for authentication not needed
# - 1 for auth-ok
# - 2 for wrong username/password
# - 3 authentication not needed this time (FHEMWEB special)
sub Authenticate {
  my ($me, $cl, $param) = @_;
  my $aName = $me->{NAME};

  my $doReturn = sub($;$){
    my ($r,$a) = @_;
    $cl->{AuthenticatedBy} = $aName if($r == 1);
    $cl->{AuthenticationDeniedBy} = $aName if($r == 2 && $a);
    if($me->{doReport} && $cl->{PEER}) {
      my $peer = "$cl->{SNAME}:$cl->{PEER}:$cl->{PORT}";
      main::DoTrigger($aName, "accepting connection from $peer")
        if($r != 2 && $me->{doReport} & 1);
      main::DoTrigger($aName, "denying connection from $peer")
        if($r == 2 && $me->{doReport} & 2);
    }
    return $r;
  };

  return 0 if($me->{disabled} && main::IsDisabled($aName));
  return 0 if($cl->{TYPE} ne "FHEMWEB");

  my $vName = $cl->{SNAME} ? $cl->{SNAME} : $cl->{NAME};
  return 0 if(!$me->{".validFor"}{$vName});
  return 0 if(!$me->{".headerAuthPolicy"});

  return &$doReturn(2) if(!$param);

  my $exc = main::AttrVal($aName, "noCheckFor", undef);
  return 3 if($exc && $param->{_Path} =~ m/$exc/);

  my $trustedProxy = main::AttrVal($aName, "trustedProxy", undef);
  if($trustedProxy) {
    return &$doReturn(0) if(!defined($cl->{PEER}) || $cl->{PEER} !~ m/$trustedProxy/);
  }

  my %effectiveHeaders = %{$param};
  my $clientIp = $cl->{PEER};
  $effectiveHeaders{"X-FHEM-Client-IP"} = $clientIp if(defined($clientIp) && $clientIp ne '');

  if($trustedProxy) {
    my $forwardedIp = _ExtractForwardedClientIP($param);
    $effectiveHeaders{"X-FHEM-Forwarded-Client-IP"} = $forwardedIp
      if(defined($forwardedIp) && $forwardedIp ne '');
    $effectiveHeaders{"X-FHEM-Trusted-Proxy-IP"} = $clientIp
      if(defined($clientIp) && $clientIp ne '');
  }

  if(!_HasRelevantHeaders($me->{".headerAuthPolicy"}, \%effectiveHeaders)) {
    if(main::AttrVal($aName, "strict", 1)) {
      $cl->{".httpAuthHeader"} = "HTTP/1.1 403 Forbidden\r\n";
      return &$doReturn(2, "headerAuthPolicy");
    }
    return &$doReturn(0);
  }
  delete $cl->{".httpAuthHeader"};

  my ($ok, $error) = FHEM::Core::Authentication::HeaderPolicy::evaluate_header_auth_policy(
    $me->{".headerAuthPolicy"},
    \%effectiveHeaders
  );
  if($error) {
    main::Log3 $aName, 1, "$aName: headerAuthPolicy evaluation failed: $error";
    $cl->{".httpAuthHeader"} = "HTTP/1.1 403 Forbidden\r\n";
    return &$doReturn(2, "headerAuthPolicy");
  }

  return &$doReturn(1, "headerAuthPolicy") if($ok);

  $cl->{".httpAuthHeader"} = "HTTP/1.1 403 Forbidden\r\n";
  return &$doReturn(2, "headerAuthPolicy");
}

sub _HasRelevantHeaders {
  my ($node, $headers) = @_;

  return 0 if(ref($node) ne 'HASH' || ref($headers) ne 'HASH');

  if(exists $node->{op}) {
    foreach my $item (@{$node->{items}}) {
      return 1 if(_HasRelevantHeaders($item, $headers));
    }
    return 0;
  }

  foreach my $headerName (keys %{$headers}) {
    next if(!defined($headerName));
    return 1 if(lc($headerName) eq lc($node->{header}));
  }

  return 0;
}

sub _ExtractForwardedClientIP {
  my ($headers) = @_;

  return undef if(ref($headers) ne 'HASH');

  my $forwarded = _HeaderValue($headers, 'Forwarded');
  if(defined($forwarded) && $forwarded ne '') {
    foreach my $element (split(/\s*,\s*/, $forwarded)) {
      next if(!defined($element) || $element eq '');
      if($element =~ m/(?:^|;)\s*for=(?:"?)([^";,]+)(?:"?)/i) {
        my $ip = $1;
        $ip =~ s/^\[//;
        $ip =~ s/\]$//;
        $ip =~ s/:\d+$// if($ip !~ m/^\d{1,3}(?:\.\d{1,3}){3}$/);
        return $ip if($ip ne '');
      }
    }
  }

  my $xff = _HeaderValue($headers, 'X-Forwarded-For');
  if(defined($xff) && $xff ne '') {
    my ($ip) = split(/\s*,\s*/, $xff, 2);
    return undef if(!defined($ip));
    $ip =~ s/^\s+//;
    $ip =~ s/\s+$//;
    $ip =~ s/^"//;
    $ip =~ s/"$//;
    $ip =~ s/^\[//;
    $ip =~ s/\]$//;
    $ip =~ s/:\d+$// if($ip !~ m/^\d{1,3}(?:\.\d{1,3}){3}$/);
    return $ip if($ip ne '');
  }

  return undef;
}

sub _HeaderValue {
  my ($headers, $wanted) = @_;

  return undef if(ref($headers) ne 'HASH' || !defined($wanted));

  foreach my $key (keys %{$headers}) {
    next if(!defined($key));
    return $headers->{$key} if(lc($key) eq lc($wanted));
  }

  return undef;
}


sub Attr {
  my ($type, $devName, $attrName, @param) = @_;
  my $hash = $main::defs{$devName};

  $main::auth_refresh = 1;
  my $set = ($type eq "del" ? 0 : (!defined($param[0]) || $param[0]) ? 1 : 0);

  if($attrName eq "disable" ||
     $attrName eq "disabledForIntervals") {
    main::readingsSingleUpdate($hash, "state", $set ? "disabled" : "active", 1)
      if($attrName eq "disable");
    if($set) {
      $hash->{disabled} = 1;
    } else {
      delete($hash->{disabled});
    }

  } elsif($attrName eq "headerAuthPolicy" ||
          $attrName eq "trustedProxy" ||
          $attrName eq "validFor") {
    if($set) {
      if($attrName eq "validFor") {
        my %vf = map { $_, 1 } split(",", join(",", @param));
        $hash->{".$attrName"} = \%vf;
      } else {
        my $raw = join(" ", @param);
        if($attrName eq "headerAuthPolicy") {
          my ($policy, $parseError) =
            FHEM::Core::Authentication::HeaderPolicy::parse_header_auth_policy($raw);
          return $parseError if($parseError);

          my $validationError =
            FHEM::Core::Authentication::HeaderPolicy::validate_header_auth_policy($policy);
          return $validationError if($validationError);

          $hash->{".$attrName"} = $policy;
        } else {
          my $regexOk = eval { '' =~ m/$raw/; 1 };
          return "trustedProxy must be a valid Perl regular expression"
            if(!$regexOk);
          $hash->{".$attrName"} = $raw;
        }
      }
    } else {
      delete($hash->{".$attrName"});
    }

    if($attrName eq "validFor") {
      main::readingsSingleUpdate($hash, "state", "validFor:".join(",",@param), 1);
      main::InternalTimer(1, "SecurityCheck", 0) if($main::init_done);
    }
    if($attrName eq "headerAuthPolicy") {
      foreach my $d (main::devspec2array("TYPE=FHEMWEB")) {
        my $sname = $main::defs{$d}{SNAME};
        delete $main::defs{$d}{Authenticated} if($sname && $hash->{".validFor"}{$sname});
      }
      main::InternalTimer(1, "SecurityCheck", 0) if($main::init_done);
    }
    if($attrName eq "trustedProxy") {
      foreach my $d (main::devspec2array("TYPE=FHEMWEB")) {
        my $sname = $main::defs{$d}{SNAME};
        delete $main::defs{$d}{Authenticated} if($sname && $hash->{".validFor"}{$sname});
      }
      main::InternalTimer(1, "SecurityCheck", 0) if($main::init_done);
    }

  } elsif($attrName eq "reportAuthAttempts") {
    if($set) {
      my $p = $param[0];
      return "Wrong value $p for attr $devName report."
        if($p !~ m/^[123]$/);
      $hash->{doReport} = $p;
    } else {
      delete $hash->{doReport};
    }
  } elsif($attrName eq "strict") {
    if($set) {
      my $p = $param[0];
      return "Wrong value $p for attr $devName strict."
        if($p !~ m/^[01]$/);
    }
  }

  return;
}

1;

=pod
=item helper
=item summary    authenticate FHEMWEB requests based on HTTP headers
=item summary_DE authentifiziert FHEMWEB Anfragen anhand von HTTP Headern
=begin html

<a id="WebAuth"></a>
<h3>WebAuth</h3>
<ul>
  <br>

  <a id="WebAuth-define"></a>
  <b>Define</b>
  <ul>
    <code>define &lt;name&gt; WebAuth</code>
    <br><br>
    Authenticate FHEMWEB requests based on HTTP headers, typically injected by
    a trusted reverse proxy or external authentication layer.<br><br>
  </ul>

  <a id="WebAuth-attr"></a>
  <b>Attributes</b>
  <ul>
    <a id="WebAuth-attr-headerAuthPolicy"></a>
    <li>headerAuthPolicy<br>
        JSON object describing nested AND/OR groups and leaf rules.<br>
        Supported matchers are: <code>present</code>, <code>equals</code>,
        <code>notEquals</code>, <code>regex</code>, <code>contains</code>,
        <code>prefix</code>, <code>suffix</code>.<br><br>

        Syntax of a group node:<br>
        <code>{"op":"AND|OR","items":[&lt;node&gt;,...]}</code><br><br>

        Syntax of a leaf rule:<br>
        <code>{"header":"Header-Name","match":"present"}</code><br>
        <code>{"header":"Header-Name","match":"equals|notEquals|regex|contains|prefix|suffix","value":"..."}</code><br><br>

        Header lookup is case-insensitive. <code>contains</code> splits the
        incoming header value on commas and matches whole trimmed items.<br><br>

        Example:<br>
<pre>{
  "op": "AND",
  "items": [
    { "header": "X-Forwarded-User", "match": "present" },
    {
      "op": "OR",
      "items": [
        { "header": "X-Auth-Source", "match": "equals", "value": "oauth2-proxy" },
        { "header": "X-Forwarded-Groups", "match": "contains", "value": "admins" }
      ]
    }
  ]
}</pre>
    </li><br>

    <a id="WebAuth-attr-trustedProxy"></a>
    <li>trustedProxy<br>
        Regexp of trusted reverse-proxy IP addresses or hostnames.<br>
        The check uses the socket peer address of the TCP connection.
        If the peer does not match, WebAuth does not handle the request and
        lets another authenticator, for example <code>allowed</code> with
        <code>basicAuth</code>, try next.<br><br>

        When the peer matches, WebAuth additionally makes the peer IP and a
        client IP derived from <code>Forwarded</code> or
        <code>X-Forwarded-For</code> available to
        <code>headerAuthPolicy</code> via synthetic internal headers.<br><br>

        Example:<br>
<pre>{
  "op": "AND",
  "items": [
    { "header": "X-Forwarded-User", "match": "present" },
    {
      "header": "X-FHEM-Forwarded-Client-IP",
      "match": "regex",
      "value": "^(192\\.168\\.1\\.|10\\.0\\.0\\.)"
    }
  ]
}</pre>
    </li><br>

    <a id="WebAuth-attr-noCheckFor"></a>
    <li>noCheckFor<br>
        Regexp matching paths for which no authentication is required.
    </li><br>

    <a id="WebAuth-attr-reportAuthAttempts"></a>
    <li>reportAuthAttempts {1|2|3}<br>
        If set to 1 or 3, each successful authentication attempt will
        generate an event. If set to 2 or 3, each unsuccessful authentication
        attempt will generate an event.
    </li><br>

    <a id="WebAuth-attr-strict"></a>
    <li>strict {1|0}<br>
        Controls how requests without any relevant authentication headers are
        handled. If set to <code>1</code> (default), such requests are denied
        with <code>403 Forbidden</code>. If set to <code>0</code>, WebAuth
        returns not-responsible and allows a later authenticator, such as
        <code>allowed</code> with <code>basicAuth</code>, to handle the
        request.
    </li><br>

    <a id="WebAuth-attr-validFor"></a>
    <li>validFor<br>
        Comma separated list of frontend instances for which this module is
        active, e.g. <code>WEB</code>.
    </li><br>
  </ul>
</ul>

=end html

=for :application/json;q=META.json 98_WebAuth.pm
{
  "abstract": "authenticates FHEMWEB requests based on HTTP headers",
  "author": [
    "Sidey"
  ],
  "keywords": [
    "Authentication",
    "Authorization",
    "Header",
    "Reverse Proxy",
    "Trusted Proxy",
    "Forward Auth",
    "SSO",
    "OIDC",
    "Web"
  ],
  "x_fhem_prereqs": [
    "a configured FHEMWEB instance referenced by attr validFor",
    "an upstream reverse proxy or authentication layer that injects trusted HTTP headers"
  ],
  "x_lang": {
    "de": {
      "abstract": "authentifiziert FHEMWEB Requests anhand von HTTP Headern"
    }
  },
  "x_version": "0.2.0"
}
=end :application/json;q=META.json

=cut
