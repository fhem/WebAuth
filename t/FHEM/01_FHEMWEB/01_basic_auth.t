#!/usr/bin/env perl
use strict;
use warnings;

use MIME::Base64 qw(encode_base64);
use Test2::V1 qw(ok is like subtest done_testing);
use Test2::Tools::Compare qw(U);

sub auth_header {
  my ($user, $password) = @_;
  return 'Basic ' . encode_base64("$user:$password", '');
}

sub make_client {
  my (%extra) = @_;
  return {
    TYPE => 'FHEMWEB',
    NAME => 'WEB_127.0.0.1_12345',
    SNAME => 'WEB',
    %extra,
  };
}

subtest 'allowed basicAuth bootstrap' => sub {
  is(fhem('define allowedWEB allowed'), U(), 'allowed device defined');
  is(fhem('attr allowedWEB validFor WEB'), U(), 'allowed device applies to WEB');
  is(
    fhem('attr allowedWEB basicAuth ' . encode_base64('fhemuser:secret', '')),
    U(),
    'basicAuth configured'
  );
  is($defs{allowedWEB}{TYPE}, 'allowed', 'allowed module loaded');
};

subtest 'missing authorization header triggers basic auth challenge' => sub {
  my $client = make_client();
  my %headers = (_Path => '/fhem');

  my $ret = Authenticate($client, \%headers);

  is($ret, 2, 'authentication is required without authorization header');
  like(
    $client->{'.httpAuthHeader'},
    qr/\AHTTP\/1\.1 401 Authorization Required\r?\nWWW-Authenticate: Basic realm="Login required"\r?\n\z/ms,
    'basic auth challenge header is returned'
  );
};

subtest 'valid authorization header authenticates request' => sub {
  my $client = make_client();
  my %headers = (
    _Path => '/fhem',
    Authorization => auth_header('fhemuser', 'secret'),
  );

  my $ret = Authenticate($client, \%headers);

  is($ret, 1, 'valid basic auth header is accepted');
  is($client->{AuthenticatedBy}, 'allowedWEB', 'allowed instance authenticated the client');
  is($client->{AuthenticatedUser}, 'fhemuser', 'authenticated user is extracted from header');
  is($client->{'.httpAuthHeader'}, U(), 'no challenge header is returned after success');
};

subtest 'invalid authorization header is rejected' => sub {
  my $client = make_client();
  my %headers = (
    _Path => '/fhem',
    Authorization => auth_header('fhemuser', 'wrong'),
  );

  my $ret = Authenticate($client, \%headers);

  is($ret, 2, 'invalid basic auth header is rejected');
  is($client->{AuthenticatedUser}, 'fhemuser', 'user is still recorded for denied login');
  like(
    $client->{'.httpAuthHeader'},
    qr/WWW-Authenticate: Basic realm="Login required"\r\n$/m,
    'basic auth challenge header is returned again'
  );
};

subtest 'noCheckFor bypasses authentication for matching paths' => sub {
  is(fhem('attr allowedWEB noCheckFor ^/fhem/icons/favicon$'), U(), 'noCheckFor configured');

  my $client = make_client();
  my %headers = (_Path => '/fhem/icons/favicon');

  my $ret = Authenticate($client, \%headers);

  is($ret, 3, 'matching path bypasses authentication');
  is($client->{'.httpAuthHeader'}, U(), 'no challenge header is generated for bypass');

  is(fhem('deleteattr allowedWEB noCheckFor'), U(), 'noCheckFor removed again');
};

subtest 'basicAuthExpiry accepts auth cookie after successful login' => sub {
  is(fhem('attr allowedWEB basicAuthExpiry 1'), U(), 'cookie expiry enabled');

  my $login_client = make_client();
  my %login_headers = (
    _Path => '/fhem',
    Authorization => auth_header('fhemuser', 'secret'),
  );

  my $login_ret = Authenticate($login_client, \%login_headers);
  is($login_ret, 1, 'initial login succeeds');
  like(
    $login_client->{'.httpAuthHeader'},
    qr/^Set-Cookie: AuthToken=[^;]+; Path=\/ ; Expires=/,
    'successful login returns auth cookie'
  );

  my ($cookie) = $login_client->{'.httpAuthHeader'} =~ /^Set-Cookie: AuthToken=([^;]+);/m;
  ok(defined $cookie, 'auth cookie token extracted from response header');

  my $cookie_client = make_client();
  my %cookie_headers = (
    _Path => '/fhem',
    Cookie => "AuthToken=$cookie",
  );

  my $cookie_ret = Authenticate($cookie_client, \%cookie_headers);
  is($cookie_ret, 1, 'auth cookie is accepted on follow-up request');
  is($cookie_client->{AuthenticatedUser}, 'fhemuser', 'user is restored from auth cookie');
  is($cookie_client->{'.httpAuthHeader'}, U(), 'no replacement cookie is sent for cookie auth');

  is(fhem('deleteattr allowedWEB basicAuthExpiry'), U(), 'cookie expiry disabled again');
};

done_testing();
exit(0);
1;
