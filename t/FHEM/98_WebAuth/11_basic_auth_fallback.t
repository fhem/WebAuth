#!/usr/bin/env perl
use strict;
use warnings;

use MIME::Base64 qw(encode_base64);
use Test::More;

sub auth_header {
  my ($user, $password) = @_;
  return 'Basic ' . encode_base64("$user:$password", '');
}

sub make_client {
  return {
    TYPE => 'FHEMWEB',
    NAME => 'WEB_127.0.0.1_12345',
    SNAME => 'WEB',
  };
}

is(fhem('define webAuthWEB WebAuth'), undef, 'WebAuth device defined');
is(fhem('attr webAuthWEB validFor WEB'), undef, 'WebAuth validFor set');
is(
  fhem(
    'attr webAuthWEB headerAuthPolicy {"op":"AND","items":[{"header":"X-Forwarded-User","match":"present"},{"header":"X-Auth-Source","match":"equals","value":"oauth2-proxy"}]}'
  ),
  undef,
  'policy set'
);
is(fhem('attr webAuthWEB strict 0'), undef, 'strict fallback mode enabled');

is(fhem('define allowedWEB allowed'), undef, 'allowed device defined');
is(fhem('attr allowedWEB validFor WEB'), undef, 'allowed validFor set');
is(
  fhem('attr allowedWEB basicAuth ' . encode_base64('fhemuser:secret', '')),
  undef,
  'basicAuth set'
);

my $challenge_client = make_client();
my %challenge_headers = (_Path => '/fhem');
my $challenge_ret = Authenticate($challenge_client, \%challenge_headers);

is($challenge_ret, 2, 'missing headers still require auth');
like(
  $challenge_client->{'.httpAuthHeader'},
  qr/WWW-Authenticate: Basic realm="Login required"/,
  'basic auth challenge survives when webauth headers are absent'
);
unlike(
  $challenge_client->{'.httpAuthHeader'},
  qr/403 Forbidden/,
  'webauth does not overwrite fallback with 403'
);

my $basic_client = make_client();
my %basic_headers = (
  _Path => '/fhem',
  Authorization => auth_header('fhemuser', 'secret'),
);
my $basic_ret = Authenticate($basic_client, \%basic_headers);

is($basic_ret, 1, 'basic auth still succeeds');
is($basic_client->{AuthenticatedBy}, 'allowedWEB', 'allowed authenticates request');

my $strict_client = make_client();
is(fhem('attr webAuthWEB strict 1'), undef, 'strict mode enabled');
my %strict_headers = (_Path => '/fhem');
my $strict_ret = Authenticate($strict_client, \%strict_headers);

is($strict_ret, 2, 'strict mode denies requests without auth headers');
like($strict_client->{'.httpAuthHeader'}, qr/\AHTTP\/1\.1 403 Forbidden\r?\n\z/ms, 'strict mode returns forbidden response');

done_testing();
exit(0);
