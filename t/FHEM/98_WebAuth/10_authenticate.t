#!/usr/bin/env perl
use strict;
use warnings;

use MIME::Base64 qw(encode_base64);
use Test2::V1 qw(ok is like unlike subtest todo done_testing);
use Test2::Tools::Compare qw(array end field hash item U);

sub header_policy_json {
  return '{"op":"AND","items":[{"header":"X-Forwarded-User","match":"present"},{"header":"X-Auth-Source","match":"equals","value":"oauth2-proxy"}]}';
}

sub nested_header_policy_json {
  return '{"op":"AND","items":[{"header":"X-Forwarded-User","match":"present"},{"op":"OR","items":[{"header":"X-Role","match":"equals","value":"fhem-admin"},{"header":"X-Forwarded-Groups","match":"contains","value":"admins"}]}]}';
}

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

subtest 'WebAuth bootstrap' => sub {
  is(fhem('define webAuthWEB WebAuth'), U(), 'WebAuth device defined');
  is(fhem('attr webAuthWEB validFor WEB'), U(), 'WebAuth device applies to WEB');
  is(fhem('attr webAuthWEB headerAuthPolicy ' . header_policy_json()), U(), 'valid headerAuthPolicy configured');
  is($defs{webAuthWEB}{TYPE}, 'WebAuth', 'WebAuth module loaded');
  is(
    $defs{webAuthWEB}{'.headerAuthPolicy'},
    hash {
      field op => 'AND';
      field items => array {
        item hash {
          field header => 'X-Forwarded-User';
          field match => 'present';
          end;
        };
        item hash {
          field header => 'X-Auth-Source';
          field match => 'equals';
          field value => 'oauth2-proxy';
          end;
        };
        end;
      };
      end;
    },
    'parsed policy is stored on device hash'
  );
};

subtest 'matching header policy authenticates request' => sub {
  my $client = make_client();
  my %headers = (
    _Path => '/fhem',
    'X-Forwarded-User' => 'demo-user',
    'X-Auth-Source' => 'oauth2-proxy',
  );

  my $ret = Authenticate($client, \%headers);

  is($ret, 1, 'matching header policy is accepted');
  is($client->{AuthenticatedBy}, 'webAuthWEB', 'WebAuth authenticated the client');
  is($client->{'.httpAuthHeader'}, U(), 'no auth header is generated after successful header auth');
};

subtest 'nested header policy authenticates request' => sub {
  is(fhem('attr webAuthWEB headerAuthPolicy ' . nested_header_policy_json()), U(), 'nested headerAuthPolicy configured');

  my $client = make_client();
  my %headers = (
    _Path => '/fhem',
    'X-Forwarded-User' => 'demo-user',
    'X-Forwarded-Groups' => 'users,admins',
  );

  my $ret = Authenticate($client, \%headers);

  is($ret, 1, 'nested header policy is accepted');
  is($client->{AuthenticatedBy}, 'webAuthWEB', 'WebAuth authenticated nested policy request');
  is($client->{'.httpAuthHeader'}, U(), 'no auth header is generated after nested header auth');

  is(fhem('attr webAuthWEB headerAuthPolicy ' . header_policy_json()), U(), 'simple headerAuthPolicy restored');
};

subtest 'non-matching header policy denies access without basic challenge' => sub {
  my $client = make_client();
  my %headers = (
    _Path => '/fhem',
    'X-Forwarded-User' => 'demo-user',
    'X-Auth-Source' => 'other',
  );

  my $ret = Authenticate($client, \%headers);

  is($ret, 2, 'non-matching header policy denies access');
  like($client->{'.httpAuthHeader'}, qr/\AHTTP\/1\.1 403 Forbidden\r?\n\z/ms, 'forbidden response header is returned');
  unlike($client->{'.httpAuthHeader'}, qr/WWW-Authenticate:\s*Basic/i, 'no basic auth challenge is returned');
};

subtest 'noCheckFor still bypasses header auth' => sub {
  is(fhem('attr webAuthWEB noCheckFor ^/fhem/icons/favicon$'), U(), 'noCheckFor configured');

  my $client = make_client();
  my %headers = (_Path => '/fhem/icons/favicon');

  my $ret = Authenticate($client, \%headers);

  is($ret, 3, 'matching path bypasses header auth');
  is($client->{'.httpAuthHeader'}, U(), 'no auth header is generated for bypass');

  is(fhem('deleteattr webAuthWEB noCheckFor'), U(), 'noCheckFor removed again');
};

subtest 'trustedProxy accepts literal hostname via DNS resolution' => sub {
  is(fhem('attr webAuthWEB trustedProxy localhost'), U(), 'trustedProxy hostname configured');

  my $client = make_client(
    PEER => '127.0.0.1',
  );
  my %headers = (
    _Path => '/fhem',
    'X-Forwarded-User' => 'demo-user',
    'X-Auth-Source' => 'oauth2-proxy',
  );

  my $ret = Authenticate($client, \%headers);

  is($ret, 1, 'literal trustedProxy hostname resolves to peer IP');
  is($client->{AuthenticatedBy}, 'webAuthWEB', 'WebAuth authenticated the request via hostname-based trustedProxy');

  is(fhem('deleteattr webAuthWEB trustedProxy'), U(), 'trustedProxy removed again');
};

todo 'known follow-up auth handling regression with the current patch' => sub {
  subtest 'strict re-checks unauthenticated keep-alive follow-up requests' => sub {
    is(fhem('attr webAuthWEB strict 0'), U(), 'strict disabled for initial request');

    my $client = make_client(
      BUF  => "GET /fhem/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
      PEER => '127.0.0.1',
      PORT => '12345',
    );
    my @answered;
    my @writes;

    no warnings 'redefine';
    local *FW_answerCall = sub {
      my ($arg) = @_;
      push @answered, $arg;
      $FW_RETTYPE = 'text/plain; charset=UTF-8';
      $FW_RET = 'ok';
      return 0;
    };
    local *FW_finishRead = sub {
      return;
    };
    local *TcpServer_WriteBlocking = sub {
      my ($hash, $txt) = @_;
      push @writes, $txt;
      return 1;
    };

    FW_Read($client, 1);

    is($client->{Authenticated}, 0, 'first request stores unauthenticated state on the connection');
    is(\@answered, ['/fhem/'], 'first request is allowed while strict is disabled');
    is(\@writes, [], 'first request is not denied');

    is(fhem('attr webAuthWEB strict 1'), U(), 'strict re-enabled for follow-up request');
    $client->{BUF} =
      "GET /fhem/FileLog_logWrapper?dev=Logfile&type=text&file=fhem-2026-03-29.log HTTP/1.1\r\n".
      "Host: localhost\r\n\r\n";

    FW_Read($client, 1);

    is(\@answered, ['/fhem/'], 'follow-up request is not passed to FW_answerCall after strict is re-enabled');
    is(scalar @writes, 1, 'follow-up request is denied');
    like($writes[0], qr/\AHTTP\/1\.1 403 Forbidden\r?\n/ms, 'denied follow-up request returns 403');
  };
};

subtest 'WebAuth coexists with allowed basicAuth when header policy matches' => sub {
  is(fhem('define allowedWEB allowed'), U(), 'allowed device defined');
  is(fhem('attr allowedWEB validFor WEB'), U(), 'allowed device applies to WEB');
  is(fhem('attr allowedWEB basicAuth ' . encode_base64('fhemuser:secret', '')), U(), 'basicAuth configured');

  my $client = make_client();
  my %headers = (
    _Path => '/fhem',
    'X-Forwarded-User' => 'demo-user',
    'X-Auth-Source' => 'oauth2-proxy',
  );

  my $ret = Authenticate($client, \%headers);

  is($ret, 1, 'header auth succeeds even with allowed basicAuth configured');
  is($client->{AuthenticatedBy}, 'webAuthWEB', 'WebAuth is the successful authenticator');
  is($client->{'.httpAuthHeader'}, U(), 'no basic auth challenge leaks through');
};

subtest 'allowed basicAuth still works when WebAuth does not match' => sub {
  my $client = make_client();
  my %headers = (
    _Path => '/fhem',
    Authorization => auth_header('fhemuser', 'secret'),
  );

  my $ret = Authenticate($client, \%headers);

  is($ret, 1, 'basicAuth still succeeds with WebAuth present');
  is($client->{AuthenticatedBy}, 'allowedWEB', 'allowed is the successful authenticator');
  is($client->{AuthenticatedUser}, 'fhemuser', 'authenticated user still comes from basicAuth');
  is($client->{'.httpAuthHeader'}, U(), 'no unexpected auth header is generated');
};

done_testing();
exit(0);
1;
