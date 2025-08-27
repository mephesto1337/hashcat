#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);
use Crypt::Mode::CBC;
use MIME::Base64 qw (encode_base64 decode_base64);
use Encode;

sub module_constraints { [[7, 7], [8, 8], [-1, -1], [-1, -1], [-1, -1]] }

sub repeat_to_size {
  my $word = shift;
  my $size = shift;

  my $repeat_count = int(($size + length($word) - 1) / length($word));
  return substr($word x $repeat_count, 0, $size);
}

sub pbe_with_sha256_derive_round {
  my $d = shift;
  my $i = shift;
  my $iterations = shift;

  my $hash = sha256($d . $i);
  for (my $i = 1; $i < $iterations; $i++) {
    $hash = sha256($hash);
  }
  return $hash;
}

sub pbe_with_sha256_derive {
  my $id_byte     = shift;
  my $word        = shift;
  my $salt        = shift;
  my $iterations  = shift;
  my $output_size = shift;
  my $v           = 64;
  my $u           = 32;

  my $p = repeat_to_size(encode("UTF-16BE", $word) . "\0\0", $v);
  my $s = repeat_to_size($salt, $v);
  my $d = chr($id_byte) x $v;

  my $rounds = int(($output_size + $u - 1) / $u);
  die("Cannot compute more than 1 round") if ($rounds != 1);

  my $result = pbe_with_sha256_derive_round($d, $s . $p, $iterations);
  return substr($result, 0, $output_size);
}

sub module_generate_hash
{
  my $word         = shift;
  my $salt         = shift // random_bytes(8);
  my $iterations   = shift // 1024;
  my $cipher       = shift;
  my $plain_hash   = shift;
  my $plain        = '';

  my $cbc   = Crypt::Mode::CBC->new ('AES', 1);
  my $key   = pbe_with_sha256_derive(1, $word, $salt, $iterations, 32);
  my $iv    = pbe_with_sha256_derive(2, $word, $salt, $iterations, 16);

  if (!defined($cipher) and !defined($plain_hash)) {
    $plain = random_bytes(16);
    # $plain = decode_base64('UIS3xIypCXX31eNCOKJOYw==');
    $cipher = $cbc->encrypt($plain, $key, $iv);
    $plain_hash = sha256($plain);
  } else {
    $plain = $cbc->decrypt($cipher, $key, $iv);
  }

  if (sha256($plain) ne $plain_hash) {
    die(sprintf("Invalid plain_hash (expected=%s / computed=%s)", encode_base64($plain_hash, ''), encode_base64(sha256($plain), '')));
  }

  return sprintf(
    "pbewithsha256and256bitaes-cbc-bc:%i:%s:%s:%s",
    $iterations,
    encode_base64($salt, ''),
    encode_base64($cipher, ''),
    encode_base64($plain_hash, '')
  );
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (/:([^:]+)$/, $line);

  return unless defined $digest;
  return unless defined $word;

  my @data = split(':', $digest);

  return if scalar(@data) != 5;

  my $signature    = shift @data;
  my $iterations   = int(shift @data);
  my $salt         = decode_base64(shift @data);
  my $cipher       = decode_base64(shift @data);
  my $plain_hash   = decode_base64(shift @data);

  return unless ($signature eq 'pbewithsha256and256bitaes-cbc-bc');

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $cipher, $plain_hash);

  return ($new_hash, $word);
}

1;
