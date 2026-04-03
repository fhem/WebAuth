#!/usr/bin/env perl

use strict;
use warnings;

use Cwd qw(abs_path);
use JSON::PP qw(decode_json);
use FindBin qw($Bin);
use File::Spec;

my $repo_root = abs_path(File::Spec->catdir($Bin, '..'));
my $module_path = File::Spec->catfile($repo_root, 'FHEM', '98_WebAuth.pm');
my $readme_path = File::Spec->catfile($repo_root, 'README.md');

my $module = _slurp_utf8($module_path);
my $readme = _slurp_utf8($readme_path);

my ($summary) = $module =~ m/^=item\s+summary\s+(.+)$/m;
my ($summary_de) = $module =~ m/^=item\s+summary_DE\s+(.+)$/m;
my ($html_block) = $module =~ m/^=begin html\s*\n(.*?)\n^=end html$/ms;
my ($meta_json) = $module =~ m/^=for :application\/json;q=META\.json 98_WebAuth\.pm\s*\n(.*?)\n^=end :application\/json;q=META\.json$/ms;

die "Missing POD summary in $module_path\n" if !defined $summary;
die "Missing POD summary_DE in $module_path\n" if !defined $summary_de;
die "Missing HTML commandref block in $module_path\n" if !defined $html_block;
die "Missing META.json block in $module_path\n" if !defined $meta_json;

my $meta = decode_json($meta_json);
my $doc = _parse_commandref_html($html_block);

my @reference_lines = (
  "## Module Reference",
  "",
  "Generated from [`FHEM/98_WebAuth.pm`]($module_path).",
  "",
  "- Summary: $summary",
  "- Zusammenfassung: $summary_de",
  "- Version: ".($meta->{x_version} // 'n/a'),
  "- Author: ".join(', ', @{$meta->{author} // []}),
);

if (my $keywords = $meta->{keywords}) {
  push @reference_lines, "- Keywords: ".join(', ', @{$keywords});
}

push @reference_lines, '';
push @reference_lines, "### Dependencies";

my @dependencies = _render_dependencies($meta);
push @reference_lines, map { "- $_" } @dependencies;

push @reference_lines, '';
push @reference_lines, "### Usage";
push @reference_lines, '';
push @reference_lines, '```text';
push @reference_lines, $doc->{define_command};
push @reference_lines, '```';
push @reference_lines, '';
push @reference_lines, _wrap_text($doc->{define_description});

push @reference_lines, '';
push @reference_lines, "### Attributes";
push @reference_lines, '';

for my $attribute (@{$doc->{attributes}}) {
  push @reference_lines, "- `".$attribute->{name}."`: ".$attribute->{description};
  if (@{$attribute->{examples}}) {
    for my $example (@{$attribute->{examples}}) {
      push @reference_lines, '';
      push @reference_lines, '```json';
      push @reference_lines, $example;
      push @reference_lines, '```';
    }
  }
}

my $reference_block = join("\n", @reference_lines)."\n";

$readme = _replace_block(
  $readme,
  'GENERATED MODULE REFERENCE',
  $reference_block,
);

_spew_utf8($readme_path, $readme);

sub _replace_block {
  my ($content, $name, $replacement) = @_;

  my $begin = "<!-- BEGIN $name -->";
  my $end = "<!-- END $name -->";
  my $pattern = qr/\Q$begin\E\n.*?\n\Q$end\E/s;
  my $block = $begin."\n".$replacement.$end;

  die "Missing README marker block for $name\n" if $content !~ $pattern;

  $content =~ s/$pattern/$block/s;
  return $content;
}

sub _render_dependencies {
  my ($meta) = @_;

  my @dependencies;
  my $runtime_requires = $meta->{prereqs}{runtime}{requires} // {};

  for my $name (sort keys %{$runtime_requires}) {
    push @dependencies, "$name >= $runtime_requires->{$name}";
  }

  if (my $fhem = $meta->{x_fhem_prereqs}) {
    push @dependencies, @{$fhem};
  }

  push @dependencies, 'none declared' if !@dependencies;
  return @dependencies;
}

sub _parse_commandref_html {
  my ($html) = @_;

  my ($define_command) = $html =~ m{<code>(define .*?)</code>}s;
  my ($define_section) = $html =~ m{<a id="WebAuth-define"></a>.*?<code>define .*?</code>\s*<br><br>\s*(.*?)\s*<br><br>\s*</ul>}s;
  die "Unable to parse define section\n" if !defined $define_command || !defined $define_section;

  my @attributes;
  while ($html =~ m{<a id="WebAuth-attr-([^"]+)"></a>\s*<li>(.*?)</li>}sg) {
    my $slug = $1;
    my $body = $2;

    my ($name) = $body =~ m{^\s*([^<\n]+)<br>}s;
    $name //= $slug;

    my @examples;
    while ($body =~ m{<pre>(.*?)</pre>}sg) {
      my $example = $1;
      $example =~ s/^\n+//;
      $example =~ s/\n+$//;
      push @examples, $example;
    }

    $body =~ s{<pre>.*?</pre>}{}sg;
    my $description = _html_to_markdown_text($body);
    $description =~ s/^\Q$name\E\s*//;
    $description =~ s/\s+/ /g;
    $description =~ s/\s+([.,:;])/$1/g;

    push @attributes, {
      name => $name,
      description => $description,
      examples => \@examples,
    };
  }

  return {
    define_command => _decode_html_entities($define_command),
    define_description => _html_to_markdown_text($define_section),
    attributes => \@attributes,
  };
}

sub _html_to_markdown_text {
  my ($text) = @_;

  $text =~ s{<code>(.*?)</code>}{'`'._decode_html_entities($1).'`'}sge;
  $text =~ s{<br\s*/?>}{\n}g;
  $text =~ s{</?(?:ul|li|b|a)[^>]*>}{}g;
  $text =~ s/\n{3,}/\n\n/g;
  $text =~ s/^\s+//;
  $text =~ s/\s+$//;

  my @lines = grep { $_ ne '' } map {
    my $line = $_;
    $line =~ s/^\s+//;
    $line =~ s/\s+$//;
    $line;
  } split /\n/, _decode_html_entities($text);
  return join("\n\n", @lines);
}

sub _decode_html_entities {
  my ($text) = @_;

  return '' if !defined $text;

  $text =~ s/&lt;/</g;
  $text =~ s/&gt;/>/g;
  $text =~ s/&quot;/"/g;
  $text =~ s/&#39;/'/g;
  $text =~ s/&amp;/&/g;
  return $text;
}

sub _wrap_text {
  my ($text) = @_;
  $text =~ s/\s*\n\s*/ /g;
  $text =~ s/\s{2,}/ /g;
  return $text;
}

sub _slurp_utf8 {
  my ($path) = @_;

  open my $fh, '<:encoding(UTF-8)', $path
    or die "Unable to read $path: $!\n";
  local $/;
  return <$fh>;
}

sub _spew_utf8 {
  my ($path, $content) = @_;

  open my $fh, '>:encoding(UTF-8)', $path
    or die "Unable to write $path: $!\n";
  print {$fh} $content
    or die "Unable to write $path: $!\n";
  close $fh
    or die "Unable to close $path: $!\n";
  return;
}
