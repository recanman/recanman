#!/usr/bin/perl
# made by recanman
use strict;
use warnings;

use LWP::UserAgent;
use JSON;

my $pgp_fingerprint = 'ED64869256105CBEF642A7A253C1853B0D753C51';

sub readable_pgp_fingerprint {
	my $fingerprint = shift;
	$fingerprint =~ s/(.{4})/$1 /g;
	$fingerprint =~ s/\s+$//;
	return $fingerprint;
}

sub get_last_block_header {
	my $url = 'http://localhost:18081/json_rpc';
	my $ua = LWP::UserAgent->new;
	my $req = HTTP::Request->new('POST', $url);
	$req->header('Content-Type' => 'application/json');
	my $json = JSON->new;
	my $data = $json->encode({
		"jsonrpc" => "2.0",
		"id"      => "0",
		"method"  => "get_last_block_header",
		"params"  => {}
	});
	$req->content($data);
	my $res = $ua->request($req);

	if ($res->is_success) {
		my $decoded_json = $json->decode($res->decoded_content);

		my $hash = $decoded_json->{'result'}->{'block_header'}->{'hash'};
		my $height = $decoded_json->{'result'}->{'block_header'}->{'height'};
		
		return ($height, $hash);
	} else {
		print STDERR "Error: " . $res->status_line . "\n";
		return undef;
	}
}

sub get_dates {
	my $date = `date +%Y-%m-%d`;
	chomp $date;
	my $next_date_timestamp = `date -d "$date + 3 months" +%s`;
	chomp $next_date_timestamp;
	my $next_date = `date -d \@$next_date_timestamp +%Y-%m-%d`;
	chomp $next_date;
	return ($date, $next_date);
}

sub generate_canary {
	my ($date, $next_date) = get_dates();
	my ($block_height, $block_hash) = get_last_block_header();
	my $readable_pgp_fingerprint = readable_pgp_fingerprint($pgp_fingerprint);

	my $canary = <<"EOF";
recanman warrant canary
=======================
Last updated: $date, next update before: $next_date
Lastest Monero block height: $block_height ($block_hash)

=== Online Presence ===
Website: http://recanman7nly4wwc5f2t2h55jnxsr7wo664o3lsydngwetvrguz4esid.onion
PGP Key: https://recanman7nly4wwc5f2t2h55jnxsr7wo664o3lsydngwetvrguz4esid.onion/pgp.txt
Canary: https://recanman7nly4wwc5f2t2h55jnxsr7wo664o3lsydngwetvrguz4esid.onion/canary
Canary (mirror): https://gist.github.com/recanman/90f3591fde77a63532bb372a566e6e6a

GitHub: https://github.com/recanman
XMRBazaar: https://xmrbazaar.com/user/recanman
Monero GitLab: https://repo.getmonero.org/recanman
Matrix: \@recanman:kernal.eu
Email: recanman\@kernal.eu

=== Statements ===
1. All of my infrastructure is in my control. The integrity of my systems are sound.

2. I have not been compromised by any government or third party.

3. I have not disclosed any private keys, passwords, or other sensitive information to any third party.

4. I have not been served with a warrant, subpoena, or other legal request that would prevent me from releasing this canary, or from making the statements contained herein.

5. My personal safety and security are not at risk, and I am not under duress.

6. If this canary is not updated by $next_date, or if this canary is removed, it will be considered a breach of the statements contained herein, and a signal that I may have been compromised or served with a legal request.

=== Verification Instructions ===
PGP fingerprint: $readable_pgp_fingerprint

1. Import my key: `gpg --import <path_to_my_key>`
2. Verify the canary: `gpg --verify canary-$date.txt`
EOF

	my $filename = "canary-$date.txt";
	return ($canary, $filename)
}

sub main {
	my ($canary, $filename) = generate_canary();
	open my $fh, '>', $filename or die "Could not open file '$filename' $!";
	print $fh $canary;
	close $fh or die "Could not close file '$filename' $!";

	print "Generated canary $filename!\n\n";
	print "To sign the canary, run the following command:\n";
	print "export TZ=UTC; gpg --clearsign --default-key $pgp_fingerprint $filename\n";
}
main();