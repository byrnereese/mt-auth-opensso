package OpenSSO::Util;

use strict;
use base 'Exporter';
our @EXPORT_OK = qw( is_token_valid VALID INVALID MALFORMED );

use constant OPENSSO_BASE_URL       => MT->instance->config->OpenSSOBaseURL;
use constant OPENSSO_IS_TOKEN_VALID => OPENSSO_BASE_URL . 'identity/isTokenValid';
use constant OPENSSO_USER_AGENT     => 'OpenSSO (Movable Type)/1.0';

sub VALID ()          { 1 }
sub INVALID ()        { -1 }
sub MALFORMED ()      { 0 }

sub is_token_valid {
    my ($ctx, $token) = @_;
    my $app = $ctx->{app};

    require LWP::UserAgent;
    my $ua = LWP::UserAgent->new;
    $ua->agent(OPENSSO_USER_AGENT);

    my $req = HTTP::Request->new(GET => OPENSSO_IS_TOKEN_VALID);
    $req->header( 'Cookie' => $app->config->OpenSSOCookieName . '=' . $token );
    my $response = $ua->request($req);

    if ( !$response->is_success ) {
	MT->log({ message => "is_token_valid: " . $response->status_line });
	return INVALID();
    }
    
    if ( substr( trim( $response->content ), 8 ) == 'true' ) {
	return VALID();
    }
    
    return MALFORMED();
}

