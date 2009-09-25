package MT::Auth::OpenSSOSAML;

use strict;
use base 'MT::Auth::MT';
use MT::Author qw(AUTHOR);
use MT::Util qw( encode_url caturl );
use OpenSSO::Util qw( is_token_valid VALID INVALID MALFORMED );

use constant OPENSSO_BASE_URL       => MT->instance->config->OpenSSOBaseURL;
use constant OPENSSO_SPID           => MT->instance->config->OpenSSOSPID;
use constant OPENSSO_LOGIN_URL      => OPENSSO_BASE_URL . 'UI/Login';
use constant OPENSSO_LOGOUT_URL     => OPENSSO_BASE_URL . 'UI/Logout';
use constant OPENSSO_IS_TOKEN_VALID => OPENSSO_BASE_URL . 'identity/isTokenValid';
use constant OPENSSO_ATTRIBUTES     => OPENSSO_BASE_URL . 'identity/attributes';
use constant OPENSSO_USER_AGENT     => 'OpenSSO (Movable Type)/1.0';

sub can_recover_password { 0 }
sub is_profile_needed { 1 }
sub password_exists { 0 }
sub delegate_auth { 1 }
sub can_logout { 1 }

sub new_user {
    my $auth = shift;
    my ($app, $user) = @_;
    $user->password('(none)');
    0;
}

sub validate_credentials {
    MT->log({ message => 'validate_credentials()' });
    my $auth = shift;
    my ($ctx, %credentials) = @_;

    my $app = $ctx->{app};
    my $username = $ctx->{username};

    MT->log({ message => "User with username: ".($username ? $username : 'none')." accessing application." });

    if ((defined $username) && ($username ne '')) {
        # load author from db
	my $user_class = $app->user_class;
	my ($author) = $user_class->search({ name => $username, type => AUTHOR, }); # auth_type => 'OpenSSO' });

	if ($author) {
            # password validation
	    if ($ctx->{session_id}) {
		$app->user($author);
		return MT::Auth::SUCCESS();
	    }
	}
	if ($author && !$author->is_active) {
	    if ( MT::Author::INACTIVE() == $author->status ) {
		$app->user(undef);
		MT->log({ message => "Failed login attempt: account for $username is inactive" });
		return MT::Auth::INACTIVE();
	    }
	    elsif ( MT::Author::PENDING() == $author->status ) {
		MT->log({ message => "Failed login attempt: account for $username is pending" });
		return MT::Auth::PENDING();
	    }
	}
    }

    my $url = caturl( OPENSSO_BASE_URL , 'idpssoinit' ) . 
	'?realm=/'.
	'&iPSPCookie=yes'.
	'&NameIDFormat=urn:oasis:names:tc:SAML:2.0:nameid-format:transient'.
	'&metaAlias=/idp'.
	'&spEntityID='.OPENSSO_SPID.
	'&binding=urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'.
	'&RelayState='.$app->return_uri();
    
    MT->log({ message => "Redirecting to $url" });
    $app->redirect($url);
    return MT::Auth::REDIRECT_NEEDED();
}

sub fetch_credentials {
    MT->log({ message => 'fetch_credentials()' });
    my $auth = shift;
    return $auth->SUPER::session_credentials(@_);
}

#is_valid_password
#can_recover_password
#is_profile_needed
#password_exists
#validate_credentials
#invalidate_credentials
#delegate_auth
#can_logout
#synchronize
#synchronize_author
#synchronize_group 
#new_user
#new_login
#login_form
#fetch_credentials

1;

__END__

=head1 NAME

MT::Auth::OpenSSO

=head1 METHODS

TODO

=head1 AUTHOR & COPYRIGHT

Please see L<MT/AUTHOR & COPYRIGHT>.

=cut
