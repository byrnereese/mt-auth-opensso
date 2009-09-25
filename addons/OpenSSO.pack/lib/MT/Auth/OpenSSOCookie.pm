package MT::Auth::OpenSSO;

use strict;
use base 'MT::Auth::MT';
use MT::Author qw(AUTHOR);
use MT::Util qw( encode_url );

sub VALID ()          { 1 }
sub INVALID ()        { -1 }
sub MALFORMED ()      { 0 }

use constant OPENSSO_BASE_URL       => MT->instance->config->OpenSSOBaseURL;
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

sub validate_credentials {
    MT->log({ message => 'validate_credentials()' });
    my $auth = shift;
    my ($ctx, %credentials) = @_;

    my $app = $ctx->{app};
    my $username = $ctx->{username};

#    return undef unless (defined $username) && ($username ne '');

    # Quick hack to get round the fact that '+' often gets decoded to ' '
    my $token = $app->cookie_val( $app->config->OpenSSOCookieName );
    $token =~ s/ /\+/g;
    MT->log({ message => "validate_credentials: Open SSO request for token: $token" });

    # Is there an SSO token?
    if ( ! $token ) {
	# If there is no token then the user has never logged in.
	my $url = OPENSSO_BASE_URL . '?goto=' . encode_url( $app->base . $app->path . $app->script );
	$app->redirect($url);
	return MT::Auth::REDIRECT_NEEDED();
    }
		
    # Token present. Is it valid?  
    my $result = is_token_valid($ctx, $token);
    if ( $result == INVALID() ) {
	MT->log({ message => "validate_credentials: token provided ($token) is invalid." });
	return MT::Auth::UNKNOWN();
    } elsif ( $result == MALFORMED() ) {
	# Error validating token
	MT->log({ message => "validate_credentials: open SSO auth cookie malformed: $token" });
	return MT::Auth::UNKNOWN();
    }
	
    # Token valid. Extract a username for lookup.
    my $username = $auth->remote_user( $ctx );

    MT->log({ message => "validate_credentials: looking up $username" });
    my $user = MT->model('author')->load({ name => $username, 
					   type => AUTHOR, 
					   auth_type => $app->config->AuthenticationModule 
					 });
    if ( ! $user ) {
        if ($app->config->ExternalUserManagement) {
            return MT::Auth::NEW_USER();
        } else {
            return MT::Auth::UNKNOWN();
	}
    }
    
    return MT::Auth::SUCCESS();
}

sub token {
    MT->log({ message => 'token()' });
    my $ctx = shift;
    my $app = $ctx->{app};
    my $token = $app->cookie_val( $app->config->OpenSSOCookieName );
    $token =~ s/ /\+/g;
    return $token;
}

sub remote_user {
    MT->log({ message => 'remote_user()' });
    
    my $auth = shift;
    my ($ctx) = @_;

    my $token = token($ctx);
    unless ($token) {
	MT->log({ message => 'remote_user: no token present' });
	return undef;
    }

    MT->log({ message => "remote_user: user request for token: $token" });

    my $app = $ctx->{app};
    my $url = OPENSSO_ATTRIBUTES . '?subjectid=' . encode_url( $token );

    require LWP::UserAgent;
    my $ua = LWP::UserAgent->new;
    $ua->agent(OPENSSO_USER_AGENT);

    my $req = HTTP::Request->new(GET => OPENSSO_IS_TOKEN_VALID);
    # The following may not be necessary
    #$req->header( 'Cookie' => $app->config->OpenSSOCookieName . '=' . $token );
    my $response = $ua->request($req);

    if ( !$response->is_success ) {
	return undef;
    }

    # Need to parse name/value pairs, to get value for username attribute
    my @lines = split( "\n", $response->content );
    my $name;
    foreach my $line (@lines) {
	if ( $line eq 'userdetails.attribute.name=' .  $app->config->OpenSSOUsernameAttribute ) {
	    # use a regex
	    $name = substr( $line, length('userdetails.attribute.name=') );
	    last;
	}
    }
    return $name;
}

sub fetch_credentials {
    MT->log({ message => 'fetch_credentials()' });
    my $auth = shift;
    my ($ctx) = @_;

    # Fetch from SSO Server the remote identity of the current user
    my $remote_user = $auth->remote_user($ctx);
    unless ($remote_user) {
	MT->log({ message => "fetch_credentials: no remote user" });
	# Returning undef will result in MT loading the login form, which we
	# don't want. Instead we need to return an empty hash which will force
	# MT to process validate_credentials which will process redirects as
	# needed.
	return { %$ctx };
    }

    my $fallback = { %$ctx, username => $remote_user };

    # Fetch MT session
    $ctx = $auth->SUPER::session_credentials(@_);
    if (!defined $ctx) {
        if ($remote_user) {
	    # Establish MT session based upon current remote_user
            $ctx = $fallback;
        } else {
            return undef;
        }
    }
    if ($ctx->{username} ne $remote_user) {
        $ctx = $fallback;
    }
    $ctx;
}

sub validate_credentials2 {
    MT->log({ message => 'validate_credentials()' });
    my $auth = shift;
    my ($ctx, %opt) = @_;

    my $app = $ctx->{app};
    my $username = $ctx->{username};
#    return undef unless (defined $user) && ($user ne '');

    my $result = MT::Auth::UNKNOWN();

    # load author from db
    my $author = MT->model('author')->load({ 
	name => $username, 
	type => AUTHOR, 
	auth_type => $app->config->AuthenticationModule 
	});
    if ($author) {
        # author status validation
        if ($author->is_active) {
            $result = MT::Auth::SUCCESS();
            $app->user($author);

            $result = MT::Auth::NEW_LOGIN()
                unless $app->session_user($author, $ctx->{session_id}, %opt);
        } else {
            $result = MT::Auth::INACTIVE();
        }
    } else {
        if ($app->config->ExternalUserManagement) {
            $result = MT::Auth::NEW_USER();
        }
    }

    return $result;
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
