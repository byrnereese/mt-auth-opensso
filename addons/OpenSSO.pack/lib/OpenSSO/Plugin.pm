package OpenSSO::Plugin;

use strict;
use MT::Util qw( encode_html );
use MIME::Base64;
use XML::Simple;
use Date::Parse;

use constant SAML2_SC_SUCCESS   => 'urn:oasis:names:tc:SAML:2.0:status:Success';
use constant SAML2_SC_REQUESTER => 'urn:oasis:names:tc:SAML:2.0:status:Requester';
use constant SAML2_SC_RESPONDER => 'urn:oasis:names:tc:SAML:2.0:status:Responder';
use constant SAML2_SC_VERSION   => 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch';

use constant SAML2_SC_AUTHNFAIL => 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';
use constant SAML2_SC_INVATTRNV => 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrnameOrValue';
use constant SAML2_SC_INVNIDPOL => 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy';
use constant SAML2_SC_NOAUTNCTX => 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext';
use constant SAML2_SC_NOAVALIDP => 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP';
use constant SAML2_SC_NOPASSIVE => 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';
use constant SAML2_SC_NOSUPPIDP => 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP';
use constant SAML2_SC_PARLOGOUT => 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';
use constant SAML2_SC_PROXYCEXC => 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded';
use constant SAML2_SC_REQDENIED => 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied';
use constant SAML2_SC_REQUNSUPP => 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported';
use constant SAML2_SC_REQVERDEP => 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated';
use constant SAML2_SC_REQVERHIG => 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh';
use constant SAML2_SC_REQVERLOW => 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow';
use constant SAML2_SC_RESONRECG => 'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized';
use constant SAML2_SC_TOOMNYRES => 'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses';
use constant SAML2_SC_UNKATTPRO => 'urn:oasis:names:tc:SAML:2.0:status:UnknownAttributeProfile';
use constant SAML2_SC_UNKPRNCPL => 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';
use constant SAML2_SC_UNSUPPBIN => 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding';

use constant XML_SIG_METHOD_RSA => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

sub edit_author {
    my ( $eh, $app, $param, $tmpl) = @_;
    return unless UNIVERSAL::isa($tmpl, 'MT::Template');
    my $q    = $app->param;
    my $type = $q->param('_type');
    my $class = $app->model($type) or return;
    my $id = $q->param('id');
    my $author = $app->user;
    my $obj_promise = MT::Promise::delay(
        sub {
            return $class->load($id) || undef;
        }
    );
    my $obj;
    if ($id) {
        $obj = $obj_promise->force()
          or return $app->error(
            $app->translate(
                "Load failed: [_1]",
                $class->errstr || $app->translate("(no reason given)")
            )
          );
        if ( $type eq 'author' ) {
            require MT::Auth;
            if ( $app->user->is_superuser ) {
                if ( $app->config->ExternalUserManagement ) {
                    if ( MT::Auth->synchronize_author( User => $obj ) ) {
                        $obj = $class->load($id);
                        ## we only sync name and status here
                        $param->{name}   = $obj->name;
                        $param->{status} = $obj->status;
                        if ( ( $id == $author->id ) && ( !$obj->is_active ) ) {
                            ## superuser has been attempted to disable herself - something bad
                            $obj->status( MT::Author::ACTIVE() );
                            $obj->save;
                            $param->{superuser_attempted_disabled} = 1;
                        }
                    }
                    my $id = $obj->external_id;
                    $id = '' unless defined $id;
                    if (length($id) && ($id !~ m/[\x00-\x1f\x80-\xff]/)) {
                        $param->{show_external_id} = 1;
                    }
                }
                delete $param->{can_edit_username};
            }
            else {
                if ( !$app->config->ExternalUserManagement ) {
                    $param->{can_edit_username} = 1;
                }
            }
            $param->{group_count} = $obj->group_count;
        }
    }
    else {    # object is new                                                                                      
        if ( $type eq 'author' ) {
            if ( !$app->config->ExternalUserManagement ) {
                if ( $app->config->AuthenticationModule ne 'MT' ) {
                    $param->{new_user_external_auth} = '1';
                }
            }
        }
    }
    if ( $type eq 'author' ) {
        $param->{'external_user_management'} =
	    $app->config->ExternalUserManagement;
    }
    my $element = $tmpl->getElementById('system_msg');
    if ( $element ) {
        my $contents = $element->innerHTML;
        my $text = <<EOT;
<mt:if name="superuser_attempted_disabled">
    <mtapp:statusmsg
        id="superuser-atempted-disabled"
        class="alert">
        <__trans_section component="enterprise"><__trans phrase="Movable Type Enterprise has just attempted to disable your account during synchronization with the external directory. Some of the external user management settings must be wrong. Please correct your configuration before proceeding."></__trans_section>
    </mtapp:statusmsg>
</mt:if>
EOT
$element->innerHTML($text . $contents);
    }
    $tmpl;
}

sub response {
    my $app = shift;
    my $q = $app->{query};
    my $saml_enc = $q->param('SAMLResponse');
    unless ($saml_enc) { 
	return $app->error("No SAML Response was posted or found.");
    }
    my $response = decode_base64( $saml_enc );
    unless ($response) {
	return $app->error("Unable to decode SAML Response.");
    }
    my $xml = XMLin($response);

    my $status = $xml->{'samlp:Status'}->{'samlp:StatusCode'}->{'Value'};
    unless ( $status eq SAML2_SC_SUCCESS ) {
	$status =~ s/urn:oasis:names:tc:SAML:2.0:status://;
	MT->log({ message => "Authentication error: $status" });
	return $app->error("There was an error in authentication: $status");
    }

    my $nameid = $xml->{'saml:Assertion'}->{'saml:Subject'}->{'saml:NameID'}->{'content'};
    unless ($nameid) {
	return $app->error("No NameID could be found in SAML Response.");
    }

    # TODO: verify certificate/signature
    my $method = $xml->{'saml:Assertion'}->{'Signature'}->{'SignedInfo'}->{'SignatureMethod'}->{'Algorithm'};
    my $message = '';
    my $signature = $xml->{'saml:Assertion'}->{'Signature'}->{'SignatureValue'};
    my $key = '';
#    unless ( _verify_sig($method,$message,$signature,$key) ) {
#	return $app->error("Failed in verifying XML signature.");
#    }

    my $html;
    # TODO: verify NotOnOrAfter for expired assertion
    my $expires = $xml->{'saml:Assertion'}->{'saml:Conditions'}->{'NotOnOrAfter'};
    $html .= "expires: $expires ";
    my $expirest = str2time($expires);
    my $now = time;
    if ($now > $expirest) {
	$html .= "Assertion expired: $expires \n";
	return $app->error("The SAML assertion presented has expired.");
    }

    # Lookup user by NameID
    my $user = MT->model('author')->load({ external_id => $nameid });
    unless ($user) {
	my ($lookup_key,$lookup_col) = split(/:/,$app->config->OpenSSOLookUpAttribute);
	my $value = _get_attr_value($xml,$lookup_key);
	return $app->error("Could not find '$lookup_key' attribute.") if !$value;
	$user = MT->model('author')->load({ $lookup_col => $value });
	if ($user) { 
	    # Associate the nameid with this user for future reference
	    $user->external_id( $nameid );
	    # we will save later
	} else {
	    # TODO - create user unless ExternalUserManagement
	    return $app->error("Unable to locate user with $lookup_col of '$value'");
	}
    }
    my @tosync = split /\s+/s, (MT->config->OpenSSOSyncAttributes || '');
    foreach (@tosync) {
	my ($src,$col) = split /:/, $_;
	my $val = _get_attr_value($xml,$src);
	# TODO: make sure column exists
	$user->$col($val);
    }

    $html .= "Authed: " . $user->email . "\n";
    $user->save() or $app->error("Could not synchronize user.");

    my $cookieparam = $app->start_session( $user, 0 );

    # Append the cookie onto the cookies hash
    # This is necessary in some cases where the cookies are read prior
    # to this code being executed, like (I think) when custom fields
    # are in use.
    require CGI::Cookie;
    $app->{cookies}{$app->user_cookie} = CGI::Cookie->new( %$cookieparam );

    # Get the previously created session's ID and store it in the app parameter
    # hash as a value for the magic_token which is used to validate the session
    my $session = $app->{session};
    $app->param( 'magic_token', $session->id );

    # Store the current user as the $app->user
    $app->user( $user );

    my $url = $q->param('RelayState');
    unless ($url) {
	$url = $app->uri( 'mode' => 'dashboard' );
    }
    return $app->redirect( $url );
}

sub _get_attr_value {
    my ($xml, $name) = @_;
    my $attrs = $xml->{'saml:Assertion'}->{'saml:AttributeStatement'}->{'saml:Attribute'};
    my @elems = grep { $_->{'Name'} eq $name } @$attrs;
    return undef unless @elems;
    return $elems[0]->{'saml:AttributeValue'}->{'content'};
}

sub _verify_sig {
    my ($method, $msg, $sig, $key) = @_;
    if ($method eq XML_SIG_METHOD_RSA) {
    } else {
	return 0;
    }
    return 1;
}

1;

__END__

<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="s274160bdcc86e3bf3588409875ba337573b90da9f" Version="2.0" IssueInstant="2009-09-23T04:36:18Z" Destination="http://blogs.dev.adobe.com/cgi-bin/mt/mt.cgi?__mode=opensso_response">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sjcdsosso-01.corp.adobe.com:1081/opensso</saml:Issuer>
  <samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <samlp:StatusCode  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="s2bcc55ec35b2faf4b24b67c8d2d0a2e1d11ecce0a" IssueInstant="2009-09-23T04:36:18Z" Version="2.0">
    <saml:Issuer>https://sjcdsosso-01.corp.adobe.com:1081/opensso</saml:Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
        <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
        <Reference URI="#s2bcc55ec35b2faf4b24b67c8d2d0a2e1d11ecce0a">
          <Transforms>
            <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </Transforms>
          <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          <DigestValue>Y36/AsIvT1UZGJSrSCDZsDAmJVI=</DigestValue>
        </Reference>
      </SignedInfo>
      <SignatureValue>TRUNCATED</SignatureValue>
      <KeyInfo>
        <X509Data>
          <X509Certificate>TRUNCATED</X509Certificate>
        </X509Data>
      </KeyInfo>
    </Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="https://sjcdsosso-01.corp.adobe.com:1081/opensso" SPNameQualifier="http://blogs.adobe.com/cgi-bin/mt/mt.cgi">oFASExAPmWLoLon6Azx3yBHrN6C1</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2009-09-23T04:46:18Z" Recipient="http://blogs.dev.adobe.com/cgi-bin/mt/mt.cgi?__mode=opensso_response"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2009-09-23T04:26:18Z" NotOnOrAfter="2009-09-23T04:46:18Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://blogs.adobe.com/cgi-bin/mt/mt.cgi</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2009-09-23T19:08:49Z" SessionIndex="s22d6121412abb5880d5edd4bed211be3f7b4f5802">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="cn">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Byrne Reese</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="uid">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">byreese</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">byrne@majordojo.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
