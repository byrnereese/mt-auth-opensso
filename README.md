This plugin for Movable Type and Melody provides support 
for the OpenSSO protocol for single sign on between a set of
federated servers and services.

When you install this plugin and configure it properly, then the
default Movable Type login form will be bypassed and users will be
redirected to the designated service (not Movable Type) to 
authenticate.

# About OpenSSO

The "SSO" of OpenSSO stands for "Single Sign On" or the ability to use a 
single username and password to access a set of distributed and disparate 
services or applications. From the project's web site:

> The Open Web SSO project (OpenSSO) provides core identity services to simplify the implementation of transparent single sign-on (SSO) as a security component in a network infrastructure. OpenSSO provides the foundation for integrating diverse web applications that might typically operate against a disparate set of identity repositories and are hosted on a variety of platforms such as web and application servers. This project is based on the code base of Sun JavaTM System Access Manager, a core identity infrastructure product offered by Sun Microsystems. 

# Installation

To install this plugin follow the instructions found here:

http://tinyurl.com/easy-plugin-install

# Setup and Configuration

Once the plugin is installed you will need to configure both your OpenSSO
server and Movable Type properly in order to use OpenSSO in favor of the 
default login experience. 

## Setup OpenSSO Servers

In order to begin, you must first setup a "Service Provider" within your
OpenSSO server for the Movable Type installation in question.

In creating a Service Provider you will provide or be given a "Service
Prodiver ID." Make note of this value as you will need to enter it into your
Movable Type configuration file. 

Once your OpenSSO server has been properly setup, you will then need to 
configure Movable Type. 

## Setup Movable Type

To get started you will need to tell Movable Type to use a different
authenication driver than whatever is currently configured. That is done
by adding the following lines to your mt-config.cgi file:

    AuthenticationModule OpenSSOSAML
    OpenSSOSPID http://blogs.adobe.com/cgi-bin/mt/mt.cgi
    OpenSSOBaseURL https://sjcdsosso.corp.adobe.com:443/opensso
    OpenSSOLookUpAttribute uid:name
    OpenSSOSyncAttributes mail:email cn:nickname

To make sense of this please consult the configuration directive reference
below.

## Configuration Directives

* `OpenSSOSPID` is the Service Provider ID you provided or were given by your
  OpenSSO server when you setup your service provider for Movable TYpe.

* `OpenSSOBaseURL` refers to the root URL for your entire OpenSSO server 
  installation. To this URL will be appended a number of different paths 
  and parameters in order to facilitate the protocol and authentication
  process. 

* `OpenSSOLookUpAttribute` controls how users within your external user store 
  will be correlated to users within Movable Type. The value of this directive
  is a name/value pair (delimitted by a colon, ':') in which the first element
  refers to the property name coming from the source system, and the second 
  element refers to the MT::Author property to which the first element will be
  matched. 

* `OpenSSOSyncAttributes` controls which fields/attributes coming from the
  source system will be synchronized within Movable Type whenever a user
  successfully authenticates. The value of this directive is a list of
  name/value pairs that collectively map attributes from the source system
  to MT::Author properties in Movable Type.

## About User Correlation

When a user from the external system successfully authenticates with Movable
Type, then the system must properly correlate the incoming user with a user
within Movable Type. Given the inherent disparity likely to exist between users
within an external system and Movable Type, it is important for users to be 
able to specify how users in the two system can be uniquely correlated and
mapped to one another. Let's look at an example.

One common way for users to be uniquely identifiable within a system is their
email address. Let's suppose that within Acme Inc's system, every user has a
property called "mail-address" which stores an email address. Movable Type also
supports email addressed, but it uses a property called "email" to store that 
value. Therefore to create an effective mapping between these two one would 
need to instruct Movable Type about this mapping using the 
`OpenSSOLookUpAttribute` configuration directive. It uses the following 
syntax:

    OpenSSOLookUpAttribute <external property>:<MT::Author property>

Using the example discussed above, the configuration directive for your 
mt-config.cgi file would look like this:

    OpenSSOLookUpAttribute mail-address:email

**Important: In order for this correlation to occur, you need to make sure
that the service provider within your OpenSSO server has been setup to 
transmit the property necessary for correlation to occur.**

## About Profile Synchronization

Whenever a user successfully authenticates into Movable Type using this 
driver, the system will attempt to automatically update the information it has
on record for the incoming user within Movable Type. This helps keep valuable
profile data in sync with the external system. 

Let's suppose for a second that your internal system has a field associated
with every user that holds their full name. Let's suppose this field is called
"cn". To synchonize this field with the "Display Name" field in Movable Type
one would specify the following configuration directive:

    OpenSSOSyncAttributes cn:nickname

And if there were several such properties, just separate them using spaces
like so:

    OpenSSOSyncAttributes mail:email cn:nickname