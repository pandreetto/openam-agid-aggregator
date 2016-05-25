# Attribute Aggregator plugin for OpenAM

## Build with Maven

Requirements:

- Java 7
- Maven 3
- OpenAM 13.0.0

Build it with the following command:

  mvn clean install
  
the library is `target/openam-agid-aggregator-0.*.*.jar`

## Installation and setup

Copy the library in $CATALINA_DIR/webapps/openam/WEB-INF/lib/
where CATALINA_DIR is usually /var/lib/tomcat

Install the runtime dependencies into $CATALINA_DIR/webapps/openam/WEB-INF/lib/
- [Bouncycastle](http://search.maven.org/remotecontent?filepath=org/bouncycastle/bcprov-jdk15on/1.51/bcprov-jdk15on-1.51.jar)
- [Commons Httpclient](http://search.maven.org/remotecontent?filepath=commons-httpclient/commons-httpclient/3.1/commons-httpclient-3.1.jar)
- [OpenSAML core](http://search.maven.org/remotecontent?filepath=org/opensaml/opensaml/2.6.4/opensaml-2.6.4.jar)
- [OpenSAML WS](http://search.maven.org/remotecontent?filepath=org/opensaml/openws/1.5.4/openws-1.5.4.jar)
- [OpenSAML xmltooling](http://search.maven.org/remotecontent?filepath=org/opensaml/xmltooling/1.4.4/xmltooling-1.4.4.jar)
- [SSL extras](http://search.maven.org/remotecontent?filepath=ca/juliusdavies/not-yet-commons-ssl/0.3.9/not-yet-commons-ssl-0.3.9.jar)

Define the following properties in the file /etc/sysconfig/tomcat (RedHat, CentOS) or /etc/default/tomcat7 (Ubuntu):
```
JAVA_OPTS="-server -Xms512M -Xmx2048m -XX:MaxPermSize=256m"
```

In the file /etc/openam-agid-aggregator/aggregator.conf define the following properties for the root realm:
```
root.required.attributes=<attribute list>
root.key.manager.file=<keystore_path>
root.key.manager.type=<keystore_type>
root.key.manager.password=<keystore_password>
root.key.alias=<key_alias>
root.key.passphrase=<key_passphrase>
root.trust.manager.file=<truststore_path>
root.trust.manager.type=<truststore_type>
root.trust.manager.password=<truststore_password>
root.entity.id=<sp_entity_id>
root.metadata.cache=<metadata_cache_dir>
```

The properties are:
- `attribute_list`: colon separated list of required attribute names
- `keystore_path`: path of the OpenAM keystore file
- `keystore_type`: the keystore type (JKS or PKCS12, default: JKS)
- `keystore_password`: the password protecting the keystore
- `key_alias`: the alias for the service private key in the keystore
- `key_passphrase`: the passphrase that protects the private key in the keystore
- `truststore_path`: the path of the JVM trust anchors file
- `truststore_type`: the truststore type (JKS or PKCS12, default: JKS)
- `truststore_password`: the password protecting the truststore
- `sp_entity_id`: the entity ID of the Service Provider, as reported in the metadata file
- `metadata_cache_dir`: directory for temporary attribute authority metadata files


Log in the OpenAM Console as administrator.

In `[Realm name]`->`Authentication`->`Core Settings`->`Authentication Post Processing Classes` add the class `it.infn.security.openam.agid.AgIDAggregator`

In `Federation`->`[SP name]`->`Assertion processing`->`Attribute mapper` define the attribute mapper as `it.infn.security.openam.agid.AgIDAggregator` and insert a new Attribute Map item as `uid=spidCode`

In `[Realm name]`->`Agents`->`[Agent name]`->`Application`->`Session Attributes Processing` set `HTTP_HEADER` as fetch mode and add a new Session Attribute Map item for any published attribute

In `Configuration`->`Global`->`Scripting`->`OIDC Claims`->`Engine Configuration`->`Java class whitelist` add the class `it.infn.security.openam.utils.OAuth2ClaimsBuilder`

In `[Realm name]`->`Services`->`[OAuth2 Provider]`->`Supported Scopes` add a new scope `spid`

In `[Realm name]`->`Services`->`[OAuth2 Provider]`->`Supported Claims` add all the attribute names for any Attribute Authority supported

In `[Realm name]`->`Scripts` add the following new groovy script, with type `OIDC Claims`
```
import it.infn.security.openam.utils.OAuth2ClaimsBuilder
import org.forgerock.oauth2.core.UserInfoClaims
return OAuth2ClaimsBuilder.getUserInfoClaims(session, scopes, requestedClaims, logger)
```

In `[Realm name]`->`Services`->`[OAuth2 Provider]`->`OIDC Claims Script` select the new groovy script


