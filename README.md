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
JAVA_OPTS="-server -Xms512M -Xmx2048m -XX:MaxPermSize=256m \
  -Dit.infn.security.openam.agid.required.attributes=<attribute list> \
  -Dit.infn.security.openam.agid.key.manager.file=<keystore_path> \
  -Dit.infn.security.openam.agid.key.manager.type=<keystore_type> \
  -Dit.infn.security.openam.agid.key.manager.password=<keystore_password> \
  -Dit.infn.security.openam.agid.key.manager.alias=<keystore_alias> \
  -Dit.infn.security.openam.agid.trust.manager.file=<truststore_path> \
  -Dit.infn.security.openam.agid.trust.manager.type=<truststore_type> \
  -Dit.infn.security.openam.agid.trust.manager.password=<truststore_password> \
  -Dit.infn.security.openam.agid.entity.id=<sp_entity_id> \
  -Dit.infn.security.openam.agid.metadata.cache=<metadata_cache_dir>"
```

The properties are:
- `attribute_list`: colon separated list of required attribute names
- `keystore_path`: path of the OpenAM keystore file (/usr/share/tomcat/openam/openam/keystore.jks)
- `keystore_type`: the keystore type (JKS or PKCS12)
- `keystore_password`: the password protecting the keystore
- `keystore_alias`: the alias for the service certificate in the keystore
- `truststore_path`: the path of the JVM trust anchors file (/etc/pki/ca-trust/extracted/java/cacerts)
- `truststore_type`: the truststore type (JKS or PKCS12)
- `truststore_password`: the password protecting the truststore (changeit)
- `sp_entity_id`: the entity ID of the Service Provider, as reported in the metadata file
- `metadata_cache_dir`: directory for temporary attribute authority metadata files (/usr/share/tomcat/openam/openam/metadata)


Log in the OpenAM Console as administrator.

In `Access Control`->`[Realm name]`->`Authentication`->`Core Settings`->`Authentication Post Processing Classes` add the class `it.infn.security.openam.agid.AgIDAggregator`

In `Federation`->`[SP name]`->`Assertion processing`->`Attribute mapper` define the attribute mapper as `it.infn.security.openam.agid.AgIDAggregator` and insert a new Attribute Map item as `uid=spidCode`

In `Access Control`->`[Realm name]`->`Agents`->`[Agent name]`->`Application`->`Session Attributes Processing` se `HTTP_HEADER` as fetch mode and add a new Session Attribute Map item for any published attribute 
