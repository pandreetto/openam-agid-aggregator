# Attribute Aggregator plugin for OpenAM

## Build with Maven

Requirements:

- Java 7
- Maven 3
- OpenAM 12.0.0

Build it with the following command:

  mvn clean install
  
the library is target/openam-agid-aggregator-0.*.*.jar

## Installation and setup

Copy the library in $CATALINA_DIR/webapps/openam/WEB-INF/lib/
where CATALINA_DIR is usually /var/lib/tomcat

Log in the OpenAM Console as administrator.
In `Access Control`->`[Realm name]`->`Authentication`->`Core Settings`->`Authentication Post Processing Classes` add the class `it.infn.security.openam.agid.AgIDAggregator`
In `Federation`->`[SP name]`->`Assertion processing`->`Attribute mapper` define the attribute mapper as `it.infn.security.openam.agid.AgIDAggregator` and insert a new Attribute Map item as `uid=spidCode`
In `Access Control`->`[Realm name]`->`Agents`->`[Agent name]`->`Application`->`Session Attributes Processing` se `HTTP_HEADER` as fetch mode and add a new Session Attribute Map item for any published attribute 
