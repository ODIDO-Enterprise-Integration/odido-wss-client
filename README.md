# Example WS-Security client

This application is provided for business partners of Odido B.V., to help them to set up the connectivity to the Odido's legacy SOAP/WS-Security APIs.

The source code is provided free, as-is, without any warranties. It was not thoroughly tested nor performance optimised. Odido Enterprise Integration can provide only best effort support.

The source code may be copied and re-used in the partners' applications without asking for permission.

## Description

The odido-wss-client repository is an example implementation of OASIS/WS-Security v1.0 message signing and signature validation, based on the Apache WSS4J library. 
The following functions are implemented:
- sign a SOAP message (request or response) with a given private key/certificate pair
- verify a signed SOAP message with a list of certificates
- proxy a SOAP/HTTP request to a configured service URL

Requirements:
- Java version: 17+
- Maven

## Development

The repo contains the following source files:
- wss_keystore.jks - test key store file with a self-signed WSS Signature certificate/key pair. This certificate is for local testing only, not trusted by the Odido test API Gateway
- wss_truststore.jks - test key store file with trusted WSS signature certificates (the certificate from the keystore and the WSS certificate of api-agile.odido.nl)
- XmlTools - common functions to parse/render XML documents and create XPath expressions
- WssUtils - common functions to sign SOAP messages and verify signatures
- ProxyServer - A simple embedded Jetty HTTP server with a request handler (for the proxy function)
- ProxyHandler - A Jetty HTTP request handler that
  - signs SOAP requests received from the client
  - forwards the signed request to the configured HTTPS server
  - validates the signature of the received response
  - forwards the received response to the client
- Main - program entry point

## Build and Run

Build and create a jar file with all dependencies:
```shell
mvn clean compile assembly:single
```

Run:
```shell
java -jar target/odido-wss-client-0.0.1-jar-with-dependencies.jar sign {input file to be signed} {signed output file}
java -jar target/odido-wss-client-0.0.1-jar-with-dependencies.jar verify {signed input file}
java -jar target/odido-wss-client-0.0.1-jar-with-dependencies.jar proxy {url to server}
```
