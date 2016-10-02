vulnerable_soap_service
=======================

This is a SOAP service written in C# that has intentional SQL injection vulnerabilties.


Works on Linux with Mono and XSP 4. Should work on Windows with Visual Studio.


A simple fuzzer for the SOAP endpoint is included in fuzzer/ and integrates in with SQLMap when it finds a vulnerable method.

The fuzzer is meant to be run on the example endpoint included and no guarantees are made it will work for complex WSDL's.

This is available in a virtual appliance from VulnHub.com

https://www.vulnhub.com/entry/csharp-vulnsoap,135/
