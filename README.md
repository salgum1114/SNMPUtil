# SNMPUtil

This project simply send SNMP OID

# How to use

// Run Option

window
- SNMPUtil.exe < snmpgetv2c | snmpsetv2c > <host> <port> <community> <oid>
- SNMPUtil.exe < snmpgetv3 | snmpsetv3 > <host> <port> <username> <auth_privacy> <auth> <auth-key> <priv> <priv-key> <contextname> <oid> < i | u | x | s > <value>

linux
- java -jar SNMPUtil.jar < snmpgetv2c | snmpsetv2c > <host> <port> <community> <oid>
- java -jar SNMPUtil.jar < snmpgetv3 | snmpsetv3 > <host> <port> <username> <auth_privacy> <auth> <auth-key> <priv> <priv-key> <contextname> <oid> < i | u | x | s > <value>

// Example

window
- SNMPUtil.exe snmpsetv3 127.0.0.1 161 OpenViewUser AUTH_NOPRIVACY MD5 auth1234 AES256 priv1234 contextName .1.3.6.1.4.1.9.9.16.1.1.1.15.333 s test
- SNMPUtil.exe snmpgetv3 127.0.0.1 161 OpenViewUser AUTH_PRIVACY MD5 auth1234 AES256 priv1234 contextName .1.3.6.1.2.1.1.5.0 
- SNMPUtil.exe snmpsetv2c 127.0.0.1 161 .1.3.6.1.2.1.1.5.0 community i 6
- SNMPUtil.exe snmpgetv2c 127.0.0.1 161 .1.3.6.1.2.1.1.5.0 community

linux
- java -jar SNMPUtil.jar snmpsetv3 127.0.0.1 161 OpenViewUser AUTH_NOPRIVACY MD5 auth1234 AES256 priv1234 contextName .1.3.6.1.4.1.9.9.16.1.1.1.15.333 s test
- java -jar SNMPUtil.jar snmpgetv3 127.0.0.1 161 OpenViewUser AUTH_PRIVACY MD5 auth1234 AES256 priv1234 contextName .1.3.6.1.2.1.1.5.0 
- java -jar SNMPUtil.jar snmpsetv2c 127.0.0.1 161 .1.3.6.1.2.1.1.5.0 community i 6
- java -jar SNMPUtil.jar snmpgetv2c 127.0.0.1 161 .1.3.6.1.2.1.1.5.0 community
