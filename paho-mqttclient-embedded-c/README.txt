#
# Orange Business Application (OAB)
#
# MQTTClient  from:
#
#   Eclipse Paho MQTT C/C++ client for Embedded platforms
#
#   github:  https://github.com/eclipse/paho.mqtt.embedded-c
#   SHA-1:   02323e1093f0414c1adcf03559e03a890b5f3a84
#
#   directory : MQTTClient-C

# And for MQTTPacket:
#   a template header file 'StackTrace.h' to plug the MQTT trace on MQTTLog.c
#

# Change made by OAB in MQTTClient.c 
#  - In function MQTTSubscribe(), use an intermediate qos variable defined as integer 
#    to fix an issue with Arduino compiler (enum pointer casted as inetger pointer)!

