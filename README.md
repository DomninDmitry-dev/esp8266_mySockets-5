# esp8266_mySockets-5
These are sockets 220V that are controlled remotely

## Quick Start
- You need connect sockets to socket 220V.
- To wait 2 minutes until the wifi module is connected to the network (wifi module has static IP 192.168.0.200 and PORT 50).
- After connecting you can set link with it. The module is a tcp server.
- There is the following protocol:
  - to turn on the sockets 1-5 you must sent commands from "releon1" till "releon5";
  - to turn off the sockets 1-5 you must sent commands from "releoff1" till "releoff5";
  - get status of the sockets you must sent commands from "status".

## Resources
Github source https://github.com/SuperHouse/esp-open-rtos
