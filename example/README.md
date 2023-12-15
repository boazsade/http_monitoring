# HTTP Packet Monitoring
## Overview
The HTTP packet monitoring application is meat as a way to monitor packets at the ethernet level from a given interface and from there to generate information about it.
This application uses for the actual work a library 'HttpPacketMonitoring'.
This library is doing the actual packet capture as well as formatting the captured data into JSON message, and from there sends it to the external consumer over HTTP message bus.
## Configuration
### Network configuration
The configuration is stored inside a JSON file.
An example JSON has this entries:
```
{
  "mngr_config":
  {
    "sender_consumer_ip": "127.0.0.1",
    "sender_consumer_port": 50020,
    "agent_working_threads": 8,
    "max_size_http_message_mb": 50,
    "max_total_memory_gb": 2
  },
  "driver_config":
  {
    "pcap_device": "wlp0s20f3",
    "filter":
    [
      {"ip": "61.243.158.194","port": 80},
      {"ip": "61.243.158.194","port": 80},
      {"ip": "35.224.170.0/24","port": 80}
    ]
  },
  "log_config":
  {
    "log_file_name": "monitor_log_file.log",
    "log_files_path": "/home/dbpost/logs/engine/packets_monitoring/",
    "file_max_size_mb": 10,
    "max_logs_dir_size_gb": 0.5,
    "delta_time_hours_to_delete": 5,
    "log_level: 2
  }
}
```
Of special notes are the 'driver_config' configuration.
This configuration contain the information from which the filter is build.
The filter accept a list of 2 parameters:
* IP: this is actual can either be:
    - An IP address in the form of IPv4 dot notation address such as 123.456.111.222
    - AN IP/Mask pair in the form of IPV4 dot notation as well as the net mask such as 123.456.111.0/24. 
        * Please note that in this case you cannot set the IPv4 octet part that is under the mask to anything other than 0!
* Port: The port is just a port number in the range of 0 - 65,536. 
- Please note:
The resulting for filter can be:
* input: ip = 1.2.3.4 port = 80, output = tcp port 80 and host 1.2.3.4
* input {ip = 1.2.3.4 port = 80, ip = 5.6.7.8 port = 180} output = '(tcp port 80 and host 1.2.3.4)' or '(tcp port 180 and host 5.6.7.8)'
* input {ip = 1.2.3.4 port = 80, ip = 5.6.7.8 port = 180, ip = 1.0.0.0/8 port = 95} output = '(tcp port 80 and host 1.2.3.4)' or '(tcp port 180 and host 5.6.7.8)' or '(tcp port 95 and net 1.0.0.0/8)'
- For more details about filters you can read in [A tcpdump Tutorial with Examples](https://danielmiessler.com/study/tcpdump/)
- Please note that while tcpdump support many complex filters, our filters are limited to the host/net and port. And ports must be specific.
The application will verity that the user input is valid. 
- For interface name (pcap_device): if the interface name do not exists it would report out that it failed to find the interface name.
- For filter: if the filter is invalid it would report why it failed to set the filter.
- Please note that for pcap_device you should not use "any" since it may not work correctly for Linux.
### Log configuration
The log configuration under "log_config" contain the following:
- log file name: the file to which the log messages are writing. Please note that each file would prefix with "rotate-N-" where N is the number of rotation for the file.
- log file path: the location at which the files will be writing on the file system. This path must exist before running the application!
- max log size in Mega Bytes: this is the size of the file before its been rotated.
- time to delete: when the file will be rotated even when it is not at max size.
- log level: what level of severity we are printing to the log - 
    * 1: debug level - all messages in the code will be printed.
    * 2: info level - all messages that are marked as info and above, no debug messages.
    * 3: warning - print warning message as well as error and critical messages.
    * 4: error - only error messages as well as critical messages will be printed to the log.
    * 5: critical - only the most critical messages are printed to the log. All are messages will not be writing.
### Consumer configuration
This is under the "remote_config".
In this section we are tell the application where to redirect the resulting JSON that were captured.
- sender consumer ip: is the remote host that accept these messages.
- sender consumer port: this is the base port to which the remote application is listening to.
- agent working threads: this actually telling this application how many additional remote ports exists over the sender consumer port.
- max total memory: this control the memory usage that is allowed by this application. This value is GigaBytes.
- max HTTP message: this control the per message allowed size. We are using this to ensure that on one message will consume all our memory.
  please note that its a good limitation for messages that can be very large such as file downloading. The value is in MegaBytes.
## Limitations
- This application only support IPv4 for now.
- This application only support TCP traffic.
- This application only support unencrypted data (no SSL/TLS traffic).
- This application only support HTTP 1/1.1 (text based).