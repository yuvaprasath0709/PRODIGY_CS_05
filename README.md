# Network Packet Analyzer

## Overview

This Python script, `network_packet.py`, is a basic network packet analyzer that captures and displays information about network packets in real-time. It uses the `scapy` library to sniff network traffic and provides a user-friendly output of relevant packet details.

## Features

* **Packet Capture:** Captures network packets from the network interface.
* **Real-time Analysis:** Displays packet information as it is captured.
* **Packet Decoding:** Decodes and displays information from the following network layers:
    * Ethernet (MAC addresses)
    * IP (IP addresses, protocol)
* **Protocol Identification:** Identifies the protocol of the packet (TCP, UDP, ICMP).
* **Packet Size:** Displays the size of each captured packet.
* **Payload Display:** Displays the first 100 characters of the packet's payload, if available.
* **Colored Output (Optional):** Uses `termcolor` to display packet information with color-coding for better readability (if the library is installed).
* **Cross-Platform:** Works on Linux, macOS, and Windows.

## Installation

1.  **Python:** Ensure you have Python 3.6 or later installed.
2.  **Scapy:** Install the `scapy` library:

    ```
    pip install scapy
    ```

3.  **Termcolor (Optional):** For colored output, install the `termcolor` library:

    ```
    pip install termcolor
    ```

## Usage

1.  **Clone the Repository:** Clone this GitHub repository to your local machine.
2.  **Run the Script:** Navigate to the directory containing `network_packet.py` and run it with root/administrator privileges:

    ```
    sudo python network_packet.py
    ```

    \* You need elevated privileges to capture network traffic.

3.  **View Packet Information:** The script will start capturing and displaying packet information in the terminal.
4.  **Stop the Script:** Press `Ctrl+C` to stop the packet capture.

## Dependencies

* [Scapy](https://scapy.net/): A powerful Python interactive packet manipulation program & library.
* [Termcolor](https://pypi.org/project/termcolor/) (Optional): For colored terminal output.

## Ethical Considerations

* This tool is intended for educational and network analysis purposes only.
* Do not use this tool to capture or analyze network traffic without proper authorization.
* Capturing network traffic without consent is illegal and unethical.
* The developer of this tool is not responsible for any misuse.

## Disclaimer

This script is provided as-is for educational purposes. The user is responsible for ensuring they have the necessary permissions and complies with all applicable laws and regulations when using this tool.
