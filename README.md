# CYBER SHIELD

**Cyber Shield** is an advanced cybersecurity solution designed to mitigate a wide range of cyber threats by integrating cutting-edge tools like **Wazuh**, **VirusTotal**, and AI-driven technologies. The platform leverages Wazuh for monitoring and managing cyberattacks, gathering critical log data for enhanced threat detection and response. Additionally, it incorporates a sophisticated AI model to analyze and address specific attack patterns, providing an extra layer of defense against emerging threats. Cyber Shield offers a comprehensive, automated approach to cybersecurity, ensuring real-time protection and proactive threat mitigation.

---

## Table of Contents
- [Infrastructure Setup](#infrastructure-setup)
  - [Installation of Wazuh](#installation-of-wazuh)
    - [Installation on Ubuntu](#installation-on-ubuntu)
    - [Installation on Windows](#installation-on-windows)
- [Wazuh Usage](#wazuh-usage)
  - [Monitoring and Alerts](#monitoring-and-alerts)
  - [Log Collection](#log-collection)
  - [Wazuh Dashboard Configuration](#wazuh-dashboard-configuration)
- [VirusTotal Integration](#virustotal-integration)
  - [Setup on Ubuntu](#setup-on-ubuntu)
  - [Setup on Windows](#setup-on-windows)
- [AI Model Configuration](#ai-model-configuration)
  - [Supported Attacks](#supported-attacks)
  - [Tuning and Customization](#tuning-and-customization)

---

## Infrastructure Setup

### Installation of Wazuh

Wazuh is a powerful security monitoring tool that provides threat detection, integrity monitoring, incident response, and compliance management. Cyber Shield uses Wazuh as its core for log collection and threat monitoring. The following subsections describe how to install Wazuh on different platforms.

#### Installation on Ubuntu
To install Wazuh on Ubuntu:

1. **Update your system packages:**
   ```bash
   sudo apt-get update && sudo apt-get upgrade
   ```
2. **Add the Wazuh repository:**
   ```bash
   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
   echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
   ```
3. **Install the Wazuh manager and dependencies:**
   ```bash
   sudo apt-get install wazuh-manager
   ```
4. **Configure the Wazuh manager:**
   - Modify the `/var/ossec/etc/ossec.conf` file for custom settings like log monitoring and alerts.

5. **Start the Wazuh manager:**
   ```bash
   sudo systemctl start wazuh-manager
   ```

#### Installation on Windows

To install Wazuh on Windows:

1. **Download the Wazuh agent installer** from the official Wazuh website.
2. **Run the installer** and follow the setup wizard to install the agent on your Windows system.
3. **Configure the Wazuh agent**:
   - Modify the `ossec.conf` file located in the Wazuh installation directory to point to your Wazuh server.
   - Example configuration:
     ```xml
     <server>
       <address>YourWazuhManagerIP</address>
       <port>1514</port>
     </server>
     ```
4. **Start the Wazuh agent**:
   ```cmd
   net start WazuhSvc
   ```
5. **Verify the connection** to the Wazuh manager by checking the logs.

---

## Wazuh Usage

### Monitoring and Alerts

Wazuh continuously monitors your system for potential threats and anomalies by analyzing log data. It generates real-time alerts based on predefined rules, which can be customized to fit your security needs.

- **Access the Wazuh dashboard** by navigating to:
  ```bash
  http://localhost:5601
  ```
  Here, you can view alerts, monitor system status, and configure custom alerting rules.
  
- Wazuh integrates with **Elasticsearch** and **Kibana** for advanced log analysis and visualization.

### Log Collection

Wazuh collects logs from various sources, including operating systems, applications, and network devices. The logs are analyzed using predefined rules to detect suspicious activity.

- **Supported log types**: system logs, firewall logs, application logs, and more.
  
- Logs are stored in the Wazuh manager and can be visualized through the **Kibana** interface.

- **Custom log collection**: Configure Wazuh to collect specific logs by editing the `ossec.conf` file and defining the paths for the logs you want to monitor.

### Wazuh Dashboard Configuration

The Wazuh dashboard is a powerful tool for monitoring and managing security events. Here’s how to configure it effectively:

1. **Access the Dashboard**: Open your web browser and navigate to the dashboard URL (`http://localhost:5601`).

2. **Initial Setup**: If this is your first time accessing the dashboard, complete the initial setup wizard to connect it to your Wazuh manager and Elasticsearch.

3. **Customize Alerts**:
   - Go to the **Management** tab.
   - Navigate to **Rules** to customize existing rules or add new ones based on your environment's needs.

4. **Dashboards and Visualizations**:
   - Explore predefined dashboards for quick insights.
   - Create custom visualizations using the **Visualize** tab to focus on specific data points relevant to your organization.

5. **User Management**: Set up user roles and permissions under the **Management** section to control access to the dashboard.

---

## VirusTotal Integration

Detecting and removing malware using VirusTotal integration
===========================================================

Wazuh uses the :doc:`integrator </user-manual/reference/ossec-conf/integration>` module to connect to external APIs and alerting tools such as VirusTotal.

In this use case, you use the Wazuh :doc:`File Integrity Monitoring </user-manual/capabilities/file-integrity/index>` (FIM) module to monitor a directory for changes and the VirusTotal API to scan the files in the directory. Then, configure Wazuh to trigger an active response script and remove files that VirusTotal detects as malicious. We test this use case on Ubuntu and Windows endpoints.

You need a `VirusTotal API key <https://developers.virustotal.com/reference/getting-started>`__ in this use case to authenticate Wazuh to the VirusTotal API.

For more information on this integration, check the :doc:`VirusTotal integration </user-manual/capabilities/malware-detection/virus-total-integration>` section of the documentation.


Configuration for the Ubuntu endpoint
-------------------------------------

Configure your environment as follows to test the use case for the Ubuntu endpoint. These steps work for other Linux distributions as well.

Ubuntu endpoint
 

Perform the following steps to configure Wazuh to monitor near real-time changes in the ``/root`` directory of the Ubuntu endpoint. These steps also install the necessary packages and create the active response script that removes malicious files.

 Search for the ``<syscheck>`` block in the Wazuh agent configuration file ``/var/ossec/etc/ossec.conf``. Make sure that ``<disabled>`` is set to ``no``. This enables the Wazuh FIM to monitor for directory changes.

 Add an entry within the ``<syscheck>`` block to configure a directory to be monitored in near real-time. In this case, you are monitoring the ``/root`` directory:



      <directories realtime="yes">/root</directories>

 Install ``jq``, a utility that processes JSON input from the active response script.



      $ sudo apt update
      $ sudo apt -y install jq

 Create the ``/var/ossec/active-response/bin/remove-threat.sh`` active response script to remove malicious files from the endpoint:



      #!/bin/bash

      LOCAL=`dirname $0`;
      cd $LOCAL
      cd ../

      PWD=`pwd`

      read INPUT_JSON
      FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
      COMMAND=$(echo $INPUT_JSON | jq -r .command)
      LOG_FILE="${PWD}/../logs/active-responses.log"

      #------------------------ Analyze command -------------------------#
      if [ ${COMMAND} = "add" ]
      then
       # Send control message to execd
       printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'

       read RESPONSE
       COMMAND2=$(echo $RESPONSE | jq -r .command)
       if [ ${COMMAND2} != "continue" ]
       then
        echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
        exit 0;
       fi
      fi

      # Removing file
      rm -f $FILENAME
      if [ $? -eq 0 ]; then
       echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
      else
       echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
      fi

      exit 0;

 Change the ``/var/ossec/active-response/bin/remove-threat.sh`` file ownership, and permissions:



      $ sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
      $ sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh

 Restart the Wazuh agent to apply the changes:



      $ sudo systemctl restart wazuh-agent

Wazuh server
 

Perform the following steps on the Wazuh server to alert for changes in the endpoint directory and enable the VirusTotal integration. These steps also enable and trigger the active response script whenever a suspicious file is detected.

 Add the following rules to the ``/var/ossec/etc/rules/local_rules.xml`` file on the Wazuh server. These rules alert about changes in the ``/root`` directory that are detected by FIM scans:



      <group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
          <!-- Rules for Linux systems -->
          <rule id="100200" level="7">
              <if_sid>550</if_sid>
              <field name="file">/root</field>
              <description>File modified in /root directory.</description>
          </rule>
          <rule id="100201" level="7">
              <if_sid>554</if_sid>
              <field name="file">/root</field>
              <description>File added to /root directory.</description>
          </rule>
      </group>

 Add the following configuration to the Wazuh server ``/var/ossec/etc/ossec.conf`` file to enable the Virustotal integration. Replace ``<YOUR_VIRUS_TOTAL_API_KEY>`` with your `VirusTotal API key <https://developers.virustotal.com/reference>`__. This allows to trigger a VirusTotal query whenever any of the rules ``100200`` and ``100201`` are triggered:



      <ossec_config>
        <integration>
          <name>virustotal</name>
          <api_key><YOUR_VIRUS_TOTAL_API_KEY></api_key> <!-- Replace with your VirusTotal API key -->
          <rule_id>100200,100201</rule_id>
          <alert_format>json</alert_format>
        </integration>
      </ossec_config>

note:

      The free VirusTotal API rate limits requests to four per minute. If you have a premium VirusTotal API key, with a high frequency of queries allowed, you can add more rules besides these two. You can also configure Wazuh to monitor more directories.

 Append the following blocks to the Wazuh server ``/var/ossec/etc/ossec.conf`` file. This enables Active Response and triggers the ``remove-threat.sh`` script when VirusTotal flags a file as malicious:



      <ossec_config>
        <command>
          <name>remove-threat</name>
          <executable>remove-threat.sh</executable>
          <timeout_allowed>no</timeout_allowed>
        </command>

        <active-response>
          <disabled>no</disabled>
          <command>remove-threat</command>
          <location>local</location>
          <rules_id>87105</rules_id>
        </active-response>
      </ossec_config>

 Add the following rules to the Wazuh server ``/var/ossec/etc/rules/local_rules.xml`` file to alert about the Active Response results:



      <group name="virustotal,">
        <rule id="100092" level="12">
          <if_sid>657</if_sid>
          <match>Successfully removed threat</match>
          <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
        </rule>

        <rule id="100093" level="12">
          <if_sid>657</if_sid>
          <match>Error removing threat</match>
          <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
        </rule>
      </group>

 Restart the Wazuh manager to apply the configuration changes:


      $ sudo systemctl restart wazuh-manager

Attack emulation
----------------

 Download an EICAR test file to the ``/root`` directory on the Ubuntu endpoint:



      $ sudo curl -Lo /root/eicar.com https://secure.eicar.org/eicar.com && sudo ls -lah /root/eicar.com

Visualize the alerts
--------------------

You can visualize the alert data in the Wazuh dashboard. To do this, go to the **Threat Hunting** module and add the filters in the search bar to query the alerts.

-  Linux - ``rule.id: is one of 553,100092,87105,100201``

   .. thumbnail:: /images/poc/virustotal-remove-malware-linux-alert.png
      :title: Remove malware on Linux alert
      :alt: Remove malware on Linux alert
      :align: center
      :width: 80%

Configuration for the Windows endpoint
--------------------------------------

Windows endpoint
 

Perform the following steps to configure Wazuh to monitor near real-time changes in the ``/Downloads`` directory. These steps also install the necessary packages and create the active response script to remove malicious files.

 Search for the ``<syscheck>`` block in the Wazuh agent ``C:\Program Files (x86)\ossec-agent\ossec.conf`` file. Make sure that ``<disabled>`` is set to ``no``. This enables the Wazuh FIM module to monitor for directory changes.

 Add an entry within the ``<syscheck>`` block to configure a directory to be monitored in near real-time. In this use case, you configure Wazuh to monitor the ``C:\Users\<USER_NAME>\Downloads`` directory. Replace the ``<USER_NAME>`` variable with the appropriate user name:



      <directories realtime="yes">C:\Users\<USER_NAME>\Downloads</directories>

 Download the Python executable installer from the `official Python website <https://www.python.org/downloads/windows/>`__.

 Run the Python installer once downloaded. Make sure to check the following boxes:

   -  ``Install launcher for all users``
   -  ``Add Python 3.X to PATH`` (This places the interpreter in the execution path)

 Once Python completes the installation process, open an administrator PowerShell terminal and use ``pip`` to install PyInstaller:



      > pip install pyinstaller
      > pyinstaller --version

   You use Pyinstaller here to convert the active response Python script into an executable application that can run on a Windows endpoint.

 Create an active response script ``remove-threat.py`` to remove a file from the Windows endpoint:



      #!/usr/bin/python3
      # Copyright (C) 2015-2022, Wazuh Inc.
      # All rights reserved.

      import os
      import sys
      import json
      import datetime

      if os.name == 'nt':
          LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
      else:
          LOG_FILE = "/var/ossec/logs/active-responses.log"

      ADD_COMMAND = 0
      DELETE_COMMAND = 1
      CONTINUE_COMMAND = 2
      ABORT_COMMAND = 3

      OS_SUCCESS = 0
      OS_INVALID = -1

      class message:
          def __init__(self):
              self.alert = ""
              self.command = 0

      def write_debug_file(ar_name, msg):
          with open(LOG_FILE, mode="a") as log_file:
              log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg +"\n")

      def setup_and_check_message(argv):

          # get alert from stdin
          input_str = ""
          for line in sys.stdin:
              input_str = line
              break


          try:
              data = json.loads(input_str)
          except ValueError:
              write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
              message.command = OS_INVALID
              return message

          message.alert = data

          command = data.get("command")

          if command == "add":
              message.command = ADD_COMMAND
          elif command == "delete":
              message.command = DELETE_COMMAND
          else:
              message.command = OS_INVALID
              write_debug_file(argv[0], 'Not valid command: ' + command)

          return message


      def send_keys_and_check_message(argv, keys):

          # build and send message with keys
          keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

          write_debug_file(argv[0], keys_msg)

          print(keys_msg)
          sys.stdout.flush()

          # read the response of previous message
          input_str = ""
          while True:
              line = sys.stdin.readline()
              if line:
                  input_str = line
                  break

          # write_debug_file(argv[0], input_str)

          try:
              data = json.loads(input_str)
          except ValueError:
              write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
              return message

          action = data.get("command")

          if "continue" == action:
              ret = CONTINUE_COMMAND
          elif "abort" == action:
              ret = ABORT_COMMAND
          else:
              ret = OS_INVALID
              write_debug_file(argv[0], "Invalid value of 'command'")

          return ret

      def main(argv):

          write_debug_file(argv[0], "Started")

          # validate json and get command
          msg = setup_and_check_message(argv)

          if msg.command < 0:
              sys.exit(OS_INVALID)

          if msg.command == ADD_COMMAND:
              alert = msg.alert["parameters"]["alert"]
              keys = [alert["rule"]["id"]]
              action = send_keys_and_check_message(argv, keys)

              # if necessary, abort execution
              if action != CONTINUE_COMMAND:

                  if action == ABORT_COMMAND:
                      write_debug_file(argv[0], "Aborted")
                      sys.exit(OS_SUCCESS)
                  else:
                      write_debug_file(argv[0], "Invalid command")
                      sys.exit(OS_INVALID)

              try:
                  file_path = msg.alert["parameters"]["alert"]["data"]["virustotal"]["source"]["file"]
                  if os.path.exists(file_path):
                      os.remove(file_path)
                  write_debug_file(argv[0], json.dumps(msg.alert) + " Successfully removed threat")
              except OSError as error:
                  write_debug_file(argv[0], json.dumps(msg.alert) + "Error removing threat")


          else:
              write_debug_file(argv[0], "Invalid command")

          write_debug_file(argv[0], "Ended")

          sys.exit(OS_SUCCESS)

      if __name__ == "__main__":
          main(sys.argv)

 Convert the active response Python script ``remove-threat.py`` to a Windows executable application. Run the following PowerShell command as an administrator to create the executable:


      > pyinstaller -F \path_to_remove-threat.py

   Take note of the path where ``pyinstaller`` created ``remove-threat.exe``.

 Move the executable file ``remove-threat.exe`` to the ``C:\Program Files (x86)\ossec-agent\active-response\bin`` directory.

 Restart the Wazuh agent to apply the changes. Run the following PowerShell command as an administrator:



      > Restart-Service -Name wazuh

Wazuh server
 

Perform the following steps on the Wazuh server to configure the VirusTotal integration. These steps also enable and trigger the active response script whenever a suspicious file is detected.

 Add the following configuration to the ``/var/ossec/etc/ossec.conf`` file on the Wazuh server to enable the VirusTotal integration. Replace ``<YOUR_VIRUS_TOTAL_API_KEY>`` with your `VirusTotal API key <https://developers.virustotal.com/reference>`__. This allows to trigger a VirusTotal query whenever any of the rules in the FIM ``syscheck`` group are triggered:



      <ossec_config>
        <integration>
          <name>virustotal</name>
          <api_key><YOUR_VIRUS_TOTAL_API_KEY></api_key> <!-- Replace with your VirusTotal API key -->
          <group>syscheck</group>
          <alert_format>json</alert_format>
        </integration>
      </ossec_config>

note:

      The free VirusTotal API rate limits requests to four per minute. If you have a premium VirusTotal API key, with a high frequency of queries allowed, you can add more rules besides these two. You can configure Wazuh to monitor more directories besides ``C:\Users\<USER_NAME>\Downloads``.

 Append the following blocks to the Wazuh server ``/var/ossec/etc/ossec.conf`` file. This enables Active Response and trigger the ``remove-threat.exe`` executable when the VirusTotal query returns positive matches for threats:



      <ossec_config>
        <command>
          <name>remove-threat</name>
          <executable>remove-threat.exe</executable>
          <timeout_allowed>no</timeout_allowed>
        </command>

        <active-response>
          <disabled>no</disabled>
          <command>remove-threat</command>
          <location>local</location>
          <rules_id>87105</rules_id>
        </active-response>
      </ossec_config>

 Add the following rules to the Wazuh server ``/var/ossec/etc/rules/local_rules.xml`` file to alert about the Active Response results.


      <group name="virustotal,">
        <rule id="100092" level="12">
            <if_sid>657</if_sid>
            <match>Successfully removed threat</match>
            <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
        </rule>

        <rule id="100093" level="12">
          <if_sid>657</if_sid>
          <match>Error removing threat</match>
          <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
        </rule>
      </group>

 Restart the Wazuh manager to apply the configuration changes:



      $ sudo systemctl restart wazuh-manager

Attack emulation
----------------

 Follow the next steps to temporarily turn off real-time Microsoft Defender antivirus protection in Windows Security:

    Click on the **Start** menu and type ``Windows Security`` to search for that app.
    Select the **Windows Security app** from results, go to **Virus & threat protection**, and under **Virus & threat protection settings** select **Manage settings**.
    Switch **Real-time protection** to **Off**.

 Download an `EICAR test <https://secure.eicar.org/eicar.com.txt>`__ file to the ``C:\Users\<USER_NAME>\Downloads`` directory on the Windows endpoint.


      > Invoke-WebRequest -Uri https://secure.eicar.org/eicar.com.txt -OutFile eicar.txt
      > cp .\eicar.txt C:\Users\<USER_NAME>\Downloads

   This triggers a VirusTotal query and generates an alert. In addition, the active response script automatically removes the file.

Visualize the alerts
--------------------

You can visualize the alert data in the Wazuh dashboard. To do this, go to the **Threat Hunting** module and add the filters in the search bar to query the alerts.

-  Windows - ``rule.id: is one of 554,100092,553,87105``

---

## AI Model Configuration

### Supported Attacks

Cyber Shield's AI model is designed to detect and mitigate several types of common cyberattacks. The model is pre-trained to identify patterns associated with the following attack types:

- **SQL Injection**: Detects malicious SQL queries attempting to manipulate databases.
- **Distributed Denial of Service (DDoS)**: Identifies abnormal traffic patterns indicative of DDoS attacks.
- **Brute Force**: Flags multiple failed login attempts that suggest a brute force attack.
- **Ransomware**: Detects file encryption behaviors commonly associated with ransomware.

### Tuning and Customization

The AI model can be tuned to detect additional or specific attack patterns. You can customize its behavior by modifying the configuration files.

1. **Edit the configuration** located in the `config/ai_model.yaml` file to adjust thresholds or add new attack signatures.
   
2. **Retrain the AI model** if necessary:
   - If you've added new attack signatures, retrain the model using the provided dataset or your own custom dataset.

3. **Deploy the updated model** to your Wazuh server for real-time analysis.

---

## Contributing

We welcome contributions! To contribute to Cyber Shield:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Open a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

---

## Credits

Cyber Shield is developed and maintained by [Your Name/Company]. We would like to acknowledge the following tools and libraries used in this project:

- **Wazuh** - For providing core monitoring and alerting capabilities.
- **VirusTotal** - For file and URL threat detection.
- **Elasticsearch & Kibana** - For log analysis and visualization.
- Contributors: @username1, @username2

---

## Contact

For any inquiries or support, please reach out to us via:

- Email: enicarthage.ieee.cs@gmail.com
- GitHub Issues: [https://github.com/IEEE_CS_ENICAR/cyber-shield/issues](https://github.com/IEEE_CS_ENICAR/cyber-shield/issues)
