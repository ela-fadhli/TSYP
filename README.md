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

Cyber Shield integrates **VirusTotal** to enhance the detection of malicious files and URLs. VirusTotal aggregates data from numerous antivirus engines and threat intelligence feeds, allowing you to cross-check suspicious files and links.

### Setup on Ubuntu

To set up VirusTotal on Ubuntu:

1. **Install the VirusTotal API client**:
   ```bash
   sudo apt-get install virustotal-cli
   ```
2. **Configure your API key**:
   Sign up for an API key on the [VirusTotal website](https://www.virustotal.com/), and set it as an environment variable:
   ```bash
   export VT_API_KEY="your-api-key"
   ```
3. **Use VirusTotal to scan files**:
   ```bash
   vt file scan myfile.txt
   ```

### Setup on Windows

To set up VirusTotal on Windows:

1. **Download and install** the VirusTotal CLI from the [official website](https://www.virustotal.com/).
2. **Set up your API key**:
   ```cmd
   setx VT_API_KEY "your-api-key"
   ```
3. **Run file scans**:
   ```cmd
   vt file scan C:\path\to\file.txt
   ```

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
