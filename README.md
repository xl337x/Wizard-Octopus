# Wizard Octopus 🐙

## Multi-Tenant IOC Blocker for Microsoft Defender

![GitHub stars](https://img.shields.io/github/stars/xl337x/Wizard-Octopus?style=social)
![GitHub forks](https://img.shields.io/github/forks/xl337x/Wizard-Octopus?style=social)

---

### **Overview**

**Wizard Octopus** is a powerful automation tool designed to streamline the submission of Indicators of Compromise (IOCs) to Microsoft Defender across single or multiple tenants. It leverages a Python generator to create a robust PowerShell script that interacts directly with the Microsoft Defender API.

This tool is ideal for MSSPs, blue teams, or any organization managing threat intelligence ingestion for multiple Microsoft 365 Defender environments.

---

### **Features**

* **Flexible Tenant Support:** Generate scripts for single or multiple Microsoft Defender tenants.
* **Secure Authentication:** Utilizes OAuth 2.0 for secure token-based authentication with the Microsoft Defender API.
* **Dynamic IOC Input:** Supports manual entry and file-based ingestion from Excel (`.xlsx`, `.xls`), JSON (`.json`), and plain text (`.txt`) files.
* **Intelligent IOC Repair:** Automatically detects and fixes defanged IOCs (e.g., `hxxp` to `http`, `[.]` to `.`, `[at]` to `@`).
* **Comprehensive IOC Types:** Supports all major IOC types including IP Addresses, URLs, Domain Names, and File Hashes (MD5, SHA1, SHA256).
* **Duplicate Prevention:** Checks for existing indicators before submission to avoid redundant entries.
* **Detailed Reporting:** Provides a summary of submitted, skipped, and failed IOCs.

---

### **How It Works**

1.  **Python Generator (`main.py`):** You provide tenant configuration details (Tenant ID, Application ID, Application Secret) to the `main.py` Python script.
2.  **PowerShell Script Generation:** `main.py` then generates a tailored PowerShell script (`.ps1`) that includes these configurations.
3.  **PowerShell Execution:** The generated PowerShell script is executed to interactively guide you through the IOC submission process to your configured Microsoft Defender tenant(s).

---

### **Getting Started**

#### **Prerequisites**

* **Python 3.x:** Installed on your system to run `main.py`.
* **PowerShell 5.1 or newer / PowerShell Core:** To run the generated `.ps1` script.
* **Microsoft Defender API Access:**
    * An Azure AD application registered with appropriate permissions for the Microsoft Defender for Endpoint API.
        * `Indicators.ReadWrite.All` (for submitting IOCs)
    * Tenant ID, Application ID (Client ID), and Client Secret for your Azure AD application.

#### **Usage**

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/xl337x/Wizard-Octopus.git 
    cd Wizard-Octopus
    python3 Wizard-Octopus-Generator.py
    <Enter YOUR tenantid , appid, appsecret>
    ```
   
2.  **Generate the PowerShell Script:**
    ```bash
    This will create a `Wizard-Octopus.ps1` file in the same directory.
    ```

3.  **Run the PowerShell Tool:**
    Execute the generated PowerShell script:
    ```powershell
    .\Wizard-Octopus.ps1
    ```
    Follow the on-screen prompts to submit your IOCs.
![image](https://github.com/user-attachments/assets/13b2d15f-985f-4b95-ba7b-d49bd1798969)

![image](https://github.com/user-attachments/assets/ffba7a42-fa13-4a6f-86b5-19c8f385c714)

![image](https://github.com/user-attachments/assets/94d68f50-687b-41d8-9664-4988159dfed2)

![image](https://github.com/user-attachments/assets/8f514b4c-8dd4-44c6-aa7d-d81b88f0bab0)

![image](https://github.com/user-attachments/assets/facba431-865c-4017-ac01-26af506ef75f)

![image](https://github.com/user-attachments/assets/7ce2058e-4e3b-4848-aef7-d4e113c6c38c)






---

### **Input File Formats**

The PowerShell tool supports the following input file formats:

* **Plain Text (`.txt`)**:
    * **Single column:** Each line is an IOC value. The tool will attempt to auto-detect the type.
        ```
        1.1.1.1
        example.com
        [https://malicious.url/path](https://malicious.url/path)
        a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
        ```
    * **Two columns (comma, tab, or 2+ spaces separated):** `IOC_Value, IOC_Type`
        ```
        1.1.1.1, IpAddress
        example.com, DomainName
        hxxps://malicious.url, Url
        ```
* **JSON (`.json`)**: An array of objects, each containing `Value`, `Type`, `Title`, and `Description`.
    ```json
    [
      {
        "Value": "malicious.domain.com",
        "Type": "DomainName",
        "Title": "Malicious Domain Block",
        "Description": "Blocked via Wizard Octopus"
      },
      {
        "Value": "192.0.2.1",
        "Type": "IpAddress",
        "Title": "Bad IP Address",
        "Description": "Found in recent threat intel"
      }
    ]
    ```
* **Excel (`.xlsx`, `.xls`)**: The tool will attempt to parse all cells and extract IOCs and their types based on keywords like "IPv4", "URL", "Domain", "FileHash-SHA256", etc. It will then apply the defanging repair.

---

### **Contributing**

Contributions are welcome! If you have ideas for improvements or new features, please feel free to:

1.  **Fork** the repository.
2.  **Create a new branch** (`git checkout -b feature/YourFeature`).
3.  **Make your changes**.
4.  **Commit your changes** (`git commit -m 'Add new feature'`).
5.  **Push to the branch** (`git push origin feature/YourFeature`).
6.  **Open a Pull Request**.

---

### **License**

This project is licensed under the [MIT License](LICENSE).

---

### **Contact**

Created by **mahdiesta** ([GitHub Profile](https://github.com/xl337x)) 
