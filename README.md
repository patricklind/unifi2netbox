# NetBox and UniFi Integration

This project provides a mechanism to integrate **NetBox** with **UniFi**, allowing you to synchronize devices and manage conflicts while maintaining accurate data within NetBox.

## Features

- **Device Synchronization**: Automatically create or update devices from UniFi into NetBox.
- **Site Mapping**: Customizable mapping between UniFi site names and NetBox site names via YAML configuration.
- **Conflict Resolution**: Handle duplicate VRFs, IP addresses, and prefixes with advanced error handling and retry mechanisms.
- **Custom Connection Management**: Optimize performance with configurable connection pooling for NetBox API communications.
- **Detailed Logging**: Comprehensive logging with verbose mode for debugging and monitoring.
- **Modular Design**: Improved code organization with a dedicated UniFi module for better maintainability.

## Requirements

- Python 3.12 or later
- Installed Python packages:
  - `pynetbox`
  - `requests`
  - `pyotp`
  - `PyYAML`
  - `python-dotenv`
  - `python-slugify`
  - `urllib3`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mrzepa/unifi2netbox.git
   cd unifi2netbox
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file at the root of the project to store sensitive information such as usernames, passwords, and tokens. The `.env` file should look like this:
   ```plaintext
   # Preferred for UniFi Integration API v1
   UNIFI_API_KEY=your-unifi-api-key
   # Optional, defaults to X-API-KEY
   UNIFI_API_KEY_HEADER=X-API-KEY

   # Optional fallback for legacy login flow
   UNIFI_USERNAME=your-unifi-username
   UNIFI_PASSWORD=your-unifi-password
   UNIFI_MFA_SECRET=your-unifi-mfa-secret

   NETBOX_TOKEN=your-netbox-api-token
   ```
   The script supports both UniFi Integration API key auth and legacy username/password login.
   `UNIFI_MFA_SECRET` is optional if your UniFi account does not use TOTP-based 2FA.

4. Copy the sample configuration file to `config/config.yaml`:
   ```bash
   cp config/config.yaml.SAMPLE config/config.yaml
   ```
   
5. Update the `config/config.yaml` file with your company-specific information (such as URLs, roles, and tenant names). For example:
   ```yaml
   UNIFI:
     URLS:
       # Integration API v1 (recommended)
       - https://<controller-ip>:11443/proxy/network/integration/v1
       # Legacy example:
       # - https://<controller-ip>:8443
   NETBOX:
     URL: http://localhost:8080
     ROLES:
       WIRELESS: Wireless AP
       LAN: Switch
       GATEWAY: Gateway Firewall
       ROUTER: Router
       UNKNOWN: Network Device
     TENANT: Organization Name
   ```

6. Configure site mapping (optional):
   Site mapping is only needed if your UniFi site names differ from NetBox site names. You have two options for configuring site mappings:
   
   **Option 1: Configure in config.yaml (recommended)**
   ```yaml
   UNIFI:
     # Other UNIFI settings...
     # Set to true to use external site_mapping.yaml file
     USE_SITE_MAPPING: false
     # Define mappings directly in config.yaml
     SITE_MAPPINGS:
       "UniFi Site Name": "NetBox Site Name"
       "Corporate Office": "HQ"
   ```
   
   **Option 2: Use external mapping file**
   Set `USE_SITE_MAPPING: true` in config.yaml, then edit `config/site_mapping.yaml`:
   ```yaml
   "UniFi Site Name": "NetBox Site Name"
   "Corporate Office": "HQ"
   "Remote Branch": "Branch-01"
   ```
   
   If both options are configured, mappings in config.yaml take precedence.
## Obtaining the UniFi OTP Seed (MFA Secret)

The OTP seed (also referred to as the MFA Secret) is required for Multi-Factor Authentication and must be added to the `.env` file. Follow these steps to obtain it:

1. **Log in to your UniFi account**:
   Go to [https://account.ui.com](https://account.ui.com) and log in with your UniFi credentials.

2. **Access your profile**:
   Once logged in, select your profile in the top-right corner of the page.

3. **Manage security settings**:
   In the profile menu, select **Manage Security**.

4. **Retrieve the MFA Secret**:
   Under the "Multi-Factor Authentication" section:
   - Click: Add New Method.
   - Select App authentication.
   - Select "Enter code manually", or use a QR code scanner.
   - The text output will contain the OTP seed (a base32 string). This is your `UNIFI_MFA_SECRET`.
   - Make sure to select App authentication as your primary MFA.

5. Add the OTP seed to your `.env` file:
   ```plaintext
   UNIFI_MFA_SECRET=your-otp-seed
   ```

If you do not have 2FA enabled, you will need to set it up to generate a new OTP seed.

## Usage

### Running the Integration Script

Once the `.env` and `config/config.yaml` files are properly set up, you can run the script:

```bash
python main.py
```

For verbose logging with detailed debug information:

```bash
python main.py -v
```

### Site Mapping

Site mapping is optional and only needed if your UniFi site names differ from NetBox site names. You have two ways to configure site mappings:

#### Option 1: Configure in config.yaml (recommended)

Define your mappings directly in the main configuration file:

```yaml
UNIFI:
  # Other settings...
  # Set to false to disable external mapping file
  USE_SITE_MAPPING: false
  # Define mappings directly here
  SITE_MAPPINGS:
    "UniFi Site Name": "NetBox Site Name"
    "Corporate Office": "HQ"
```

#### Option 2: Use external mapping file

Enable the external mapping file in config.yaml:

```yaml
UNIFI:
  # Other settings...
  USE_SITE_MAPPING: true
```

Then edit the `config/site_mapping.yaml` file:

```yaml
"UniFi Site Name": "NetBox Site Name"
"Corporate Office": "HQ"
"Remote Branch": "Branch-01"
```

**Note:** If both options are configured, mappings in config.yaml take precedence over those in the external file.

If a UniFi site name is not found in any mapping, the script will use the UniFi site name directly when looking for a matching NetBox site.

### Logging

The script logs information at different levels:

- **INFO**: Standard operational information (default level)
- **DEBUG**: Detailed debugging information (enabled with `-v` flag)
- **WARNING**: Potential issues that don't prevent operation
- **ERROR**: Problems that prevent specific operations
- **CRITICAL**: Critical failures

All logs are written to the `logs` directory. Logs are organized by severity (e.g., `info.log`, `error.log`) for easier debugging. Example of an error log:

```plaintext
2025-01-22 14:24:54,390 - ERROR - Unable to delete VRF at site X: '409 Conflict'
```

### Troubleshooting

If you encounter issues with the integration:

1. **Run with verbose logging**: Use the `-v` flag to enable detailed debug output
   ```bash
   python main.py -v
   ```

2. **Check log files**: Review the logs in the `logs` directory for specific errors

3. **Verify site mapping**: Ensure your site mapping in `config/site_mapping.yaml` correctly maps UniFi sites to NetBox sites

4. **Authentication issues**: 
   - If using Integration API, verify `UNIFI_API_KEY` (and optionally `UNIFI_API_KEY_HEADER`) in `.env`
   - If using legacy auth, verify `UNIFI_USERNAME`, `UNIFI_PASSWORD`, and optional `UNIFI_MFA_SECRET`
   - Check that your NetBox API token has appropriate permissions

5. **API connectivity**: 
   - Ensure the UniFi controller is accessible at the configured URL
   - Verify the NetBox API is reachable and responding
   - The client supports Integration API v1 (`/proxy/network/integration/v1`) and also auto-detects UniFi OS (`/api/auth/login` with `/proxy/network`) and legacy controller (`/api/login`) session API styles.

6. **Session issues**: If you encounter authentication problems, try deleting the session file and running again

### Device Roles

`NETBOX.ROLES` supports multiple role keys. The script will infer the best key per device and fall back automatically:

- `WIRELESS`: access points
- `LAN`: switches
- `GATEWAY`: gateway/firewall devices (for example USG/UXG/UDM families)
- `ROUTER`: routing-focused devices
- `UNKNOWN`: fallback role when no specific match is found

### Handling Conflicts

If there are conflicts (e.g., duplicate device names, VRFs, or IP addresses), the script:
- Logs the issue in the error log.
- Attempts to resolve it automatically where possible.
- Skips problematic devices or sites if the issue cannot be resolved.

## Contributing

Contributions are welcome! To contribute to this project:
1. Fork the repository.
2. Create a branch for your feature or bugfix:
   ```bash
   git checkout -b feature/my-feature
   ```
3. Commit your changes and push the branch:
   ```bash
   git commit -m "Add my feature"
   git push origin feature/my-feature
   ```
4. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- This project was inspired by the need for unified network management.
