# Ubuntu-AD-Wizard
The Ubuntu AD Wizard script follows a structured workflow designed to guide users through the process of integrating an Ubuntu system into an Active Directory environment. Here's an overview of its step-by-step approach:

### 1. Initial Setup and Checks:

Displays a welcome banner and checks for root privileges.
Verifies Ubuntu version compatibility.
Confirms network connectivity and synchronizes system time.


### 2. Dependency Management:

Checks for required packages and installs any missing dependencies.


### 3. User Input and Domain Information:

Prompts for domain address and validates the input.
Checks DNS resolution for the domain.
Optionally configures custom DNS settings.


### 4. ystem Configuration:

Configures firewall rules to allow necessary communication.
Prompts for admin credentials for domain join.
Configures Kerberos settings.
Ensures SSSD directory exists and is properly set up.


### 5. Domain Join Process:

Attempts to join the domain using the provided information.
Handles potential errors and provides troubleshooting guidance if join fails.


### 6. Post-Join Configuration:

Configures SSSD for domain integration.
Sets up automatic home directory creation for domain users.
Installs and configures GPO support packages.
Updates system authentication settings (NSSwitch).
Optionally configures sudo access for domain users.


### 7. Verification and Testing:

Tests domain user lookup to ensure proper integration.
Offers advanced troubleshooting if issues are encountered.


### 8. Finalization:

Provides a summary of actions taken and important information.
Recommends system reboot and offers to perform it.
Conducts final checks on service status and configuration.


### 9. Logging and Cleanup:

Maintains a log of all actions for future reference.
Performs necessary cleanup operations.
