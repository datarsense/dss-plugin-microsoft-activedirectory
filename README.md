# DSS Plugin - Microsoft Active Directory

This Dataiku DSS plugin provides python connectors to load user and computer accounts from an Active Directory domain controller.

## Compatibility

* Dataiku DSS 12.0 or higher
* Microsoft Active Directory domain controller

## Plugin configuration
The following parameter can be configured globally :
* **LDAP server** : FQDN or IP address of the Active Directory domain controller.
* **LDAP server port** : LDAP port of the target domain controller. Can usually be 389 (unsecure conection) or 636 (connection secured by TLS/SSL).
* **Use TLS ?** : Defines if TLS/SSL is used to secure LDAP connection. Default is YES.
* **Anonymous bind ?** : Connect anonymously to the LDAP server ? Default is NO.
* **Bind DN** : If the LDAP connection requires authentication, specifies the DN to use for LDAP bind.
* **Bind password** : If the LDAP connection requires authentication, specifies the password to use for LDAP bind, along with the Bind DN above.

## Plugin usage
### Get all user accounts
This connector retrieves **all attributes of all user accounts** which are members of the target Active Directory domain. Computer accounts are _not_ retrieved.

Specify the **base dn** (ex: dc=mycompany, dc=com) of the LDAP query when creating the dataset.

### Get all computer accounts
This connector retrieves **all attributes of all computer accounts** which are members of the target Active Directory domain.

Specify the **base dn** (ex: dc=mycompany, dc=com) of the LDAP query when creating the dataset.