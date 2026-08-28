# Event ID catalog

Windows Event Log entries use the `TierLevelIsolation` source in the
`Application` log. Event IDs are unique by meaning within that source. Debug
events are written to the text log only.

If the `TierLevelIsolation` source is unavailable and cannot be registered,
Windows Event Log output is disabled for that run. The scripts do not write
under the shared `Application` source.

## TierLevelComputerManagement

| Event ID | Severity    | Meaning                                                            |
|----------|-------------|--------------------------------------------------------------------|
| 1000     | Information | Computer management script started                                 |
| 1003     | Error       | Unexpected error while updating the Tier 0 computer group          |
| 1004     | Error       | AD Web Service connection failed during computer management        |
| 1101     | Error       | Default or Active Directory configuration was not found            |
| 1102     | Error       | Configuration file could not be read                               |
| 1103     | Error       | Specified configuration file was not found                         |
| 1104     | Error       | Unexpected error while reading the configuration                   |
| 1200     | Error       | Tier 0 computer group was not found                                |
| 1201     | Debug       | Current Tier 0 computer group member count                          |
| 1202     | Error       | Tier 1 computer group was not found                                |
| 1203     | Error       | AD Web Service is unavailable                                      |
| 1204     | Warning     | Tier 0 computer object is not listed in the global catalog         |
| 1300     | Warning     | Tier 0 computer OU is missing                                      |
| 1301     | Debug       | Computer count in a Tier 0 OU                                      |
| 1302     | Information | Computer is being added to the Tier 0 computer group               |
| 1303     | Debug       | Tier 0 computer group was updated                                  |
| 1304     | Warning     | Computer is being removed from the Tier 0 computer group           |
| 1305     | Debug       | OU does not contain computer objects                               |
| 1306     | Warning     | AD Web Service is unavailable; unexpected computers cannot be verified |
| 1400     | Warning     | Tier 1 computer OU is missing                                      |
| 1401     | Information | Computer was added to the Tier 1 computer group                    |
| 1402     | Error       | Unexpected error while updating the Tier 1 computer group          |
| 1403     | Warning     | Computer is being removed from the Tier 1 computer group           |
| 1404     | Warning     | Tier 1 computer object is not listed in the global catalog         |
| 1405     | Debug       | Tier 1 computer group was updated                                  |

---

## TierLevelUserManagement

| Event ID | Severity    | Meaning                                                                    |
|----------|-------------|----------------------------------------------------------------------------|
| 2000     | Information | User management script started                                             |
| 2001     | Warning     | Configured log file path is invalid                                        |
| 2002     | Error       | Default or Active Directory configuration was not found                    |
| 2003     | Error       | Configuration file could not be read                                       |
| 2004     | Error       | Specified configuration file was not found                                 |
| 2005     | Error       | Unexpected error while reading the configuration                           |
| 2006     | Error       | Requested scope conflicts with the configured scope                        |
| 2007     | Debug       | Current scope includes Tier 0 and Tier 1                                   |
| 2008     | Debug       | Schema Admins validation started                                           |
| 2009     | Debug       | Enterprise Admins validation started                                       |
| 2010     | Debug       | Tier 0 account isolation succeeded                                         |
| 2011     | Debug       | Tier 0 account isolation failed                                            |
| 2012     | Debug       | Tier 1 account isolation succeeded                                         |
| 2013     | Debug       | Tier 1 account isolation failed                                            |
| 2014     | Debug       | `Set-TierLevelIsolation` was called                                        |
| 2015     | Debug       | Configuration was read from the specified file                             |
| 2101     | Error       | Kerberos Authentication Policy was not found                               |
| 2102     | Warning     | User OU is missing                                                         |
| 2103     | Warning     | Built-in Administrator is located in a Tier 0 user OU                      |
| 2104     | Information | Kerberos Authentication Policy was assigned to a user                      |
| 2105     | Information | User was marked as sensitive and cannot be delegated                       |
| 2106     | Information | User was added to the Protected Users group                                |
| 2107     | Error       | Access was denied while changing a user attribute                          |
| 2108     | Error       | Active Directory identity was not found                                    |
| 2109     | Error       | Unexpected error during user isolation                                     |
| 2200     | Warning     | Configured group SID is unavailable                                        |
| 2201     | Warning     | User is being removed from a privileged group                              |
| 2202     | Error       | AD Web Service is unavailable while removing a privileged group member     |
| 2203     | Error       | Error while removing a user from a privileged group                        |
| 2204     | Error       | Unexpected error while processing a privileged group member                |
| 2205     | Debug       | Privileged service account was detected                                    |
| 2206     | Debug       | Privileged user was detected                                               |
| 2207     | Debug       | Search of additional privileged groups started                             |
| 2208     | Warning     | Privileged group was not found                                             |
| 2209     | Warning     | General error while processing privileged user groups                      |
| 2210     | Warning     | Domain from a configured group entry was not found                         |
| 2211     | Information | `adminCount` was set to 1 on a nested Tier 0 group                         |
| 2212     | Error       | `adminCount` could not be set on a nested Tier 0 group                     |
| 2213     | Error       | DNS domain could not be resolved for a nested group                        |
| 2300     | Debug       | Domain could not be contacted during privileged-group discovery            |
| 2301     | Debug       | DNS domain name was resolved from a NetBIOS name                           |
| 2302     | Warning     | Domain for a NetBIOS name was not found                                    |
| 2303     | Error       | NetBIOS name could not be converted to a DNS domain name                   |

---
