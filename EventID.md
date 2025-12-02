# Known Event ID
## TierLevelComputerManagement
|EventID |Severity   |Message|
|---|---|---|
|1000| Information   | Computer management script started                                 |
|1002| Debug         | Reading configuration from AD                                      |
|1003| Error         | Missing AD configuration settings                                  |
|1004| Error         | AD Web Service failed to connect                                   |
|1100| Debug         | Reading configuration file from default configuration path         |
|1101| Debug         | Reading configuration from file                                    |
|1200| Error         | Cannot find the Tier 0 computer group                              |
|1201| Debug         | Current count of member in the Tier 0 computer group               |
|1202| Error         | Can't find Tier 1 computer group                                   |
|1203| Error         | AD Web Service failed to connect                                   |
|1204| Warning       | A Tier 0 computer object is not listed in the global catalog       |
|1300| Warning       | Missing a Tier 0 computer OU                                       |
|1301| Debug         | Count member in tier 0 group                                       |
|1302| Information   | Adding a computer to Tier 0 computer group                         |
|1303| Debug         | Tier 0 computer group updated                                      |
|1304| Warning       | Removing a computer from Tier 0 computer groups                    |
|1305| Debug         | A OU do not contain any computer object                            |
|1306| Warning       | ADWS is down cannot verify unexpected computers                    |
|1400| Warning       | A Tier 1 OU is missing                                             |
|1401| Information   | A computer is added to the Tier 1 computer group                   |
|1402| Error         | Unexpected error occurred while updating the Tier 1 computer group |
|1403| Warning       | Removing a computer from Tier 1 computer group                     |
|1404| Warning       | A Tier 1 computer object is not listed in the global catalog       |
|1405| Debug         | The Tier 1 computer is updated                                     |
---

## TierLevelUserManagement
|EventID|Severity    |Message|
|---|---|---|
|2000   | Information| Script started                                                  |
|2002   | Error      | Missing Kerberos Authentication Policy                          |
|2003   | Debug      | Failed to read the configuration form the config file           |
|2004   | Error      | configuration File missing                                      |
|2005   | Error      | Cannot read the configuration file                              |
|2006   | Error      | Configuration file parameter error                              |
|2008   | Debug      | Validating Schema admins                                        |
|2009   | Debug      | Validating Enterprise admins                                    |
|2010   | Debug      | successfully isolation of Tier 0 account                        |
|2011   | Debug      | An error occurred during the Tier 0 account isolation           |
|2012   | Debug      | successfully isolation of Tier 1 account                        |
|2013   | Debug      | An error occurred during the Tier 1 account isolation           |
|2014   | Debug      | calling the Set-TierLevelIsolation function                     |
|2101   | Error      | Kerberos Authentication Policy not found                        |
|2102   | Warning    | OU missing                                                      |
|2103   | Warning    | The Built-In Administrator located in Tier 0 users OU           |
|2104   | Information| A Kerberos Authentication Policy is added to a user             |
|2105   | Information| A user is marked as sensitive and cannot be delegated           |
|2106   | Information| A user is added to the protected users group                    |
|2107   | Error      | Access denied while changing user attribute                     |
|2108   | Error      | A AD identity not found                                         |
|2109   | Error      | Unexpected Error                                                |
|2200   | Warning    | Missing group SID                                               |
|2201   | Warning    | A user is removed from a privileged group                       |
|2202   | Error      | Cannot connect to AD-Webservice                                 |
|2203   | Error      | A error occurred while a removing a user from a privileged group|
|2204   | Error      | unexpected error                                                |
|2205   | Debug      | privileged service account detected                             | 
|2206   | Debug      | privileged user detected                                        |
|2300   | Error      | Cannot connect to a AD Web Service                              | 
---


