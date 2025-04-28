# TierLevelIsolation
## Overview 
This solution implements Tier Level isolation as described in the blog "Protection Tier 0 the modern way". It prepares your Active Directory forest to support Kerberos Authentication Policies, creating prerequisites to isolate Tier 0 or Tier 1 and automate the Tier 0 / Tier 1 user management. The Kerberos Authentication Policy ensure privileged accounts must use Kerberos as authentication protocol and can only request Kerberos TGT on predefined computers. 
The solution automates the management of Tier 0 and Tier 1 users with Kerberos Authentication Policies through scripts. One script adds AD-Computer objects to an AD group included in the Kerberos Authentication Policy claim. Another script applies the policy to Tier 0 / Tier 1 users in the correct OU, and for Tier 0, removes users from privileged groups if they are not located in the correct OU.
The user management script ensures that users are added to the protected users group and removes users from privileged groups if they are not part of the administrator OU. 
This solution can manage Tier 0 and Tier 1 users within a single Active Directory Domain or across the entire Active Directory Forest. It utilizes scheduled tasks that run on your primary Active Directory domain, typically the Forest Root domain. 

# The scripts in a nutshell
## Install.ps1
Install the solution into you Active Directory environment
### TierLevelComputerManagement.ps1
Adds computer to the Kerberos Authentication claim group
### TierLevelUserManagement.ps1
Applies the Kerberos Authentication Policy to the Tier Level administrators

# Installation 
Preparation
Before you start installing TierLevelIsolation, there are a few preparatory steps that need to be done. Make sure you have all the necessary materials and tools on hand. 
1.	Download the latest version of TierLevelIsolation
2.	Classify the files as trusted (remove the "mark of the web" attribute) 
3.	The installation process requires Enterprise Administrator permissions.
4.	The installation can be done on a member server on which the Active Directory PowerShell modules and the Group Policy Powershell modules are installed.
5.	(optional) After a review of the files, the files should be signed
6.	Administration

## Installation
The installation process is started via the install.ps1 script. The installation script guides you through the configuration and creates the required resource. The install.ps1 script should be run as an enterprise administrator to avoid access issues with the Kerberos Authentication Police. 

### Target Selection
The script provides a list of the Active Directory domains in the current forest. Here you have to make a selection in which domains the tier-level isolation should take place.

### Scope Selection
In the next step, the tier levels for which the TierLevelIsolation is to be used are defined

## Tier 0
### Tier 0 Administrator OU
Here you have to specify the path in which the Tier0 administrators are stored. The path can be specified as a relative path (without the domain components e.g. OU=Admins,OU=Tier 0,OU=Admin), in which case the same OU structure will be applied in all domains. If the OU structures in the individual domains differ, this should be defined individually for each OU (e.g. OU=Admins,OU=Tier 0,OU=Admin,DC=contoso,DC=com)
If there are Tier 0 users in different OU structures, both relative and fully qualified DN can be specified

### Tier 0 Service Account OU
This is the path where Tier 0 service accounts are stored. Tier 0 service accounts differ from user accounts in that they are not assigned a Kerberos authentication policy, even though they are in AD privileged groups. Again, multiple paths can be specified as relative DN or fully qualified DN.

### Tier 0 Server OU
Is one or more path to the Tier 0 computer objects.

### Tier 0 Kerberos Authentication Policy 
The name of the Tier 0 Kerberos Authentication Policy. 

## Tier 1
### Tier 1 Administrator OU
Is the realtive path where the Tier 1 Administrator accounts are stored. If the path is specified as a relative DN, the OU structure must be present in all domains. Again, multiple DistinguishedNames can be specified.

### Tier 1 Service Account OU
This setting has no function at the moment

### Tier 1 Server OU
Is the absolute or relative DistinguishedName in which the server objects are stored.

### Tier 1 Kerberos Authentication Policy name
Is the name of the Tier 1 Kerberos Authentication Policy

## Server Groups
### Tier 0 Server group name
Is the name of the computer group to be included in the Tier 0 computer. This group is created in the Standard Users container. The group should be moved to a Tier 0 managed OU
### Tier 1 Server group name
Is the name of the group in which the Tier 1 computers are included. This group is created in the Standard Users container. 
### Protected Group
This setting determines whether Tier 0 / Tier 12 users are automatically added to the Protected User group. 
[0] All user objects stored in the Tier 0 Admin OU are automatically added to the Protected Users group
[1] All user objects stored in the Tier 1 Admin OU are automatically added to the Protected Users group
[2] Both Tier 0 and Tier 1 user objects are added to the Protectd Users group
[3] Neither Tier 0 nor Tier 1 administrators will be added to the Protected Users group
### Enable privileged group clean up
If the answer to this question is Y, all user objects from the following groups will be removed, unless they are in the Tier 0 Admin OU, Tier 0 Service Account OU, the Built Administrator and not a GMSA.
### Group managed service account
In a multi-domain forest, a GMSA is needed to manage the users in the forest domains. The SAM account name must be entered here. 
The GMSA is created on demand and added to the Enterprise Administrators group


## Post installation tasks
### Validate Kerberos AmoringKerberos Amoring must be active to isolate Tier 0 / Tier 1 administrators. For this purpose, the current Kerberos cache should be set with 
KLIST PURGE 
Delete and request a new Kerberos ticket (e.g. dir \\<domain>\SYSVOL). Afterwards, you have the requested Kerberos ticket with 
KLIST
Indicate. In the TGT displayed, the value "Cache Flags" should be set to 0x41 -> PRIMARY FAST
The group policy settings for Kerberos Amoring are made only in the local domain. For all other domains in the AD-Forest, the settings must be manually completed.

If Kerberos Amoring is not available validate:
### Default Domain Policy
This enables support for Kerberos Amoring for all client computers. This is done via the setting:
Administrative Templates\System\Kerberos\Kerberos Amoring

### Default Domain Controller Policy:
In this group policy, Kerberos Amoring is enabled at the domain level. The following settings are made for this purpose:
Administrative Template\System\KDC\Kerberos Amoring Support mode
Administrative Templates\System\Kerberos\Kerberos Amoring

## Activation of Tier Level Isolation
Once installed, you will need to enable TierLevelIsolation. Activation is done via the Tier Level Isolation group policy. This policy group consists of 5 Schedule Tasks that run on the current domain. The schedule tasks are:
### Change user context
Group Policy Preference does not allow you to create a Schedule Task in the context of a GMSA. This task of this Schedule Task is to change the Schedule Tasks Tier 0 User Management / Tier 1 User Management from SYSTEM to the GMSA context
### Tier 0 computer management
The task of this schedule task is to add or remove computer objects from the Tier 0 server group
Both user Schedule Tasks have the trigger disabled by default to ensure that Tier 0 administrators are not locked out.
In the first step, the two schedule tasks "Tier 0 Computer Management" and "Tier 1 Computer Management" should be adapted. The default setting is that the task starts daily at 12 p.m. and then repeats every 10 minutes. 
### Tier 0 user management
This Schedule Task adds the Tier 0 Kerberos Authentication Policy to Tier 0 administrators
### Tier 1 computer management
The task of this schedule task is to add or remove computer objects from the Tier 1 server group
### tier 1 user management
This Schedule Task adds the Tier 0 Kerberos Authentication Policy to Tier 0 administrators

Once the Computer Management task has been started for the first time, all computer objects must appear in the Tier 0 Computer group. Once this is done, make sure that the Tier 0 Member Server objects have been restarted. 
## Active the Tier 0 and Tier 1 user management tasks
Both user Schedule Tasks have the trigger disabled by default to ensure that Tier 0 administrators are not locked out.
In the first step, the two schedule tasks "Tier 0 Computer Management" and "Tier 1 Computer Management" should be adapted. The default setting is that the task starts daily at 12 p.m. and then repeats every 10 minutes. 
Once the Computer Management task has been started for the first time, all computer objects must appear in the Tier 0 Computer group. Once this is done, make sure that the Tier 0 Member Server objects have been restarted. 
Subsequently, the TierLevel isolation based on "Kerberos Authentication Polices" was to be tested. To do this, the Kerberos Authentication Policy is to add a Tier 0 user and validate the logon with this user object. 
The test is successful if this user can only authenticate on a Tier 0 member server or a domain controller. (RDP from an unprotected system is not supported)
The test can be repeated with several users. Once the administrators are familiar with Kerberos Authentication Policy based Administration, the Tier 0 user management task is enabled in the TierLevelIsolation Group Policy. 
To do this, the trigger in the "Tier 0 User Management" tab must be set to active in the Group Policy in the Preferences/Schedule Task. The Taks starts at 12a.m. by default and repeats every 10 minutes. Depending on the environment, these values can be adjusted

# Monitoring
Monitoring is done in the Application Event log. For detailed information, a debug log file is also created. The path to the log file is logged as Windows events Source:TierLevelIsolation 1000 or Source:TierLevelIsolation 2000.
## Computer management
To monitor the computer management functions, look for the following events in the event log:
|Event ID|	Type|	Description|	Trigger|
1000	Information	Starting the Computer Management Script	This event is triggered when the Computer Management Script is executed. This event ID should appear every 10 minutes. 
1302	Information	Adding a Computer Object to the Tier 0 Computer Group	If a new computer object is detected in a Tier 0 computer OU, it is added to the Tier Level Isolation Computer group
1304	Warning	Removing a Computer Object from Tier Level OU	If a Computer Object is removed from the Tier Level OU, this Object is also removed from the group. 
1401	Information	Adding a Computer Object to the Tier 0 Computer Group	If a new computer object is detected in a Tier 1 computer OUs, it is added to the Tier Level Isolation Computer group

