# API Allowlist
This external module adds additional IP, user, and project-based constraints on API access to REDCap.

## Changes
- 2022-02-24
  - Updated the way logging was done to meet requirements of newer EM framework versions
  - If you have previously installed this EM, you need to update the rules project and also add a new column to the logging table:
   <br> `alter table redcap_log_api_allowlist add column notified bit default b'0';`

## How it works
This module provides a security filter to all API requests, blocking all API requests by default and only
allowing permitted API requests based on project, user, or IP range.

Permission to use the API is controlled by the 'API Allowlist Rules Project'.  The EM will automatically
create this project if you select the 'first-time-setup' option in the config.

When an API request arrives to your server, the Allowlist database is checked - only if the request matches
an rule/entry is it permitted to continue.  Non-matching requests are rejected with a custom message that
includes a survey url to request an exception (e.g. new rule).

After creation, you can enter as many rules as you like to permit API access.  If someone attempts to use
the API and is rejected, you can customize the message they will see.  The Rules project can also be used
as a 'request' survey for users the request access to the API.

Upon activation of this module, a new database table will be created to log all API access.  The table is
called 'redcap_log_api_allowlist'.

## Rejection Notifications
When an API request is rejected, in addition to the 403 message specified in the module configuration, the
token owner will recieve an email summarizing the rejections. Users will receive a maximum of one email every
60 minutes regardless of the amount of rejected requests.

## Viewing API Activity
The API Allowlist Info page from the control center provides example SQL queries you can use to view API activity.
These can be easily added to the 'Admin Dashboard' external module from the REDCap repository.

## FAQ
Administrators : Navigate to the control center and enable the API Allowlist module after clicking the External
Modules link on the left sidebar under Technical / Developer tools.

Clicking configure and checking the `First Time Setup` checkbox will create a new `API Allowlist Rules Project`
project and default the rest of the options on the configuration page. Clicking this option will also enable surveys
within the project.  You should customize the first instrument to match your institution's policies.

### What kinds of allowlist exceptions can I create?
- You can allow access by network IP range.
  - Multiple IP addresses can be added (comma or return-separated)
  - You can use CIDR notation (e.g. 10.0.0.0/16).
    - It does NOT support subnet mask (e.g. 10.0.0.0/255.255.0.0)
    - It does NOT support an IP-defined range (e.g. 10.0.0.0-10.0.255.255)
- You can allow access by project_id
  - this will allow any users with API tokens to that project to connect
- You can allow access by user
  - trusted users can connect from any IP to any project
- Lastly, you can create more restrictive rules by combining the three options.  For example, specifing a user, a project, and an IP address will ONLY allow that user to access that project from that IP address.

### How often will a user be emailed if their API requests are rejected?
- The default is 60 minutes.  Which means the fist rejection will result in 1 email, but subsequent rejections will
be pooled until this gap has elapsed.  A final email containing all rejection messages will then be sent.  This was
done to prevent users from getting spammed with hundreds of emails upon running a script from a source not on the allowlist.

### How can a user STOP getting emailed?
- If your API token is associated with a script you no longer control, you can reset your API token from the project
User Rights page,  This will delete your API token and prevent future emails.

### Do Rules Expire?
- Yes, you can make your rules expire based on the anticipated lifetime of the project.  This helps reduce your attack surface area.

### What can I do with the logs?
- The logging information also stores the total time elapsed by the API call.  This makes it a valuable source to determine if some users are abusing your REDCap API, by, for example, repeatedly exporting large volumes of data and consuming excessive server processes and memory.

### How can I thank the developers of this EM?
- Beer and other beverages can be shipped to 455 Broadway, 3rd floor Discovery Hall, Redwood City, CA - Attn: REDCap Team

### Alerts and Notifications setup
The Alerts & Notifications feature allows you to construct alerts and send customized notifications.
These notifications may be sent to one or more recipients and can be triggered or scheduled when a form/survey is saved and/or based on conditional logic whenever data is saved or imported.

The following two alerts are implemented in the Stanford REDCap instance and might be useful:

1. Forward to service desk (JIRA)
   1. When 'API Allow List Request' is saved with a complete status: send to JIRA email handler
2. API exception about to expire
   1. When an API Allow List rule is about to expire: `datediff([expiration_date], 'today','M')<=1 and [enabled(1)]='1'`
   2. Send email to user detailing expiration
