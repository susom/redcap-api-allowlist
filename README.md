# API Allowlist
This external module adds additional IP and user-based constraints on API access to REDCap.

## How it works
This module provides a security filter to all API requests, blocking all API requests by default and only allowing permitted API requests based on project, user, or IP range.

Permission to use the API is controlled by the 'API Allowlist Rules Project'.  The EM will automatically
create this project if you select the 'first-time-setup' option in the config.

When an API request arrives to your server, the Allowlist database is checked - only if the request matches
an entry is it permitted through.  Otherwise the request is rejected.

After creation, you can enter as many rules as you like to permit API access.  If someone attempts to use
the API and is rejected, you can customize the message they will see.  The Rules project can also be used
as a 'request' survey for users the request access to the API.

Upon activation of this module, a new database table will be created to log all API access.  The table is 
called 'redcap_log_api_allowlist'. 
##Rejection Notifications
When an API request is rejected, in addition to the 403 message specified in the module configuration, the token owner wilil recieve
an email summarizing the rejections. Users will recieve a maximum of one email every 15 minutes regardless of the amount of rejected requests.

## Viewing API Activity
The API Allowlist Info page from the control center provides example SQL queries you can use to view API activity.
These can be easily added to the 'Admin Dashboard' external module from the REDCap repository.

## FAQ
Administrators : Navigate to the control center and enable the API Allowlist module after clicking the External Modules link on the
left sidebar under Technical / Developer tools.

Clicking configure and checking the `First Time Setup` checkbox will create a new `API Allowlist EM Rules`
project and default the rest of the options on the configuration page. Clicking this option will also enable surveys within
the project.

### What kinds of allowlist exceptions can I create?
- You can allow access by network IP range.  This uses CIDR notation so you can list an entire block of addresses easily.
- You can allow access by project_id - this will allow any users to that project that have a valid API token to use the API
- You can allow access by user/project - this will allow only certain users from specific projects to access the API

### How often will a user be emailed if their API requests are rejected?
- The default is 15 minutes.  Which means the fist rejection will result in 1 email, but subsequent rejections will
be pooled until 15 minutes has elapsed.  A final email containing all rejection messages will then be sent.  This was
done to prevent users from getting spammed with hundreds of emails upon running a script from a source not on the allowlist.

### How can a user STOP getting emailed?
- If your API token is associated with a script you no longer control, you can reset your API token from the project
User Rights page,  This will delete your API token and prevent future emails.


### How can I thank the developers of this EM?
- Beer and other beverages can be shipped to 455 Broadway, 3rd floor Discovery Hall, Redwood City, CA - Attn: REDCap Team