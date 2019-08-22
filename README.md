# API Whitelist
This external module adds additional IP and user-based constraints on API access to REDCap.

## How it works
This module provides a whitelist mechanism to allow certain projects to use the API functionality while
limiting others by user / project / and network IP address.

There is a REDCap project that acts as the API Whitelist database.  Each record in this project
is an exception to the firewall - allowing users to connect to your REDCap instance.

When an API request arrives to your server, the Whitelist database is checked - only if the request matches
an entry is it permitted through.  Otherwise the request is rejected.

A REDCap database table is created as well for this module that is used for logging


## FAQ

#### What kinds of whitelist exceptions can I create?
- You can allow access by network IP range.  This uses CIDR notation so you can whitelist an entire block of addresses easily.
- You can allow access by project_id - this will allow any users to that project that have a valid API token to use the API
- You can allow access by user/project - this will allow only certain users from specific projects to access the API


 ## TODO:
 
 