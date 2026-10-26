#!/usr/bin/env bash
export NetworkAccess__TrustedNetwork="${NetworkAccess__TrustedNetwork:-true}"
export ASPNETCORE_URLS="${ASPNETCORE_URLS:-http://0.0.0.0:5203}"
export AllowedHosts="${AllowedHosts:-localhost;127.0.0.1;[::1];clauderunner;clauderunner.nmcq.org;192.168.1.209}"
export ASPNETCORE_ENVIRONMENT="${ASPNETCORE_ENVIRONMENT:-Development}"
exec dotnet watch --project KittyClaw.Web --non-interactive --no-launch-profile
