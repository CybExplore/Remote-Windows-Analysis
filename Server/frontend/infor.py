import wmi
import json
import getpass
from datetime import datetime

c = wmi.WMI()
current_user = getpass.getuser()

def wmi_datetime_to_iso(wmi_dt):
    """Convert WMI datetime string to ISO 8601 or return as is if invalid."""
    try:
        return datetime.strptime(wmi_dt.split('.')[0], "%Y%m%d%H%M%S").isoformat()
    except Exception:
        return wmi_dt

def get_user_account_info(username):
    for user in c.Win32_UserAccount():
        if user.Name.lower() == username.lower():
            return {prop: getattr(user, prop) for prop in user.properties}
    return {}

def get_user_groups(username):
    groups = []
    for group in c.Win32_GroupUser():
        if f'Name="{username}"' in str(group.PartComponent):
            try:
                group_name = group.GroupComponent.split('Name="')[1].split('"')[0]
                groups.append(group_name)
            except IndexError:
                continue
    return groups

def get_user_profiles(username):
    profiles = []
    for profile in c.Win32_UserProfile():
        if profile.LocalPath and username.lower() in profile.LocalPath.lower():
            profiles.append({
                "LocalPath": profile.LocalPath,
                "LastUseTime": wmi_datetime_to_iso(profile.LastUseTime) if profile.LastUseTime else None,
                "Status": profile.Status
            })
    return profiles

def get_logged_on_sessions(username):
    sessions = []
    for session in c.Win32_LogonSession():
        assoc_users = c.query(f"ASSOCIATORS OF {{Win32_LogonSession.LogonId='{session.LogonId}'}} WHERE AssocClass=Win32_LoggedOnUser Role=Dependent")
        for user in assoc_users:
            if user.Name.lower() == username.lower():
                sessions.append({
                    "LogonId": session.LogonId,
                    "LogonType": session.LogonType,
                    "StartTime": wmi_datetime_to_iso(session.StartTime) if session.StartTime else None
                })
    return sessions

def get_user_environment_variables(username):
    # This requires registry access or another method, complicated in WMI; 
    # skipping here unless you want me to add that.
    return {}

user_data = {
    "account_info": get_user_account_info(current_user),
    "groups": get_user_groups(current_user),
    "profiles": get_user_profiles(current_user),
    "sessions": get_logged_on_sessions(current_user),
    "environment": get_user_environment_variables(current_user)
}

print(json.dumps(user_data, indent=4))





    # {
    #     "AccountType": 512,
    #     "Caption": "DESKTOP-AOU91JJ\\WDAGUtilityAccount",
    #     "Description": "A user account managed and used by the system for Windows Defender Application Guard scenarios.",
    #     "Disabled": true,
    #     "Domain": "DESKTOP-AOU91JJ",
    #     "FullName": "",
    #     "InstallDate": null,
    #     "LocalAccount": true,
    #     "Lockout": false,
    #     "Name": "WDAGUtilityAccount",
    #     "PasswordChangeable": true,
    #     "PasswordExpires": true,
    #     "PasswordRequired": true,
    #     "SID": "S-1-5-21-550850760-2695552310-605195006-504",
    #     "SIDType": 1,
    #     "Status": "Degraded"
    # }

