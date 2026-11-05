// git connect testing 12
public with sharing class AgentCreateUserAction {

    public class UserCreationException extends Exception {}

    private static final Set<String> BLOCKED_PROFILES =
        new Set<String>{ 'System Administrator' };
    private static final String DEFAULT_ROLE = 'NA';
    private static final String DEFAULT_LICENSE = 'Salesforce';

    // ---------- INPUT ----------
    public class Request {
        @InvocableVariable(label='First Name'
            description='First name of the new user' required=true)
        public String firstName;

        @InvocableVariable(label='Last Name'
            description='Last name of the new user' required=true)
        public String lastName;

        @InvocableVariable(label='Email'
            description='Email address of the new user' required=true)
        public String email;

        @InvocableVariable(label='User Id'
            description='Employee/SSO user id. Stored in Federation ID' required=true)
        public String userId;

        @InvocableVariable(label='Profile Name'
            description='Exact Salesforce profile name, e.g. Standard User' required=true)
        public String profileName;

        @InvocableVariable(label='Role Name'
            description='Optional. Role name. Leave empty if the user did not provide one'
            required=false)
        public String roleName;

        @InvocableVariable(label='License Name'
            description='Optional. User license name. Leave empty if the user did not provide one'
            required=false)
        public String licenseName;

        @InvocableVariable(label='Copy Access From'
            description='Optional. Email or username of an existing active user with the same profile to copy permission sets and groups from. Leave empty if the user did not provide one'
            required=false)
        public String copyFromEmail;
    }

    // ---------- OUTPUT ----------
    public class Response {
        @InvocableVariable(label='Is Success') public Boolean isSuccess;
        @InvocableVariable(label='Message') public String message;
        @InvocableVariable(label='New User Id') public Id newUserId;
        @InvocableVariable(label='Copied From User') public String copiedFromUser;
        @InvocableVariable(label='Role Assigned') public String roleAssigned;
        @InvocableVariable(label='Permission Sets Assigned') public Integer permissionSetsAssigned;
        @InvocableVariable(label='Groups Assigned') public Integer groupsAssigned;
    }

    @InvocableMethod(
        label='Create User With Cloned Access'
        description='Creates a Salesforce user, then copies permission sets, permission set groups and public groups/queues from an existing active user with the same profile'
        category='User Management')
    public static List<Response> createUser(List<Request> requests) {
        Response res = new Response();
        res.isSuccess = false;
        res.permissionSetsAssigned = 0;
        res.groupsAssigned = 0;
        try {
            if (requests == null || requests.size() != 1) {
                throw new UserCreationException('This action creates one user per call.');
            }
            process(requests[0], res);
        } catch (Exception e) {
            res.isSuccess = false;
            res.message = e.getMessage();
        }
        return new List<Response>{ res };
    }

    private static void process(Request req, Response res) {
        if (!Schema.sObjectType.User.isCreateable()) {
            throw new UserCreationException('You do not have permission to create users.');
        }

        // ---- 1. Clean and validate input ----
        String firstName   = clean(req.firstName);
        String lastName    = clean(req.lastName);
        String email       = clean(req.email);
        String fedId       = clean(req.userId);
        String profileName = clean(req.profileName);

        if (String.isBlank(firstName) || String.isBlank(lastName) || String.isBlank(email)
            || String.isBlank(fedId) || String.isBlank(profileName)) {
            throw new UserCreationException(
                'First name, last name, email, user id and profile are mandatory.');
        }
        if (!Pattern.matches('[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}', email)) {
            throw new UserCreationException('Email format is invalid: ' + email);
        }
        if (BLOCKED_PROFILES.contains(profileName)) {
            throw new UserCreationException(
                'Creating users with profile ' + profileName + ' through the agent is not allowed.');
        }

        // ---- 2. Defaults for optional inputs ----
        String roleName = clean(req.roleName);
        Boolean roleProvided = String.isNotBlank(roleName) && !roleName.equalsIgnoreCase('NA');
        String roleToUse = roleProvided ? roleName : DEFAULT_ROLE;

        String licenseName = clean(req.licenseName);
        if (String.isBlank(licenseName) || licenseName.equalsIgnoreCase('NA')) {
            licenseName = DEFAULT_LICENSE;
        }

        // ---- 3. Resolve lookups ----
        List<Profile> profiles = [
            SELECT Id, Name, UserLicense.Name
            FROM Profile WHERE Name = :profileName LIMIT 1
        ];
        if (profiles.isEmpty()) {
            throw new UserCreationException('Profile not found: ' + profileName);
        }
        Profile prof = profiles[0];
        if (prof.UserLicense.Name != licenseName) {
            throw new UserCreationException('Profile ' + prof.Name + ' uses license "'
                + prof.UserLicense.Name + '", not "' + licenseName + '".');
        }

        Id roleId = null;
        String roleNote = '';
        List<UserRole> roles = [SELECT Id FROM UserRole WHERE Name = :roleToUse LIMIT 1];
        if (!roles.isEmpty()) {
            roleId = roles[0].Id;
        } else if (roleProvided) {
            throw new UserCreationException('Role not found: ' + roleName);
        } else {
            roleNote = ' No role named "' + DEFAULT_ROLE + '" exists, so the role was left empty.';
        }
        res.roleAssigned = (roleId != null) ? roleToUse : 'None';

        List<UserLicense> lics = [
            SELECT TotalLicenses, UsedLicenses FROM UserLicense WHERE Name = :licenseName LIMIT 1
        ];
        if (!lics.isEmpty() && lics[0].UsedLicenses >= lics[0].TotalLicenses) {
            throw new UserCreationException('No free "' + licenseName + '" licenses available.');
        }

        // ---- 4. Duplicate check ----
        Integer dupCount = [
            SELECT COUNT() FROM User
            WHERE Username = :email OR FederationIdentifier = :fedId
        ];
        if (dupCount > 0) {
            throw new UserCreationException(
                'A user with this email/username or Federation ID already exists.');
        }

        // ---- 5. Choose the source user BEFORE creating the new user ----
        String copyFrom = clean(req.copyFromEmail);
        User source;
        if (String.isNotBlank(copyFrom)) {
            List<User> chosen = [
                SELECT Id, Name, Username FROM User
                WHERE (Email = :copyFrom OR Username = :copyFrom)
                  AND ProfileId = :prof.Id AND IsActive = true
                LIMIT 1
            ];
            if (chosen.isEmpty()) {
                throw new UserCreationException('No active user with profile ' + prof.Name
                    + ' found for "' + copyFrom + '". No user was created.');
            }
            source = chosen[0];
        } else {
            List<User> latest = [
                SELECT Id, Name, Username FROM User
                WHERE ProfileId = :prof.Id AND IsActive = true
                ORDER BY LastLoginDate DESC NULLS LAST
                LIMIT 1
            ];
            if (!latest.isEmpty()) {
                source = latest[0];
            }
        }

        // ---- 6. Create the user ----
        User newUser = new User(
            FirstName = firstName,
            LastName = lastName,
            Email = email,
            Username = email,
            FederationIdentifier = fedId,
            Alias = (firstName.left(1) + lastName).left(8),
            ProfileId = prof.Id,
            UserRoleId = roleId,
            TimeZoneSidKey = UserInfo.getTimeZone().getID(),
            LocaleSidKey = UserInfo.getLocale(),
            LanguageLocaleKey = UserInfo.getLanguage(),
            EmailEncodingKey = 'UTF-8'
        );
        Database.DMLOptions opts = new Database.DMLOptions();
        opts.emailHeader.triggerUserEmail = false; // set false if SSO-only
        Database.SaveResult sr = Database.insert(newUser, opts);
        if (!sr.isSuccess()) {
            throw new UserCreationException(
                'User creation failed: ' + sr.getErrors()[0].getMessage());
        }
        res.newUserId = newUser.Id;

        if (source == null) {
            res.isSuccess = true;
            res.copiedFromUser = 'None found';
            res.message = 'User created (' + newUser.Id + ') with role ' + res.roleAssigned
                + '. No existing active user with profile ' + prof.Name
                + ' was found, so no permission sets or groups were copied.' + roleNote;
            return;
        }
        res.copiedFromUser = source.Name + ' (' + source.Username + ')';

        // ---- 7. Clone permission sets / permission set groups ----
        Set<Id> psIds = new Set<Id>();
        Set<Id> psgIds = new Set<Id>();
        for (PermissionSetAssignment psa : [
            SELECT PermissionSetId, PermissionSetGroupId
            FROM PermissionSetAssignment
            WHERE AssigneeId = :source.Id AND PermissionSet.IsOwnedByProfile = false
        ]) {
            if (psa.PermissionSetGroupId != null) {
                psgIds.add(psa.PermissionSetGroupId);
            } else {
                psIds.add(psa.PermissionSetId);
            }
        }
        List<PermissionSetAssignment> newPsas = new List<PermissionSetAssignment>();
        for (Id psgId : psgIds) {
            newPsas.add(new PermissionSetAssignment(
                AssigneeId = newUser.Id, PermissionSetGroupId = psgId));
        }
        for (Id psId : psIds) {
            newPsas.add(new PermissionSetAssignment(
                AssigneeId = newUser.Id, PermissionSetId = psId));
        }

        // ---- 8. Clone public group / queue membership ----
        List<GroupMember> newMembers = new List<GroupMember>();
        for (GroupMember gm : [
            SELECT GroupId FROM GroupMember
            WHERE UserOrGroupId = :source.Id AND Group.Type IN ('Regular', 'Queue')
        ]) {
            newMembers.add(new GroupMember(GroupId = gm.GroupId, UserOrGroupId = newUser.Id));
        }

        List<String> errors = new List<String>();
        if (!newPsas.isEmpty()) {
            res.permissionSetsAssigned = countSuccess(
                Database.insert(newPsas, false), errors, 'Permission set');
        }
        if (!newMembers.isEmpty()) {
            res.groupsAssigned = countSuccess(
                Database.insert(newMembers, false), errors, 'Group');
        }

        res.isSuccess = true;
        res.message = 'User ' + firstName + ' ' + lastName + ' created (' + newUser.Id
            + ') with role ' + res.roleAssigned + '. Access copied from ' + res.copiedFromUser + ': '
            + res.permissionSetsAssigned + ' of ' + newPsas.size() + ' permission set(s)/group(s), '
            + res.groupsAssigned + ' of ' + newMembers.size() + ' public group(s)/queue(s).'
            + roleNote
            + (errors.isEmpty() ? '' : ' Some items failed: ' + String.join(errors, '; '));
    }

    private static Integer countSuccess(
            List<Database.SaveResult> results, List<String> errors, String label) {
        Integer ok = 0;
        for (Database.SaveResult r : results) {
            if (r.isSuccess()) {
                ok++;
            } else {
                for (Database.Error err : r.getErrors()) {
                    if (err.getStatusCode() != StatusCode.DUPLICATE_VALUE) {
                        errors.add(label + ': ' + err.getMessage());
                    }
                }
            }
        }
        return ok;
    }

    private static String clean(String s) {
        return s == null ? null : s.trim();
    }
}