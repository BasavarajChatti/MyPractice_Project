public with sharing class AgentRevokeUserAccessAction {

    public class RevokeException extends Exception {}

    // Users with these profiles cannot be deactivated through the agent
    private static final Set<String> PROTECTED_PROFILES =
        new Set<String>{ 'System Administrator' };

    // ---------- INPUT ----------
    public class Request {
        @InvocableVariable(label='First Name'
            description='Exact first name of the user to deactivate. Use together with last name'
            required=false)
        public String firstName;

        @InvocableVariable(label='Last Name'
            description='Exact last name of the user to deactivate. Use together with first name'
            required=false)
        public String lastName;

        @InvocableVariable(label='Email'
            description='Exact email address or username of the user to deactivate. Use this instead of first and last name'
            required=false)
        public String email;
    }

    // ---------- OUTPUT ----------
    public class Response {
        @InvocableVariable(label='Is Success') public Boolean isSuccess;
        @InvocableVariable(label='Message') public String message;
        @InvocableVariable(label='Deactivated User Id') public Id deactivatedUserId;
        @InvocableVariable(label='Deactivated Username') public String deactivatedUsername;
    }

    @InvocableMethod(
        label='Revoke User Access'
        description='Finds a Salesforce user by exact email, or by exact first and last name, and deactivates the user by unchecking the Active checkbox'
        category='User Management')
    public static List<Response> revokeAccess(List<Request> requests) {
        Response res = new Response();
        res.isSuccess = false;
        try {
            // One user per call keeps this at 1 SOQL and 1 DML
            if (requests == null || requests.size() != 1) {
                throw new RevokeException('This action deactivates one user per call.');
            }
            process(requests[0], res);
        } catch (Exception e) {
            res.isSuccess = false;
            res.message = e.getMessage();
        }
        return new List<Response>{ res };
    }

    private static void process(Request req, Response res) {
        if (!Schema.sObjectType.User.fields.IsActive.isUpdateable()) {
            throw new RevokeException('You do not have permission to deactivate users.');
        }

        // ---- 1. Validate input: email OR (first name AND last name) ----
        String firstName = clean(req.firstName);
        String lastName  = clean(req.lastName);
        String email     = clean(req.email);
        Boolean hasEmail = String.isNotBlank(email);
        Boolean hasName  = String.isNotBlank(firstName) && String.isNotBlank(lastName);

        if (!hasEmail && !hasName) {
            throw new RevokeException(
                'Please provide the exact email address, or both the exact first name and last name.');
        }

        // ---- 2. Query the user (1 SOQL) ----
        List<User> matches;
        if (hasEmail) {
            matches = [
                SELECT Id, Name, Username, Email, IsActive, Profile.Name
                FROM User
                WHERE (Email = :email OR Username = :email) AND UserType = 'Standard'
                LIMIT 6
            ];
        } else {
            matches = [
                SELECT Id, Name, Username, Email, IsActive, Profile.Name
                FROM User
                WHERE FirstName = :firstName AND LastName = :lastName AND UserType = 'Standard'
                LIMIT 6
            ];
        }
        if (matches.isEmpty()) {
            throw new RevokeException(
                'No user found for the details provided. Please check the exact spelling.');
        }

        List<User> activeMatches = new List<User>();
        for (User u : matches) {
            if (u.IsActive) {
                activeMatches.add(u);
            }
        }
        if (activeMatches.isEmpty()) {
            res.message = matches[0].Name + ' (' + matches[0].Username
                + ') is already inactive. No changes were made.';
            return;
        }
        if (activeMatches.size() > 1) {
            List<String> names = new List<String>();
            for (User u : activeMatches) {
                names.add(u.Name + ' (' + u.Username + ')');
            }
            throw new RevokeException('More than one active user matches: '
                + String.join(names, '; ')
                + '. No changes were made. Please provide the exact Username of the user to deactivate.');
        }

        // ---- 3. Safety checks ----
        User target = activeMatches[0];
        if (target.Id == UserInfo.getUserId()) {
            throw new RevokeException('You cannot deactivate yourself.');
        }
        if (PROTECTED_PROFILES.contains(target.Profile.Name)) {
            throw new RevokeException('Users with profile ' + target.Profile.Name
                + ' cannot be deactivated through the agent.');
        }

        // ---- 4. Deactivate (1 DML, only the field that changes) ----
        Database.SaveResult sr = Database.update(new User(Id = target.Id, IsActive = false), false);
        if (!sr.isSuccess()) {
            throw new RevokeException('Could not deactivate ' + target.Name + ': '
                + sr.getErrors()[0].getMessage());
        }

        res.isSuccess = true;
        res.deactivatedUserId = target.Id;
        res.deactivatedUsername = target.Username;
        res.message = target.Name + ' (' + target.Username + ') has been deactivated.';
    }

    private static String clean(String s) {
        return s == null ? null : s.trim();
    }
}