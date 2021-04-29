# wso2-event-password-validator
Custom event handler that would enforce the password policies. This event handler is capable of checking for blacklisted passwords and palindrom passwords.

## Build

Clone the repository and in the directory where the pom file is located, issue the following command to build the project.
```
mvn clean install
```

## Deploy

After successfully building the project, the resulting jar file can be retrieved from the target directory. (the already built jar is included in the zip file) copy the resulting jar to the <IS_HOME>/repository/components/dropins/ directory.

In the deployment.toml this handler can be configured using the following configuration.(the following configuration would be global, i.e. for all tenants the following configuration would apply.)

```
[[event_handler]]
name= "CustomPasswordPolicyValidator"
subscriptions =["PRE_UPDATE_CREDENTIAL","PRE_UPDATE_CREDENTIAL_BY_ADMIN"]
[event_handler.properties]
enable = true
'class.PasswordBlacklistPolicy'= 'org.wso2.custom.extensions.password.validator.BlackListedPasswordPolicy'
'class.PasswordPalindromPolicy'= 'org.wso2.custom.extensions.password.validator.PasswordPalindromPolicy'
'blacklisted.passwords'= "#bigguy,#bigguy1,#superxr"
'blacklisted.passwords.check.enable' = true
'palindrom.check.enable'= true
```
Start the server.

You can enable/disable and configure the validator per tenant under the resident idp configuration to suit your needs.

<img width="1680" alt="Screen Shot 2021-04-29 at 2 51 33 PM" src="https://user-images.githubusercontent.com/47600906/116530108-46062e80-a8fb-11eb-9ff3-9998fdc4d392.png">
