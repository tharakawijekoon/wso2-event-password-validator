package org.wso2.custom.extensions.password.validator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class BlackListedPasswordPolicy extends org.wso2.carbon.identity.mgt.policy.AbstractPasswordPolicyEnforcer{

    List<String> BLACKLISTED_PASSWORDS = new ArrayList<String>();
    boolean BLACKLISTED_PASSWORD_CHECK_ENABLED = true;

    @Override
    public boolean enforce(Object... args) {

        if (args != null) {

            String password = args[0].toString();
            if (password.length() > 0 && BLACKLISTED_PASSWORD_CHECK_ENABLED && BLACKLISTED_PASSWORDS.contains(password)) {
                errorMessage = "Password is black listed";
                return false;
            }
        }
        return true;
    }

    @Override
    public void init(Map<String, String> arg0) {
        if (arg0 != null && arg0.size() > 0) {

            BLACKLISTED_PASSWORDS = Arrays.asList(arg0.get("blacklisted.passwords").split("\\s*,\\s*"));
            BLACKLISTED_PASSWORD_CHECK_ENABLED = Boolean.parseBoolean(arg0.get("blacklisted.passwords.check.enabled"));
        }
    }


}

