package org.wso2.custom.extensions.password.validator;

import org.wso2.carbon.identity.mgt.policy.AbstractPasswordPolicyEnforcer;
import java.util.Map;

public class PasswordPalindromPolicy extends AbstractPasswordPolicyEnforcer{

    boolean PALINDROM_CHECK_ENABLED = true;

    public static boolean isPalindrome(String str) {
        int left = 0;
        int right = str.length() -1;

        while(left < right) {
            if(str.charAt(left) != str.charAt(right)) {
                return false;
            }
            left ++;
            right --;
        }
        return true;
    }


    @Override
    public boolean enforce(Object... args) {

        if (args != null) {

            String password = args[0].toString();
            if (password.length() > 0 && PALINDROM_CHECK_ENABLED && isPalindrome(password)) {
                errorMessage = "Password cannot be a palindrom";
                return false;
            }
        }
        return true;
    }


    @Override
    public void init(Map<String, String> arg0) {
        if (arg0 != null && arg0.size() > 0) {
            PALINDROM_CHECK_ENABLED = Boolean.parseBoolean(arg0.get("palindrom.check.enabled"));
        }

    }


}