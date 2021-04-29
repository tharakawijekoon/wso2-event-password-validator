package org.wso2.custom.extensions.password.validator;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.mgt.policy.PolicyRegistry;
import org.wso2.carbon.identity.mgt.policy.PolicyViolationException;
import org.wso2.carbon.identity.password.policy.constants.PasswordPolicyConstants;
import org.wso2.carbon.identity.password.policy.internal.IdentityPasswordPolicyServiceDataHolder;
import org.wso2.carbon.identity.password.policy.util.Utils;

import java.util.*;

public class CustomPasswordPolicyValidatorHandler extends AbstractEventHandler implements IdentityConnectorConfig {
    private static final Log log = LogFactory.getLog(CustomPasswordPolicyValidatorHandler.class);

    public CustomPasswordPolicyValidatorHandler() {
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {
        Map<String, Object> eventProperties = event.getEventProperties();

        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        Object credentials = eventProperties.get(IdentityEventConstants.EventProperty.CREDENTIAL);

        Property[] identityProperties;
        try {
            identityProperties = IdentityPasswordPolicyServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving password policy properties.", e);
        }

        boolean passwordPolicyValidation = false;
        String passwordBlackListValidation = "false";
        String passwordPalindromeValidation =  "false";
        String blackListedPasswords = "";

        for (Property identityProperty : identityProperties) {
            if (identityProperty == null) {
                continue;
            }
            String propertyName = identityProperty.getName();
            String propertyValue = identityProperty.getValue();

            if (CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE.equals(propertyName)) {
                passwordPolicyValidation = BooleanUtils.toBoolean(propertyValue);
                if (!passwordPolicyValidation) {
                    if (log.isDebugEnabled()) {
                        log.debug("Custom Password Policy validation is disabled");
                    }
                    return;
                }
                continue;
            } else if (CustomPasswordPolicyConstants.PASSWORD_BLACKLIST_POLICY_ENABLE.equals(propertyName)) {
                if (StringUtils.isNotBlank(propertyValue)) {
                    passwordBlackListValidation = propertyValue;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Password Black List Validation not defined, hence not enabled");
                    }
                }
                continue;
            } else if (CustomPasswordPolicyConstants.PASSWORD_PALINDROME_POLICY_ENABLE.equals(propertyName)) {
                if (StringUtils.isNotBlank(propertyValue)) {
                    passwordPalindromeValidation = propertyValue;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Palindrome Password Policy validation not defined, hence not enabled");
                    }
                }
                continue;
            } else if (CustomPasswordPolicyConstants.BLACKLIST_PASSWORDS.equals(propertyName)) {
                if (StringUtils.isNotBlank(propertyValue)) {
                    blackListedPasswords = propertyValue;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Black list not defined. Using empty list of passwords");
                    }
                }
                continue;
            }

        }

        PolicyRegistry policyRegistry = new PolicyRegistry();

        String pwBlacklistPolicyCls = configs.getModuleProperties().
                getProperty(CustomPasswordPolicyConstants.PASSWORD_BLACKLIST_POLICY_CLASS);
        String pwPalinfromePolicyCls = configs.getModuleProperties().
                getProperty(CustomPasswordPolicyConstants.PASSWORD_PALINDROME_POLICY_CLASS);

        try {
            if (pwBlacklistPolicyCls != null) {
                BlackListedPasswordPolicy passwordBlackListPolicy = (BlackListedPasswordPolicy) Class.
                        forName(pwBlacklistPolicyCls).newInstance();
                HashMap pwBlackListParams = new HashMap<String, String>();
                pwBlackListParams.put("blacklisted.passwords", blackListedPasswords);
                pwBlackListParams.put("blacklisted.passwords.check.enabled", passwordBlackListValidation);
                passwordBlackListPolicy.init(pwBlackListParams);
                policyRegistry.addPolicy(passwordBlackListPolicy);
            }

            if (pwPalinfromePolicyCls != null) {
                PasswordPalindromPolicy passwordBlackListPolicy = (PasswordPalindromPolicy) Class.
                        forName(pwPalinfromePolicyCls).newInstance();
                HashMap pwPalindromeListParams = new HashMap<String, String>();
                pwPalindromeListParams.put("palindrom.check.enabled", passwordPalindromeValidation);
                passwordBlackListPolicy.init(pwPalindromeListParams);
                policyRegistry.addPolicy(passwordBlackListPolicy);
            }

        } catch (Exception e) {
            throw Utils.handleEventException(
                    PasswordPolicyConstants.ErrorMessages.ERROR_CODE_LOADING_PASSWORD_POLICY_CLASSES, null, e);
        }

        try {
            policyRegistry.enforcePasswordPolicies(credentials.toString(), userName);
        } catch (PolicyViolationException e) {
            throw Utils.handleEventException(
                    PasswordPolicyConstants.ErrorMessages.ERROR_CODE_VALIDATING_PASSWORD_POLICY, e.getMessage(), e);
        }
    }


    @Override
    public String getName() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getFriendlyName() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getCategory() {
        return "CustomPasswordPolicyValidator";
    }

    @Override
    public String getSubCategory() {
        return "DEFAULT";
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap();
        nameMapping.put(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE, "Enable Custom Password Policy Feature");
        nameMapping.put(CustomPasswordPolicyConstants.PASSWORD_BLACKLIST_POLICY_ENABLE, "Enable Password BlackList Policy");
        nameMapping.put(CustomPasswordPolicyConstants.PASSWORD_PALINDROME_POLICY_ENABLE, "Enable Password Palindrome Policy");
        nameMapping.put(CustomPasswordPolicyConstants.BLACKLIST_PASSWORDS, "BlackListed Passwords");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap();
        descriptionMapping.put(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE, "Enable Custom Password Policy Feature");
        descriptionMapping.put(CustomPasswordPolicyConstants.PASSWORD_BLACKLIST_POLICY_ENABLE, "Enable Password BlackList Policy");
        descriptionMapping.put(CustomPasswordPolicyConstants.PASSWORD_PALINDROME_POLICY_ENABLE, "Enable Password Palindrome Policy");
        descriptionMapping.put(CustomPasswordPolicyConstants.BLACKLIST_PASSWORDS, "List of BlackListed Passwords for Blacklist Policy");
        return descriptionMapping;
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {
        super.init(configuration);
        IdentityPasswordPolicyServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityConnectorConfig.class.getName(), this, null);
    }

    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE);
        properties.add(CustomPasswordPolicyConstants.PASSWORD_BLACKLIST_POLICY_ENABLE);
        properties.add(CustomPasswordPolicyConstants.PASSWORD_PALINDROME_POLICY_ENABLE);
        properties.add(CustomPasswordPolicyConstants.BLACKLIST_PASSWORDS);
        return properties.toArray(new String[properties.size()]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {
        Map<String, String> defaultProperties = new HashMap();
        defaultProperties.put(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstants.CUSTOM_PASSWORD_POLICY_ENABLE));
        defaultProperties.put(CustomPasswordPolicyConstants.PASSWORD_BLACKLIST_POLICY_ENABLE, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstants.PASSWORD_BLACKLIST_POLICY_ENABLE));
        defaultProperties.put(CustomPasswordPolicyConstants.PASSWORD_PALINDROME_POLICY_ENABLE, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstants.PASSWORD_PALINDROME_POLICY_ENABLE));
        defaultProperties.put(CustomPasswordPolicyConstants.BLACKLIST_PASSWORDS, this.configs.getModuleProperties().getProperty(CustomPasswordPolicyConstants.BLACKLIST_PASSWORDS));
        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {
        return null;
    }
}