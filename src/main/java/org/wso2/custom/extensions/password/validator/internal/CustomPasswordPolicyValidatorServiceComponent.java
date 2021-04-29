package org.wso2.custom.extensions.password.validator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.password.policy.internal.IdentityPasswordPolicyServiceDataHolder;
import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.custom.extensions.password.validator.CustomPasswordPolicyValidatorHandler;

/**
 * Registers  as an osgi component.
 */
@Component(
        name = "org.wso2.custom.extensions.password.validator.component",
        service = CustomPasswordPolicyValidatorServiceComponent.class,
        immediate = true
)
public class CustomPasswordPolicyValidatorServiceComponent {
    private static Log log = LogFactory.getLog(CustomPasswordPolicyValidatorServiceComponent.class);
    private static RealmService realmService;
    private static RegistryService registryService;


    protected void activate(ComponentContext context) {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Password Policy Service component is enabled");
            }

            BundleContext bundleContext = context.getBundleContext();
            IdentityPasswordPolicyServiceDataHolder.getInstance().setBundleContext(bundleContext);

            CustomPasswordPolicyValidatorHandler passwordPolicyValodatorHandler = new CustomPasswordPolicyValidatorHandler();
            context.getBundleContext().registerService(AbstractEventHandler.class.getName(), passwordPolicyValodatorHandler, null);

            log.info("CustomPasswordPolicyValidatorServiceComponent bundle activated successfully..");
        } catch (Exception e) {
            log.error("Error while activating CUSTOM password policy component.", e);
        }
    }

    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("CustomPasswordPolicyValidatorServiceComponent is deactivated ");
        }
    }


    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {
        IdentityPasswordPolicyServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {
        IdentityPasswordPolicyServiceDataHolder.getInstance().setIdentityGovernanceService(idpManager);
    }

}