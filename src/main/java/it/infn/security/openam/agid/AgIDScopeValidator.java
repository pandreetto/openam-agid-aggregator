package it.infn.security.openam.agid;

import javax.inject.Inject;
import javax.inject.Named;

import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.openam.oauth2.IdentityManager;
import org.forgerock.openam.oauth2.OpenAMScopeValidator;
import org.forgerock.openam.scripting.ScriptConstants;
import org.forgerock.openam.scripting.ScriptEvaluator;
import org.forgerock.openam.scripting.service.ScriptingServiceFactory;
import org.forgerock.openam.utils.OpenAMSettings;
import org.forgerock.openidconnect.OpenIDTokenIssuer;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;

public class AgIDScopeValidator
    extends OpenAMScopeValidator {

    @Inject
    public AgIDScopeValidator(IdentityManager identityManager, OpenIDTokenIssuer openIDTokenIssuer,
            OAuth2ProviderSettingsFactory providerSettingsFactory, OpenAMSettings openAMSettings,
            @Named(ScriptConstants.OIDC_CLAIMS_NAME) ScriptEvaluator scriptEvaluator,
            OpenIdConnectClientRegistrationStore clientRegistrationStore,
            ScriptingServiceFactory scriptingServiceFactory) {
        super(identityManager, openIDTokenIssuer, providerSettingsFactory, openAMSettings, scriptEvaluator,
                clientRegistrationStore, scriptingServiceFactory);
    }
}