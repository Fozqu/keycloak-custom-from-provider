package org.prsq.providers.auth;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Serhii Morunov
 */
public class WebsiteRegistration implements FormAction, FormActionFactory {

    private static String FIELD_WEBSITE = "user.attributes.website";

    private static String ATTRIBUTE_WEBSITE = "website";

    private static final String PROVIDER_ID = "website-validator";

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOISES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };


    static {
        System.out.println("Website validator provider loaded...");
    }

    public String getDisplayType() {
        return "Website Validation";
    }

    public String getReferenceCategory() {
        return null;
    }

    public boolean isConfigurable() {
        return false;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOISES;
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public void buildPage(FormContext context, LoginFormsProvider form) {

    }

    public void validate(ValidationContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<FormMessage>();
        String website = formData.getFirst(FIELD_WEBSITE);
        List<UserModel> users = context.getSession().users().searchForUserByUserAttribute(ATTRIBUTE_WEBSITE, cleanURL(website), context.getRealm());
        if (users.size() > 0) {
            errors.add(new FormMessage(FIELD_WEBSITE, "User with such website address already exists"));
        }
        if (errors.size() > 0) {
            context.validationError(formData, errors);
        } else {
            context.success();
        }
    }

    public void success(FormContext context) {
        UserModel user = context.getUser();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String website = cleanURL(formData.getFirst(FIELD_WEBSITE));
        user.setSingleAttribute("website", website);
    }

    public boolean requiresUser() {
        return false;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    public String getHelpText() {
        return "Validates website field and stores it in user data";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    public void close() {

    }

    public FormAction create(KeycloakSession session) {
        return this;
    }

    public void init(Config.Scope config) {

    }

    public void postInit(KeycloakSessionFactory factory) {

    }

    public String getId() {
        return PROVIDER_ID;
    }

    private String cleanURL(String dirty) {
        return dirty.replaceAll("((https|http):\\/\\/)|www\\.", "").replaceAll("(\\/(.+))$", "");
    }
}
