from burp import IBurpExtender, IScannerCheck, IScanIssue
from array import array
import re
import base64
import json

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("KeyHunter")
        self._callbacks.registerScannerCheck(self)
        print("[+] KeyHunter Loaded")
        return

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        else:
            return 0

    def doPassiveScan(self, baseRequestResponse):
        scan_issues = []
        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)

        content_type = self._CustomScans.getContentType()
        if any(binary in content_type for binary in ["image", "font", "video", "audio"]):
            return None

        extra_patterns = {
            "Generic Credentials": r"(?i)pass(word|wd|phrase)|secretToken|secret|token|api[-_]?key|auth|credential|private[-_]key",
            "JWT": r"(?<![\w-])eyJ[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{5,}(?![\w-])",
            "Private IPs": r"(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[0-1])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})",
            "AWS Access Keys": r"(AKIA|ASIA)[A-Z0-9]{16}",
            "Email Addresses": r"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+)",
            "URL with Secrets": r"https?:\/\/[^:/]+:[^@/]+@",
            "Azure Keys": r"(AccountKey|sig)=[a-z0-9+/=]{48}",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Slack Token": r"xoxb-\\d{12}-\\d{12}-[a-zA-Z0-9]{24}",
            "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "Postgres DB Connection": r"postgres(ql)?:\/\/[^:@]+:[^@]+@",
            "Private Key Block": r"-----BEGIN (RSA|EC) PRIVATE KEY-----",
            "Stripe Key": r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
            "Twilio SID": r"SK[0-9a-fA-F]{32}"
        }

        for name, pattern in extra_patterns.items():
            matches = self._CustomScans.findRegExValidated(pattern, name)
            scan_issues.extend(matches)

        keywords = [
            "access_key", "secretToken", "access_token", "accessKey", "accessToken", "account_sid", "accountsid",
            "admin_pass", "admin_user", "api_key", "api_secret", "apikey", "app_key", "app_secret",
            "app_url", "application_id", "aws_secret_token", "authsecret", "aws_access",
            "aws_access_key_id", "aws_bucket", "aws_config", "aws_default_region", "aws_key",
            "aws_secret", "aws_secret_access_key", "aws_secret_key", "aws_token", "bucket_password",
            "client_secret", "cloudinary_api_key", "cloudinary_api_secret", "cloudinary_name",
            "connectionstring", "consumer_secret", "database_dialect", "database_host",
            "database_logging", "database_password", "database_schema", "database_schema_test",
            "database_url", "database_username", "db_connection", "db_database", "db_dialect",
            "db_host", "db_password", "db_port", "db_server", "db_username", "dbpasswd", "dbpassword",
            "dbuser", "django_password", "elastica_host", "elastica_port", "elastica_prefix",
            "email_host_password", "facebook_app_secret", "facebook_secret", "fb_app_secret", "fb_id",
            "fb_secret", "gatsby_wordpress_base_url", "gatsby_wordpress_client_id",
            "gatsby_wordpress_client_secret", "gatsby_wordpress_password", "gatsby_wordpress_protocol",
            "gatsby_wordpress_user", "github_id", "github_secret", "google_id", "google_oauth",
            "google_oauth_client_id", "google_oauth_client_secret", "google_oauth_secret", "google_secret",
            "google_server_key", "gsecr", "heroku_api_key", "heroku_key", "heroku_oauth",
            "heroku_oauth_secret", "heroku_oauth_token", "heroku_secret", "heroku_secret_token",
            "htaccess_pass", "htaccess_user", "incident_bot_name", "incident_channel_name",
            "jwt_passphrase", "jwt_password", "jwt_public_key", "jwt_secret", "jwt_secret_key",
            "jwt_secret_token", "jwt_token", "jwt_user", "keyPassword", "mail_driver", "mail_encryption",
            "mail_from_address", "mail_from_name", "mail_host", "mail_password", "mail_port",
            "mail_username", "mailgun_key", "mailgun_secret", "maps_api_key", "mix_pusher_app_cluster",
            "mix_pusher_app_key", "mysql_password", "oauth_discord_id", "oauth_discord_secret",
            "oauth_key", "oauth_token", "oauth2_secret", "secretKeyForEncryption", "paypal_identity_token",
            "paypal_sandbox", "paypal_secret", "paypal_token", "playbooks_url", "postgres_password",
            "private_key", "pusher_app_cluster", "pusher_app_id", "pusher_app_key", "pusher_app_secret",
            "queue_driver", "redis_host", "redis_password", "redis_port", "response_auth_jwt_secret",
            "response_data_secret", "response_data_url", "root_password", "sa_password", "secret",
            "secret_access_key", "secret_bearer", "secret_key", "secret_token", "secretKey",
            "security_credentials", "send_keys", "sentry_dsn", "session_driver", "session_lifetime",
            "sf_username", "sid twilio", "sid_token", "sid_twilio", "slack_channel",
            "slack_incoming_webhook", "slack_key", "slack_outgoing_token", "slack_secret",
            "slack_signing_secret", "slack_token", "slack_url", "slack_webhook", "slack_webhook_url",
            "square_access_token", "square_apikey", "square_app", "square_app_id", "square_appid",
            "square_secret", "square_token", "squareSecret", "squareToken", "ssh2_auth_password",
            "sshkey", "storePassword", "strip_key", "strip_secret", "strip_secret_token", "strip_token",
            "stripe_key", "stripe_secret", "stripe_secret_token", "stripe_token", "stripSecret",
            "stripToken", "stripe_publishable_key", "token_twilio", "trusted_hosts", "twi_auth",
            "twi_sid", "twilio_account_id", "twilio_account_secret", "twilio_account_sid",
            "twilio_accountsid", "twilio_api", "twilio_api_auth", "twilio_api_key", "twilio_api_secret",
            "twilio_api_sid", "twilio_api_token", "twilio_auth", "twilio_auth_token", "twilio_secret",
            "twilio_secret_token", "twilio_sid", "twilio_token", "twilioapiauth", "twilioapisecret",
            "twilioapisid", "twilioapitoken", "TwilioAuthKey", "TwilioAuthSid", "twilioauthtoken",
            "TwilioKey", "twiliosecret", "TwilioSID", "twiliotoken", "twitter_api_secret",
            "twitter_consumer_key", "twitter_consumer_secret", "twitter_key", "twitter_secret",
            "twitter_token", "twitterKey", "twitterSecret", "wordpress_password", "zen_key", "zen_tkn",
            "zen_token", "zendesk_api_token", "zendesk_key", "zendesk_token", "zendesk_url",
            "zendesk_username", "zendesk_password", "auth_key", "auth_secret", "auth_token", "bearer_token", "client_key", "credential", 
            "crypto_key", "decryption_key", "enc_key", "enc_secret", "enc_token", "hmac_key", 
            "jwt_secret", "master_key", "passphrase", "privatekey", "public_key", "salt", 
            "secure_token", "security_token", "shared_secret", "signature", "signing_key", 
            "x_api_key", "x_secret_key", "azure_client_id", "azure_client_secret", "azure_tenant_id", "azure_subscription_id",
            "azure_storage_account_key", "azure_storage_connection_string", "azure_cosmos_key",
            "gcp_project_id", "gcp_client_email", "gcp_private_key", "gcp_client_id",
            "gcp_api_key", "gcp_refresh_token", "gcp_access_token", "gcp_secret", "google_cloud_keyfile", "google_service_account", "google_private_key_id",
            "digitalocean_token", "do_api_key", "do_client_id", "do_client_secret", "ibm_cloud_api_key", "ibm_cloud_iam_apikey", "ibm_cloud_iam_token",
            "oracle_cloud_api_key", "oci_key_fingerprint", "oci_user_ocid", "oci_tenancy_ocid",
            "kubernetes_token", "kubeconfig_token", "kubeapi_token", "dockerhub_username", "dockerhub_password", "dockerhub_token",
            "docker_registry_user", "docker_registry_password","circleci_token", "circleci_api_key", "travis_token",
            "gitlab_token", "gitlab_private_token", "gitlab_ci_token", "bitbucket_username", "bitbucket_app_password", "bitbucket_oauth_token",
            "heroku_api_token", "heroku_git_token", "npm_auth_token", "npm_token","yarn_registry_key","slack_oauth_token", "slack_bot_token", "slack_signing_secret",
            "jira_api_token", "jira_user_email", "jira_api_key","newrelic_api_key", "newrelic_license_key",
            "rollbar_access_token", "rollbar_post_server_item","honeybadger_api_key", "honeybadger_project_id",
            "pagerduty_integration_key", "pagerduty_api_token","datadog_api_key", "datadog_app_key",
            "sumologic_access_id", "sumologic_access_key","splunk_hec_token", "splunk_username", "splunk_password",
            "algolia_api_key", "algolia_app_id", "algolia_search_key","sendgrid_api_key", "mailchimp_api_key", "mailchimp_server_prefix",
            "twine_username", "twine_password","pypi_token", "docker_token","oauth_client_id", "oauth_client_secret", "oauth_refresh_token",
            "ssm_parameter", "vault_token", "vault_path", "vault_key","ansible_vault_password", "ansible_ssh_pass",
            "openssl_private_key", "openssl_public_key", "ssl_certificate","pem_key", "pfx_password",
            "telegram_bot_token", "discord_webhook_url", "mastodon_access_token","spotify_client_id", "spotify_client_secret",
            "stripe_client_id", "paypal_client_id","cloudflare_api_token", "cloudflare_email", "cloudflare_api_key",
            "auth0_client_id", "auth0_client_secret", "auth0_domain","okta_client_id", "okta_client_secret", "okta_org_url",
            "saml_certificate", "saml_certificate_key","twilio_api_version", "twilio_messaging_service_sid",
            "aws_session_token", "aws_profile", "aws_creds_file","azure_key_vault_secret", "gcp_secret_manager_secret",
            "onepassword_token", "bitwarden_client_id", "bitwarden_client_secret", ".env", ".env.local", ".env.development", ".env.production", ".env.test",
            "credentials.yml", "credentials.yaml", "config.yml", "config.yaml", "settings.py", "application.properties", "application.yml", "secrets.json", "secrets.yml", "manifest.json",
            "docker_config_json", "docker_config", "jest_config", "connection_string","redis_url", "memcached_password", "smtp_username", "smtp_password", "smtp_host",
            "imap_username", "imap_password", "ftp_username", "ftp_password","sql_connection_string", "mongo_uri", "mongodb_uri", "mongodb_username", "mongodb_password",
            "neo4j_uri", "neo4j_password", "rabbitmq_url", "rabbitmq_username", "rabbitmq_password","celery_broker_url", "broker_url", "session_token", "auth_header", "authz_header",
            "cookie_secret", "cookie_encryption_key", "flash_secret", "csrf_secret","GOOGLE_APPLICATION_CREDENTIALS", "AWS_DEFAULT_PROFILE", "AZURE_CLIENT_CERT",
            "GCP_METADATA_TOKEN", "METADATA_FLAVOR", "x_ms_msi_auth", "api_endpoint", "api_base_url","admin_email", "recovery_email", "support_email", "webhook_url", "callback_url",
            "login_token", "unlock_token", "reset_password_token", "confirmation_token"
        ]

        for key in keywords:
            regex = r"(?i)\b" + re.escape(key) + r"\b['\"]?\s*(=|:)\s*['\"]?([^\s\"'&<]+)"
            matches = self._CustomScans.findRegExValidated(regex, key)
            scan_issues.extend(matches)

        return scan_issues if scan_issues else None

class CustomScans:
    def __init__(self, requestResponse, callbacks):
        self._requestResponse = requestResponse
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._params = self._helpers.analyzeRequest(requestResponse.getRequest()).getParameters()

    def getContentType(self):
        analyzed_response = self._helpers.analyzeResponse(self._requestResponse.getResponse())
        headers = analyzed_response.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type"):
                return header.lower()
        return ""

    def findRegExValidated(self, regex, key):
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        if not response:
            return []

        response_str = self._helpers.bytesToString(response)
        responseLength = len(response)
        rg = re.compile(regex)
        matches = rg.finditer(response_str)

        for match in matches:
            value = match.group(len(match.groups())) if match.groups() else match.group(0)
            if not value:
                continue
            context = response_str[max(0, match.start() - 30): match.end() + 30]

            if any(x in context.lower() for x in ["example", "test", "dummy", "sample"]):
                continue

            if key == "JWT" and not self._validate_jwt(value):
                continue
            if key == "AWS Access Keys" and len(value) != 20:
                continue
            if key == "Email Addresses" and any(bad in value for bad in ["example.com", "test.com"]):
                continue

            url = self._helpers.analyzeRequest(self._requestResponse).getUrl()
            start = self._helpers.indexOf(response, value, True, 0, responseLength)
            offset[0] = start
            offset[1] = start + len(value)
            offsets = [offset]

            detail = "<b>{}</b> : <code>{}</code>".format(key, value)
            severity = "High" if key in ["JWT", "AWS Access Keys", "Stripe Key"] else "Information"

            scan_issues.append(ScanIssue(
                self._requestResponse.getHttpService(),
                url,
                [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                "KeyHunter Detected[{}]".format(key),
                severity,
                detail
            ))
        return scan_issues

    def _validate_jwt(self, token):
        parts = token.split('.')
        if len(parts) != 3:
            return False
        try:
            decoded = base64.urlsafe_b64decode(parts[1] + '==')
            json.loads(decoded)
            return True
        except:
            return False

class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"
