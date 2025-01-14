# ---+ Security and Authentication
# ---++ HTTP Security Headers
# Enable security headers for secure web applications.

# **BOOLEAN LABEL="Deny Frame Options" CHECK="undefok emptyok"**
# Set the X-Frame-Options header to "DENY":
# This header can prevent your application responses from being loaded within
# frame or iframe HTML elements. This is to prevent clickjacking
# requests where your application response is displayed on another website,
# within an invisible iframe, which then hijacks the user's request when they
# click a link on your website.
$Foswiki::cfg{Http}{DenyFrameOptions} = 1;

# **STRING 100 LABEL="Strict Transport Security" CHECK="undefok emptyok"**
# Require all resources to be loaded via SSL.
# This header instructs the requester to load all content from the domain via
# HTTPS and not load any content unless there is a valid ssl certificate. This
# header can help prevent man-in-middle attacks as it ensures that all HTTP
# requests and responses are encrypted. The Strict-Transport-Security header has
# a max-age parameter that defines how long in seconds to enforce the policy for.
# A default of 31536000 seconds is equivalent to 365 dayys.
$Foswiki::cfg{Http}{StrictTransportSecurity} = "max-age=31536000; includeSubDomains";

# **STRING 100 LABEL="Content Type Options" CHECK="undefok emptyok"**
# IE-only header to disable mime sniffing.
# This is an IE only header that is used to disable mime sniffing. The
# vulnerability is that IE will auto-execute any script code contained in a file
# when IE attempts to detect the file type.
$Foswiki::cfg{Http}{ContentTypeOptions} = "nosniff";

# **STRING 100 LABEL="Download Options" CHECK="undefok emptyok"**
# IE-only header that prevents it from opening an HTML file directly on download.
# This is another IE-only header that prevents IE from opening an HTML file
# directly on download from a website. The security issue here is, if a browser
# opens the file directly, it can run as if it were part of the site.
$Foswiki::cfg{Http}{DownloadOptions} = "noopen";

# **STRING 100 LABEL="XSS Protection" CHECK="undefok emptyok"**
# IE-only header to force it to turn on its XSS filter (IE >= 8)
# This header was introduced in IE8 as part of the
# cross-site-scripting (XSS) filter functionality (more here). Additionally it
# has an optional setting called "mode" that can force IE to block the entire
# page if an XSS attempt is detected.
$Foswiki::cfg{Http}{XSSProtection} = "1; mode=block";

# **SELECT no-referrer-when-downgrade,no-referrer,origin-when-cross-origin,same-origin,strict-origin,strict-origin-when-cross-origin,unsafe-url LABEL="Referrer-Policy" CHECK="undefok emptyok"**
# referrer information provided in requests, i.e. in outgoing links.
#    * no-referrer-when-downgrade: default browser behavior
#    * no-referrer: suppress referrer information
#    * origin: only send the origin
#    * origin-when-cross-origin: send the origin, path, and query string when performing a same-origin request, but only send the origin of the document for other cases
#    * same-origin: referrer information will be sent for same-site origins, but cross-origin requests will send no referrer information
#    * strict-origin: send the origin of the document as the referrer when the protocol security level stays the same (HTTPS->HTTPS)
#    * strict-origin-when-cross-origin: send the origin, path, and querystring when performing a same-origin request, only send the origin when the protocol security level stays the same while performing a cross-origin request (HTTPS->HTTPS), and send no header to any less-secure destinations (HTTPS->HTTP)
#    * unsafe-url: Send the origin, path, and query string when performing any request, regardless of security. WARNING: This policy will leak potentially-private information from HTTPS resource URLs to insecure origins. Carefully consider the impact of this setting.
$Foswiki::cfg{Http}{ReferrerPolicy} = "same-origin";

# ---+++ Content Security Policy
# The CSP header sets a whitelist of domains from which content can be safely
# loaded. This prevents most types of XSS attack, assuming the malicious content
# is not hosted by a whitelisted domain. For example this specifies that all
# content should only be loaded from the responding domain: "default-src 'self'"
# WARNING: Enabling this setting will currently render your Foswiki non-operational
# as it relys on unsafe inline css and js.
# See directive reference at http://content-security-policy.com/

# **BOOLEAN LABEL="Upgrade Insecure Requests" CHECK="undefok emptyok"**
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'upgrade-insecure-requests'} = 1; 

# **STRING 100 CHECK="undefok emptyok"**
# Default policy for loading content such as JavaScript, Images, CSS, Font's, AJAX requests, Frames, HTML5 Media
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'default-src'} = "'self'";

# **STRING 100 CHECK="undefok emptyok"**
# Defines valid sources for manifest files
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'manifest-src'} = "'self'";

# **STRING 100 CHECK="undefok emptyok"**
# Defines valid sources of JavaScript
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'script-src'} = "'self' blob: *.google-analytics.com *.googleapis.com 'unsafe-eval' 'unsafe-inline'";

# **STRING 100 CHECK="undefok emptyok"**
# Defines valid sources of stylesheets.
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'style-src'} = "'self' 'unsafe-inline'";

# **STRING 100 CHECK="undefok emptyok"**
# Defines valid sources of images
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'img-src'} = "'self' data: blob:";

# **STRING 100 CHECK="undefok emptyok"**
# Applies to XMLHttpRequest (AJAX), WebSocket or EventSource. If not allowed the browser emulates a 400 HTTP status code.
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'connect-src'}= "'self'";

# **STRING 100 CHECK="undefok emptyok"**
# Defines valid sources of fonts.
$Foswiki::cfg{Http}{ContentSecurityPolicy}{"font-src"} = "'self' data:"; 

# **STRING 100 CHECK="undefok emptyok"**
# Defines valid sources of plugins, eg &lt;object>, &lt;embed> or &lt;applet
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'object-src'} = "*";

# **STRING 100 CHECK="undefok emptyok"**
# Defines valid sources of audio and video, eg HTML5 &lt;audio>, &lt;video> elements.
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'media-src'} = "*";

# **STRING 100 CHECK="undefok emptyok"**
# Defines valid sources for loading frames. Deprecated in modern browsers in
# favour of child-src, which however is not yet understood by all browsers still in use.
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'frame-src'} = "'self' vnd.sun.star.webdav: ms-word: ms-excel: ms-powerpoint: ms-access: ms-infopath: ms-publisher: ms-visio: ms-project:";

# **STRING 100 CHECK="undefok emptyok"**
# Enables a sandbox for the requested resource similar to the iframe sandbox
# attribute. The sandbox applies a same origin policy, prevents popups, plugins
# and script execution is blocked. You can keep the sandbox value empty to keep
# all restrictions in place, or add values: allow-forms allow-same-origin
# allow-scripts, and allow-top-navigation
$Foswiki::cfg{Http}{ContentSecurityPolicy}{sandbox} = "";

# **STRING 100 CHECK="undefok emptyok"**
# Instructs the browser to POST a reports of policy failures to this URI.
$Foswiki::cfg{Http}{ContentSecurityPolicy}{'report-uri'} = '$Foswiki::cfg{ScriptUrlPath}/rest/SecurityHeadersPlugin/report';

# **BOOLEAN LABEL="Enable deprecated CSP headers" CHECK="undefok emptyok"**
# Switch this on to enable deprecated CSP headers for older browsers. This is
# normally not required as above ContentSecurityPolicy is supported by all
# major browsers today.
$Foswiki::cfg{Http}{EnableDeprecatedCSPHeaders} = 0;

1;
