auto_derived!(
    /// hCaptcha Configuration
    pub struct CaptchaFeature {
        /// Whether captcha is enabled
        pub enabled: bool,
        /// Client key used for solving captcha
        pub key: String,
    }

    /// Generic Service Configuration
    pub struct Feature {
        /// Whether the service is enabled
        pub enabled: bool,
        /// URL pointing to the service
        pub url: String,
    }

    /// # Information about a livekit node
    pub struct VoiceNode {
        pub name: String,
        pub lat: f64,
        pub lon: f64,
        pub public_url: String,
    }

    /// # Voice Server Configuration
    pub struct VoiceFeature {
        /// Whether voice is enabled
        pub enabled: bool,
        /// All livekit nodes
        pub nodes: Vec<VoiceNode>,
    }
    /// Feature Configuration
    pub struct RevoltFeatures {
        /// hCaptcha configuration
        pub captcha: CaptchaFeature,
        /// Whether email verification is enabled
        pub email: bool,
        /// Whether this server is invite only
        pub invite_only: bool,
        /// File server service configuration
        pub autumn: Feature,
        /// Proxy service configuration
        pub january: Feature,
        /// Voice server configuration
        pub livekit: VoiceFeature,
    }

    /// Build Information
    pub struct BuildInformation {
        /// Commit Hash
        pub commit_sha: String,
        /// Commit Timestamp
        pub commit_timestamp: String,
        /// Git Semver
        pub semver: String,
        /// Git Origin URL
        pub origin_url: String,
        /// Build Timestamp
        pub timestamp: String,
    }

    /// Server Configuration
    pub struct RevoltConfig {
        /// Revolt API Version
        pub revolt: String,
        /// Features enabled on this Revolt node
        pub features: RevoltFeatures,
        /// WebSocket URL
        pub ws: String,
        /// URL pointing to the client serving this node
        pub app: String,
        /// Web Push VAPID public key
        pub vapid: String,
        /// Build information
        pub build: BuildInformation,
    }
);
