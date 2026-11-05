const { existsSync } = require("node:fs");
const { join } = require("node:path");

// Android notifications come through Firebase Cloud Messaging, which needs the Firebase file of the
// app. The file is optional, so the app builds before the Firebase project exists, and such a build
// gets no notifications on Android. The file has public identifiers only; the account service has the
// key that sends.
const GOOGLE_SERVICES_FILE = "./google-services.json";

// Paid Apple Developer accounts ($99/yr) can sign Push Notifications, Associated Domains, App Groups,
// and multi-target extensions (Widgets / Live Activities, Notification Service, Share Extension).
// Free Apple ID "Personal Team" accounts (7-day certificates / SideStore / AltStore) fail in Xcode
// if those entitlements or extension targets are present. Default to Personal Team mode unless
// OPENBOT_IOS_PAID_TEAM=1 is set.
const PAID_IOS_PLUGINS = new Set([
  "expo-notifications",
  "expo-widgets",
  "./plugins/with-notification-service",
  "./plugins/with-share-target",
]);

/** @param {{ config: import('expo/config').ExpoConfig }} context */
module.exports = ({ config }) => {
  const paidIosTeam = process.env.OPENBOT_IOS_PAID_TEAM === "1";
  const bundleIdentifier = process.env.OPENBOT_IOS_BUNDLE_ID || config.ios?.bundleIdentifier || "run.openbot.personal";

  const plugins = (config.plugins ?? []).filter((entry) => {
    if (paidIosTeam) return true;
    const name = Array.isArray(entry) ? entry[0] : entry;
    return !PAID_IOS_PLUGINS.has(name);
  });

  const ios = {
    ...config.ios,
    bundleIdentifier,
    ...(paidIosTeam ? {} : { associatedDomains: undefined }),
  };

  const nextConfig = {
    ...config,
    ios,
    plugins,
  };

  return existsSync(join(__dirname, GOOGLE_SERVICES_FILE))
    ? { ...nextConfig, android: { ...nextConfig.android, googleServicesFile: GOOGLE_SERVICES_FILE } }
    : nextConfig;
};
