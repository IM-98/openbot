/**
 * Product analytics and telemetry are disabled by default across all regions in this personal fork.
 */
export function analyticsOnByDefault(_countryCode: string, _timeZone: string | undefined): boolean {
  return false;
}
