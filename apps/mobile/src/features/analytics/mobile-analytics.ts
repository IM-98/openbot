import { MobileAnalytics } from "./analytics-core";
import { mobileReportQueue } from "./failure-reports";

export const mobileAnalytics = new MobileAnalytics(() => null, mobileReportQueue);
