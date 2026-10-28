// The account page's tabs. The element shows the one in its `data-section` and announces a
// switch, so a host can keep the tab in its URL and a link can open a given one.

export const ACCOUNT_SECTIONS = ['profile', 'security', 'notifications'] as const;

export type AccountSection = (typeof ACCOUNT_SECTIONS)[number];

/** The reader switched tabs. Bubbles, `composed`; the detail is `{ section }`. */
export const SECTION_EVENT = 'ev:section';
