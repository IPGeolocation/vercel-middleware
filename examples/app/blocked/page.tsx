// A block page for the App Router. Save as app/blocked/page.tsx.
//
// In Next.js 15 and later searchParams is a Promise. On Next.js 13 and 14 it is
// a plain object, so drop the await and the Promise type.

export const metadata = {
  title: 'Access restricted',
  robots: { index: false, follow: false }
};

const REASONS: Record<string, string> = {
  country: 'This site is not available in your country.',
  vpn: 'Connections through a VPN are not accepted.',
  proxy: 'Connections through a proxy are not accepted.',
  residential_proxy: 'Connections through a residential proxy are not accepted.',
  tor: 'Connections through the Tor network are not accepted.',
  relay: 'Connections through a relay network are not accepted.',
  cloud_provider: 'Connections from cloud and hosting networks are not accepted.',
  bot: 'This request looks automated.',
  spam: 'This address is associated with spam activity.',
  known_attacker: 'This address is associated with attack activity.',
  anonymous: 'Anonymised connections are not accepted.',
  threat_score: 'This address has a high risk score.',
  lookup_failed: 'We could not verify your connection.',
  security_unavailable: 'We could not verify your connection.'
};

export default async function BlockedPage({
  searchParams
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const { reason } = await searchParams;
  const message = (reason && REASONS[reason]) || 'Access to this site is restricted.';

  return (
    <main style={{ maxWidth: '32rem', margin: '4rem auto', fontFamily: 'system-ui' }}>
      <h1>Access restricted</h1>
      <p>{message}</p>
      <p>
        If you think this is a mistake, contact{' '}
        <a href="mailto:support@example.com">support@example.com</a>.
      </p>
    </main>
  );
}
