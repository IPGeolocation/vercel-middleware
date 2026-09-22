// Reading the geo headers in a Server Component. Save as app/page.tsx.
//
// In Next.js 15 and later headers() is async. On Next.js 13 and 14 it is
// synchronous, so drop the await.

import { headers } from 'next/headers';

export default async function Page() {
  const h = await headers();

  const country = h.get('x-ipgeo-country');
  const city = h.get('x-ipgeo-city');
  const currency = h.get('x-ipgeo-currency');

  if (!country) return <p>We could not work out where you are.</p>;

  return (
    <main>
      <h1>
        Hello from {city ?? 'your city'}, {country}
      </h1>
      <p>Prices are shown in {currency ?? 'USD'}.</p>
    </main>
  );
}
